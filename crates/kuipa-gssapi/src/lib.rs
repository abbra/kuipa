//! GSSAPI / SPNEGO support for kuipa (from `ahdapa-gssapi`).
//!
//! # Typical usage
//!
//! At startup, acquire a server credential from the HTTP service keytab:
//!
//! ```no_run
//! let cred = kuipa_gssapi::GssServerCred::acquire("HTTP", "/etc/ahdapa/http.keytab")
//!     .expect("GSSAPI credential");
//! ```
//!
//! For each incoming `Authorization: Negotiate <base64>` request, call
//! [`accept_token`] and match on [`AcceptStep`]:
//!
//! ```no_run
//! # let cred = kuipa_gssapi::GssServerCred::acquire("HTTP", "/etc/ahdapa/http.keytab")
//! #     .expect("GSSAPI credential");
//! # let token_bytes: Vec<u8> = vec![];
//! match kuipa_gssapi::accept_token(&cred, &token_bytes, None).expect("GSSAPI accept") {
//!     kuipa_gssapi::AcceptStep::Complete { out_token, principal } => {
//!         // `principal` is e.g. "user@REALM"
//!         // `out_token` is the optional mutual-auth response (may be empty)
//!     }
//!     kuipa_gssapi::AcceptStep::Continue { out_token, ctx } => {
//!         // Send `out_token` as `WWW-Authenticate: Negotiate <base64>` with 401.
//!         // On the next request, call `ctx.step(...)` with the client's new token.
//!     }
//! }
//! ```
//!
//! # Thread safety
//!
//! [`GssServerCred`] is `Send`.  When built against MIT Kerberos (the default;
//! controlled by `cfg(mit_kerberos)` in `build.rs`), it is also `Sync`, allowing
//! a single `Arc<GssServerCred>` to be shared across all request-handling threads.
//! MIT Kerberos guarantees that `gss_accept_sec_context` is safe for concurrent
//! use with the same acceptor credential; Heimdal does not.

pub mod error;
mod ffi;
mod kinit;
mod status;
mod thread_ccache;

#[cfg(heimdal_kerberos)]
use std::ffi::c_char;
use std::ffi::{CStr, CString};
use std::ptr;

pub use error::GssError;
pub use kinit::{ticket, NoPreauth, Preauth};
pub use status::format_gss_status;
pub use thread_ccache::{set_thread_ccache, thread_ccache_name};

// ── Credential re-acquisition ────────────────────────────────────────────────

/// How the server credential was originally acquired, allowing re-acquisition
/// when the credential handle becomes stale.
#[derive(Debug, Clone)]
pub enum GssCredMode {
    GssProxy { service: String },
    Keytab { service: String, keytab: String },
}

/// Re-acquire a `GssServerCred` using the same method as startup.
pub fn reacquire_server_cred(mode: &GssCredMode) -> Result<GssServerCred, GssError> {
    match mode {
        GssCredMode::GssProxy { service } => GssServerCred::from_gssproxy(service),
        GssCredMode::Keytab { service, keytab } => GssServerCred::acquire(service, keytab),
    }
}

/// How the initiator (client) credential was originally acquired, allowing
/// re-acquisition when the credential handle becomes stale.
#[derive(Debug, Clone)]
pub enum InitiatorCredMode {
    GssProxy {
        has_principal: bool,
    },
    Keytab {
        keytab: String,
        ccache: Option<String>,
    },
}

/// Re-acquire a `GssClientCred` using the same method as startup.
pub fn reacquire_initiator_cred(mode: &InitiatorCredMode) -> Result<GssClientCred, GssError> {
    match mode {
        InitiatorCredMode::GssProxy { has_principal } => GssClientCred::from_ccache(*has_principal),
        InitiatorCredMode::Keytab { keytab, ccache } => {
            GssClientCred::from_keytab_combined(keytab, ccache.as_deref())
        }
    }
}

// ── GssServerCred ─────────────────────────────────────────────────────────────

/// Server-side GSSAPI credential, acquired from a keytab at startup.
///
/// The underlying `gss_cred_id_t` is safe to use from multiple threads
/// simultaneously for `gss_accept_sec_context` calls: MIT documents that
/// guarantee for acceptor credentials, and Heimdal gives it by keeping the
/// `krb5_context` in thread-specific storage and reading the credential
/// without writing it.
///
/// Drop releases the credential handle via `gss_release_cred`.
pub struct GssServerCred {
    raw: ffi::GssCredIdT,
}

impl std::fmt::Debug for GssServerCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssServerCred")
            .field("raw", &self.raw)
            .finish()
    }
}

// SAFETY: gss_cred_id_t is a pointer owned exclusively by this struct.
// Moving it to another thread is safe; the raw pointer carries no thread affinity.
unsafe impl Send for GssServerCred {}

// SAFETY: MIT Kerberos explicitly documents that gss_accept_sec_context is
// thread-safe for concurrent calls with the same acceptor credential.
// This impl is gated on cfg(mit_kerberos) (set by build.rs) because Heimdal
// and other GSSAPI implementations do NOT make this guarantee.
#[cfg(mit_kerberos)]
unsafe impl Sync for GssServerCred {}

// SAFETY: Heimdal's `gss_accept_sec_context` reads the acceptor credential
// without writing it — the principal and keytab handle are set at acquire
// time — and each call gets its own `krb5_context` (Heimdal keeps it in
// thread-specific storage) and its own keytab cursor, which opens its own
// file descriptor under an advisory lock.  Concurrent accepts on one
// acceptor credential therefore share no mutable state.
#[cfg(heimdal_kerberos)]
unsafe impl Sync for GssServerCred {}

impl Drop for GssServerCred {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            // SAFETY: self.raw is a valid, non-null gss_cred_id_t obtained from
            // gss_acquire_cred_from; we own it exclusively and never use it again
            // after this point.  The pointer is set to null by gss_release_cred.
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut self.raw) };
        }
    }
}

impl GssServerCred {
    /// Acquire a server credential for `service_name` (e.g. `"HTTP"`) using
    /// the keytab at `keytab_file`.
    ///
    /// MIT Kerberos appends `@<local-hostname>` when no realm is specified, so
    /// passing `"HTTP"` is usually sufficient for a single-homed host.
    /// Use `"HTTP@fully.qualified.hostname"` to be explicit.
    ///
    /// Under MIT Kerberos this calls `gss_acquire_cred_from()` (RFC 5587) with
    /// a credential store entry `{key="keytab", value=keytab_file}`, which
    /// avoids any environment-variable mutation and is safe to call from
    /// multiple threads.
    ///
    /// Under Heimdal there is no credential store: the keytab is resolved with
    /// `krb5_kt_resolve` and imported with `gss_krb5_import_cred`, which yields
    /// an ACCEPT credential with no principal of its own.  Heimdal then matches
    /// each request against the ticket's own server name, so any principal
    /// present in the keytab is accepted and `service_name` is not used to
    /// select one ([`Self::principal_name`] returns `None`).
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInServiceName`] — `service_name` contains a NUL byte.
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::ImportName`] — `gss_import_name` rejected the service name.
    /// - [`GssError::AcquireCred`] — credential acquisition failed (keytab
    ///   missing, wrong principal, or Kerberos library error).
    /// - [`GssError::Krb5`] — Heimdal could not open the keytab.
    pub fn acquire(service_name: &str, keytab_file: &str) -> Result<Self, GssError> {
        // Validate strings first so NUL-byte errors are reported before any I/O.
        #[cfg(mit_kerberos)]
        let svc_cstr = CString::new(service_name).map_err(|_| GssError::NulInServiceName)?;
        // Heimdal's acceptor credential carries no principal, so the service
        // name is validated and then dropped — but a NUL in it is still the
        // caller's bug and must be reported the same way.
        #[cfg(heimdal_kerberos)]
        CString::new(service_name).map_err(|_| GssError::NulInServiceName)?;
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;

        // Pre-flight readability check before calling into the GSSAPI library so that a
        // missing or wrong-path keytab produces a clear error rather than an
        // opaque major/minor status pair.
        std::fs::File::open(keytab_file).map_err(|e| GssError::KeytabNotReadable {
            path: keytab_file.to_owned(),
            source: e,
        })?;

        #[cfg(mit_kerberos)]
        return Self::acquire_mit(&svc_cstr, &kt_cstr);
        #[cfg(heimdal_kerberos)]
        return Self::acquire_heimdal(&kt_cstr);
    }

    /// The MIT path: a credential store naming the keytab for both the accept
    /// and the initiate half.
    #[cfg(mit_kerberos)]
    fn acquire_mit(svc_cstr: &CStr, kt_cstr: &CStr) -> Result<Self, GssError> {
        let mut minor: ffi::OmUint32 = 0;

        // Import "service_name" as a host-based service name.
        let svc_oid = ffi::gss_c_nt_hostbased_service();
        let svc_buf = ffi::GssBufferDesc {
            length: svc_cstr.to_bytes().len(),
            // SAFETY: gss_import_name treats input_name_buffer as read-only per
            // RFC 2744 §2; *const → *mut cast is safe for C APIs with that contract.
            #[allow(clippy::as_ptr_cast_mut)]
            value: svc_cstr.as_ptr() as *mut _,
        };
        let mut svc_name: ffi::GssNameT = ptr::null_mut();
        // SAFETY: all arguments are valid: minor points to a local u32, svc_buf
        // wraps a valid CString slice, svc_oid is a well-formed OID descriptor,
        // svc_name is a valid output pointer.
        let major = unsafe {
            ffi::gss_import_name(
                &raw mut minor,
                &raw const svc_buf,
                &raw const svc_oid,
                &raw mut svc_name,
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            let detail = format_gss_status(major, minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_import_name (service name) failed");
            return Err(GssError::ImportName {
                detail,
                major,
                minor,
            });
        }

        // Build the credential store: {keytab, client_keytab} both pointing at the
        // same file.  The `keytab` entry provides the ACCEPT credential; `client_keytab`
        // provides the INITIATE credential.  Without `client_keytab`, MIT Kerberos
        // falls back to the default credential cache for the initiate half of
        // GSS_C_BOTH, which fails when no matching ccache entry exists.
        let key_keytab = c"keytab";
        let key_client_keytab = c"client_keytab";
        let key_ccache = c"ccache";
        // A private in-memory ccache for the initiator half: without one,
        // GSS_C_BOTH would use the process's default ccache (KRB5CCNAME) and
        // fail, or pick up someone else's TGT, whenever that holds another
        // principal.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ccache_cstr = CString::new(format!(
            "MEMORY:kuipa-acceptor-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
        .expect("no NUL in a generated name");
        let mut elements = [
            ffi::GssKeyValueElementDesc {
                key: key_keytab.as_ptr(),
                value: kt_cstr.as_ptr(),
            },
            ffi::GssKeyValueElementDesc {
                key: key_client_keytab.as_ptr(),
                value: kt_cstr.as_ptr(),
            },
            ffi::GssKeyValueElementDesc {
                key: key_ccache.as_ptr(),
                value: ccache_cstr.as_ptr(),
            },
        ];
        let cred_store = ffi::GssKeyValueSetDesc {
            count: elements.len() as ffi::OmUint32,
            elements: elements.as_mut_ptr(),
        };

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // Try GSS_C_BOTH first: the credential supports INITIATE in addition to
        // ACCEPT so it can be used as the impersonator in
        // gss_acquire_cred_impersonate_name (S4U2Self).  An ACCEPT-only credential
        // is rejected by gssproxy for impersonation requests.
        //
        // If GSS_C_BOTH fails (e.g. no TGT obtainable in a containerised
        // environment without a reachable KDC), fall back to GSS_C_ACCEPT which
        // is sufficient for SPNEGO validation.
        let mut cred_usage = ffi::GSS_C_BOTH;
        // SAFETY: all arguments are valid; svc_name was returned by gss_import_name,
        // cred_store elements point to live CStrings, output pointers are valid locals.
        let mut major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                svc_name,
                0, // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                cred_usage,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        if major != ffi::GSS_S_COMPLETE {
            // Defensively release a potentially non-null cred_handle on failure.
            if !cred_handle.is_null() {
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
                cred_handle = ptr::null_mut();
            }
            if !actual_mechs.is_null() {
                unsafe { ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs) };
                actual_mechs = ptr::null_mut();
            }
            let detail = format_gss_status(major, minor);
            tracing::warn!(%detail, "GSS_C_BOTH acquire failed, retrying with GSS_C_ACCEPT (S4U2Self will be unavailable)");
            cred_usage = ffi::GSS_C_ACCEPT;
            major = unsafe {
                ffi::gss_acquire_cred_from(
                    &raw mut minor,
                    svc_name,
                    0,
                    ffi::GSS_C_NO_OID_SET,
                    cred_usage,
                    &raw const cred_store,
                    &raw mut cred_handle,
                    &raw mut actual_mechs,
                    &raw mut time_rec,
                )
            };
        }

        // Snapshot the error minor before cleanup calls overwrite it.
        let error_minor = minor;

        // Release the name and the actual_mechs set regardless of success/failure.
        // SAFETY: svc_name is a valid GssNameT returned by gss_import_name above.
        unsafe {
            ffi::gss_release_name(&raw mut minor, &raw mut svc_name);
            if !actual_mechs.is_null() {
                // SAFETY: actual_mechs is non-null and was set by gss_acquire_cred_from.
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            // Defensively release a potentially non-null cred_handle on failure.
            // RFC 2743 §2.1.1 says it is NULL on failure, but non-conformant
            // implementations may write a partial handle.
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (server keytab) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        if cred_usage == ffi::GSS_C_ACCEPT {
            tracing::info!("GSSAPI server credential acquired (ACCEPT-only, S4U2Self unavailable)");
        }

        Ok(GssServerCred { raw: cred_handle })
    }

    /// The Heimdal path: resolve the keytab and import it as an ACCEPT
    /// credential.  With no principal passed to `gss_krb5_import_cred` the
    /// credential has no name of its own, and Heimdal looks the keytab up by
    /// the server principal named in each request's ticket.
    #[cfg(heimdal_kerberos)]
    fn acquire_heimdal(kt_cstr: &CStr) -> Result<Self, GssError> {
        // SAFETY: every handle is initialised here and released on every path,
        // including the failure paths, in reverse order of acquisition.
        unsafe {
            let mut ctx: ffi::Krb5Context = ptr::null_mut();
            let ret = ffi::krb5_init_context(&raw mut ctx);
            if ret != 0 {
                tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_init_context failed");
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_init_context",
                });
            }

            let mut keytab: ffi::Krb5Keytab = ptr::null_mut();
            let ret = ffi::krb5_kt_resolve(ctx, kt_cstr.as_ptr(), &raw mut keytab);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_kt_resolve failed");
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_kt_resolve",
                });
            }

            let mut minor: ffi::OmUint32 = 0;
            let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
            let major = ffi::gss_krb5_import_cred(
                &raw mut minor,
                ptr::null_mut(), // ccache: this credential only accepts
                ptr::null_mut(), // no principal: match whatever the ticket names
                keytab,
                &raw mut cred_handle,
            );
            let error_minor = minor;
            ffi::krb5_kt_close(ctx, keytab);
            ffi::krb5_free_context(ctx);

            if major != ffi::GSS_S_COMPLETE {
                if !cred_handle.is_null() {
                    // SAFETY: set by gss_krb5_import_cred.
                    ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle);
                }
                let detail = format_gss_status(major, error_minor);
                tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_krb5_import_cred (acceptor keytab) failed");
                return Err(GssError::AcquireCred {
                    detail,
                    major,
                    minor: error_minor,
                });
            }
            Ok(GssServerCred { raw: cred_handle })
        }
    }

    /// Acquire a server credential for `service_name` via gssproxy.
    ///
    /// Calls `gss_acquire_cred_from()` with a null credential store, which is
    /// equivalent to `gss_acquire_cred()`.  When gssproxy is active for this
    /// process (matching UID / service entry in `/etc/gssproxy/conf.d/`), it
    /// intercepts the call and supplies credentials from the configured keytab
    /// without requiring the process to have direct keytab file access.
    ///
    /// gssproxy is a MIT Kerberos mechanism; a Heimdal build has no
    /// credential-store proxy to talk to, so this reports
    /// [`GssError::Unsupported`] and the caller should use
    /// [`Self::acquire`] with the keytab path instead.
    ///
    /// # Errors
    ///
    /// - [`GssError::Unsupported`] — this build links Heimdal.
    /// - [`GssError::AcquireCred`] — gssproxy denied the request, the service
    ///   has no gssproxy entry, or the Kerberos library returned an error.
    pub fn from_gssproxy(_service_name: &str) -> Result<Self, GssError> {
        #[cfg(heimdal_kerberos)]
        return Err(GssError::Unsupported {
            feature: "gssproxy credential acquisition",
        });
        #[cfg(mit_kerberos)]
        return Self::from_gssproxy_mit();
    }

    #[cfg(mit_kerberos)]
    fn from_gssproxy_mit() -> Result<Self, GssError> {
        let mut minor: ffi::OmUint32 = 0;

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // Pass GSS_C_NO_NAME (NULL) as desired_name so gssproxy selects the
        // acceptor credential from its configured keytab without any name
        // serialisation on our side.  Passing a stack-allocated OID descriptor
        // (as gss_c_nt_hostbased_service() returns) causes proxymech to call
        // generic_gss_release_oid on an OID whose elements point to static
        // memory, triggering a glibc heap-corruption abort.
        //
        // SAFETY: NULL cred_store == GSS_C_NO_CRED_STORE; gssproxy intercepts
        // based on the process UID matching the service entry.  All output
        // pointers are valid stack locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                // GSS_C_BOTH: must support INITIATE as well as ACCEPT so this
                // credential can serve as the impersonator in S4U2Self calls
                // (gss_acquire_cred_impersonate_name).  GSS_C_ACCEPT-only is
                // rejected by gssproxy for impersonation requests.
                ffi::GSS_C_BOTH,
                ptr::null(), // cred_store = GSS_C_NO_CRED_STORE → gssproxy
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;

        // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (gssproxy) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssServerCred { raw: cred_handle })
    }

    /// Return the service principal name stored in this credential, e.g.
    /// `"HTTP/ipsilon.vda.li@VDA.LI"`.
    ///
    /// Calls `gss_inquire_cred` to retrieve the internal name, then
    /// `gss_display_name` to convert it to a UTF-8 string.  Returns `None`
    /// if either call fails or if the result is not valid UTF-8.
    pub fn principal_name(&self) -> Option<String> {
        let mut minor: ffi::OmUint32 = 0;
        let mut name: ffi::GssNameT = ptr::null_mut();

        // SAFETY: self.raw is a valid gssproxy credential handle; name is an
        // output-only pointer; the three trailing outputs we don't need are
        // null (no-op).
        let major = unsafe {
            ffi::gss_inquire_cred(
                &raw mut minor,
                self.raw,
                &raw mut name,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if major != ffi::GSS_S_COMPLETE || name.is_null() {
            tracing::debug!(
                major,
                minor,
                "gss_inquire_cred failed or returned null name"
            );
            return None;
        }

        let mut buf = ffi::GssBufferDesc {
            length: 0,
            value: ptr::null_mut(),
        };
        let mut name_type: *mut ffi::GssOidDesc = ptr::null_mut();
        // SAFETY: name is non-null, buf and name_type are valid output-only locals.
        let major2 = unsafe {
            ffi::gss_display_name(&raw mut minor, name, &raw mut buf, &raw mut name_type)
        };

        let result = if major2 == ffi::GSS_S_COMPLETE && !buf.value.is_null() {
            // SAFETY: buf.value points to a GSSAPI-allocated buffer of length buf.length.
            let slice = unsafe { std::slice::from_raw_parts(buf.value as *const u8, buf.length) };
            std::str::from_utf8(slice).ok().map(str::to_owned)
        } else {
            None
        };

        // SAFETY: buf was returned by gss_display_name and must be released.
        unsafe {
            if !buf.value.is_null() {
                ffi::gss_release_buffer(&raw mut minor, &raw mut buf);
            }
            ffi::gss_release_name(&raw mut minor, &raw mut name);
        }

        result
    }
}

// ── GssClientCred ─────────────────────────────────────────────────────────────

/// Client-side GSSAPI credential loaded from a keytab.
///
/// Used to obtain service tickets for a target service (e.g. `"HTTP@hostname"`).
/// The underlying `gss_cred_id_t` is safe to use from multiple threads
/// simultaneously for `gss_init_sec_context` calls (MIT Kerberos guarantees
/// this for initiator credentials).
///
/// Drop releases the credential handle via `gss_release_cred`.
pub struct GssClientCred {
    raw: ffi::GssCredIdT,
}

impl std::fmt::Debug for GssClientCred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssClientCred")
            .field("raw", &self.raw)
            .finish()
    }
}

// SAFETY: gss_cred_id_t is a pointer owned exclusively by this struct.
// Moving it to another thread is always safe — no concurrent access occurs,
// which Send does not imply. Concurrent shared access requires MIT Kerberos
// (see cfg-gated Sync impl below).
unsafe impl Send for GssClientCred {}
#[cfg(mit_kerberos)]
unsafe impl Sync for GssClientCred {}

impl Drop for GssClientCred {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            // SAFETY: self.raw is a valid, non-null gss_cred_id_t obtained from
            // gss_acquire_cred_from; we own it exclusively and never use it again
            // after this point.
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut self.raw) };
        }
    }
}

impl GssClientCred {
    /// Acquire an initiator credential from the caller's ambient Kerberos ticket cache.
    ///
    /// Equivalent to `from_ccache(false)`.  Requires a prior `kinit`; does not
    /// touch any keytab.  Intended for CLI tools that run in a user's login session.
    ///
    /// # Errors
    ///
    /// - [`GssError::AcquireCred`] — no valid TGT in the ccache or the Kerberos
    ///   library returned an error.
    pub fn ambient() -> Result<Self, GssError> {
        Self::from_ccache(false)
    }

    /// Acquire a credential from the default Kerberos credential cache (ccache).
    ///
    /// The calling process must already hold a valid TGT (e.g. from `kinit`).
    /// No keytab is required.  Passing `GSS_C_NO_CRED_STORE` (NULL) for the
    /// credential store makes MIT Kerberos use the ambient ccache, identical
    /// to calling `gss_acquire_cred()` with default arguments.  Heimdal's
    /// `gss_acquire_cred` with no name does the same: the default ccache first,
    /// falling back to the default keytab.
    ///
    /// `for_impersonation` controls the GSSAPI credential usage flag:
    /// - `false` → `GSS_C_INITIATE` — for pure initiator use (LDAP bind,
    ///   token fetch). Use when the credential will never be passed to
    ///   `gss_acquire_cred_impersonate_name` or act as an ACCEPT responder.
    /// - `true` → `GSS_C_BOTH` — when the same credential must also serve as
    ///   the impersonator for S4U2Self or as an ACCEPT responder for SPNEGO.
    ///   Note: in gssproxy mode with an existing ACCEPT credential in the
    ///   union table, `GSS_C_BOTH` causes the union mechanism to pass that
    ///   credential as `input_cred_handle`, triggering an AS exchange; only
    ///   pass `true` when the impersonator role is actually required.
    ///
    /// A Heimdal build has no S4U2Self, so `for_impersonation == true` reports
    /// [`GssError::Unsupported`].
    ///
    /// # Errors
    ///
    /// - [`GssError::Unsupported`] — `for_impersonation` under Heimdal.
    /// - [`GssError::AcquireCred`] — no valid TGT in the ccache, or the
    ///   Kerberos library returned an error.
    pub fn from_ccache(for_impersonation: bool) -> Result<Self, GssError> {
        #[cfg(heimdal_kerberos)]
        if for_impersonation {
            return Err(GssError::Unsupported {
                feature: "S4U2Self impersonation credentials",
            });
        }
        #[cfg(mit_kerberos)]
        return Self::from_ccache_mit(for_impersonation);
        #[cfg(heimdal_kerberos)]
        return Self::from_ccache_heimdal();
    }

    #[cfg(mit_kerberos)]
    fn from_ccache_mit(for_impersonation: bool) -> Result<Self, GssError> {
        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        let cred_usage = if for_impersonation {
            ffi::GSS_C_BOTH
        } else {
            ffi::GSS_C_INITIATE
        };

        // SAFETY: NULL for cred_store == GSS_C_NO_CRED_STORE; MIT Kerberos
        // falls back to the default ccache, matching gss_acquire_cred() behaviour.
        // desired_name = GSS_C_NO_NAME selects the default principal.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                cred_usage,
                ptr::null(), // cred_store = GSS_C_NO_CRED_STORE → default ccache
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (default ccache) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// The Heimdal path: `gss_acquire_cred` with no name reads the default
    /// ccache (`KRB5CCNAME`), and only falls back to the default keytab if the
    /// ccache holds nothing usable.
    #[cfg(heimdal_kerberos)]
    fn from_ccache_heimdal() -> Result<Self, GssError> {
        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();

        // SAFETY: minor and cred_handle are valid locals; GSS_C_NO_NAME and
        // GSS_C_NO_OID_SET are null.
        let major = unsafe {
            ffi::gss_acquire_cred(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME → default principal
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw mut cred_handle,
                ptr::null_mut(), // actual_mechs
                ptr::null_mut(), // time_rec
            )
        };

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_acquire_cred (default ccache) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Acquire an initiator credential from the keytab at `keytab_file`.
    ///
    /// Under MIT Kerberos this passes `desired_name = NULL` so the library
    /// selects from the keytab whichever credential can obtain a service ticket
    /// for the requested target, using `gss_acquire_cred_from()` (RFC 5587)
    /// with `GSS_C_INITIATE`.  The keytab is consulted lazily: no TGT is
    /// acquired until the credential is first used.
    ///
    /// Heimdal has no credential store and no lazy keytab initiator, so this
    /// reads the *first* entry of the keytab, obtains a TGT for that principal
    /// now, stores it in a private in-process ccache, and imports that ccache
    /// as an INITIATE credential.  Which principal that is therefore depends on
    /// the keytab's entry order, and concurrent calls share one ccache name —
    /// pass an explicit principal with
    /// [`Self::from_keytab_initiate_named`] when the choice matters.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::KeytabNotReadable`] — keytab file cannot be opened.
    /// - [`GssError::Krb5`] — Heimdal could not read the keytab or obtain the
    ///   TGT.
    /// - [`GssError::AcquireCred`] — credential acquisition failed (keytab
    ///   missing, no usable credential, or Kerberos library error).
    pub fn from_keytab(keytab_file: &str) -> Result<Self, GssError> {
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;

        std::fs::File::open(keytab_file).map_err(|e| GssError::KeytabNotReadable {
            path: keytab_file.to_owned(),
            source: e,
        })?;

        #[cfg(mit_kerberos)]
        return Self::from_keytab_mit(&kt_cstr);
        #[cfg(heimdal_kerberos)]
        return Self::from_keytab_heimdal(&kt_cstr);
    }

    #[cfg(mit_kerberos)]
    fn from_keytab_mit(kt_cstr: &CStr) -> Result<Self, GssError> {
        let mut minor: ffi::OmUint32 = 0;
        let key_keytab = c"keytab";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_keytab.as_ptr(),
            value: kt_cstr.as_ptr(),
        };
        let cred_store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: all arguments are valid; desired_name=NULL lets the library
        // choose the credential; output pointers are valid locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = NULL
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;

        // SAFETY: actual_mechs is non-null when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(keytab = %kt_cstr.to_string_lossy(), major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (keytab) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// The Heimdal path: name the principal from the keytab's first entry, get
    /// its TGT into a private in-process ccache, and import that ccache.
    #[cfg(heimdal_kerberos)]
    fn from_keytab_heimdal(kt_cstr: &CStr) -> Result<Self, GssError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ccache_name = CString::new(format!(
            "MEMORY:kuipa-keytab-initiator-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
        .expect("no NUL in a generated name");

        let principal = keytab_first_principal(kt_cstr)?;
        tgt_into_ccache(kt_cstr, &principal, &ccache_name)?;
        let cred_handle = acquire_initiator_from_ccache(&ccache_name)?;
        Ok(GssClientCred { raw: cred_handle })
    }

    /// Acquire a combined initiator+acceptor credential from the keytab at `keytab_file`.
    ///
    /// Under MIT Kerberos this sets both `{"client_keytab": path}` (for
    /// `GSS_C_INITIATE`) and `{"keytab": path}` (for `GSS_C_ACCEPT`) in the
    /// credential store, then calls `gss_acquire_cred_from()` with
    /// `GSS_C_BOTH`.  MIT uses `client_keytab` to obtain a TGT automatically
    /// (no `kinit` required); gssproxy, when active, is told exactly which
    /// keytab to use for both roles via the same two keys.  `desired_name =
    /// NULL` lets the library choose the principal from the keytab.
    ///
    /// Under Heimdal there is no credential store: the TGT for the keytab's
    /// first principal is obtained into `ccache` (or a private in-process
    /// ccache when none is named), and ccache plus keytab are imported together
    /// as a credential of both usages.  The principal is thus chosen by the
    /// keytab's entry order rather than by the request.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::NulInCcacheName`] — `ccache` contains a NUL byte.
    /// - [`GssError::Krb5`] — Heimdal could not read the keytab or obtain the
    ///   TGT.
    /// - [`GssError::AcquireCred`] — credential acquisition failed.  In
    ///   gssproxy mode the daemon reads the keytab; the process itself does not
    ///   need read permission on the file.
    pub fn from_keytab_combined(keytab_file: &str, ccache: Option<&str>) -> Result<Self, GssError> {
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;
        let cc_cstr = ccache
            .map(CString::new)
            .transpose()
            .map_err(|_| GssError::NulInCcacheName)?;

        #[cfg(mit_kerberos)]
        return Self::from_keytab_combined_mit(&kt_cstr, cc_cstr.as_deref(), ccache);
        #[cfg(heimdal_kerberos)]
        return Self::from_keytab_combined_heimdal(&kt_cstr, cc_cstr.as_deref());
    }

    #[cfg(mit_kerberos)]
    fn from_keytab_combined_mit(
        kt_cstr: &CStr,
        cc_cstr: Option<&CStr>,
        ccache: Option<&str>,
    ) -> Result<Self, GssError> {
        tracing::debug!(
            keytab = %kt_cstr.to_string_lossy(),
            ccache,
            "gss_acquire_cred_from client_keytab+keytab+ccache GSS_C_BOTH"
        );

        let mut minor: ffi::OmUint32 = 0;

        let key_client_keytab = c"client_keytab";
        let key_keytab = c"keytab";
        let key_ccache = c"ccache";

        // Build element list: always keytab + client_keytab, add ccache when provided.
        // The ccache entry is what allows gssproxy to store the acquired TGT and return
        // a usable credential handle — without it gssproxy acquires the TGT but cannot
        // persist it and returns an error (matching mod_auth_gssapi's GssapiCredStore
        // keytab + client_keytab + ccache triple).
        let mut elements: Vec<ffi::GssKeyValueElementDesc> = vec![
            ffi::GssKeyValueElementDesc {
                key: key_client_keytab.as_ptr(),
                value: kt_cstr.as_ptr(),
            },
            ffi::GssKeyValueElementDesc {
                key: key_keytab.as_ptr(),
                value: kt_cstr.as_ptr(),
            },
        ];
        if let Some(cc) = cc_cstr {
            elements.push(ffi::GssKeyValueElementDesc {
                key: key_ccache.as_ptr(),
                value: cc.as_ptr(),
            });
        }
        let cred_store = ffi::GssKeyValueSetDesc {
            count: elements.len() as ffi::OmUint32,
            elements: elements.as_mut_ptr(),
        };

        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: elements lives until gss_acquire_cred_from returns; kt_cstr and
        // the two key literals are all live for this scope; output pointers are
        // valid stack locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_BOTH,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;
        // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle is non-null and was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(keytab = %kt_cstr.to_string_lossy(), major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (keytab combined) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        tracing::debug!(
            keytab = %kt_cstr.to_string_lossy(),
            lifetime_secs = time_rec,
            "gss_acquire_cred_from ok"
        );
        Ok(GssClientCred { raw: cred_handle })
    }

    /// The Heimdal path: TGT for the keytab's first principal into a ccache,
    /// then import ccache and keytab as one credential of both usages.
    #[cfg(heimdal_kerberos)]
    fn from_keytab_combined_heimdal(
        kt_cstr: &CStr,
        ccache: Option<&CStr>,
    ) -> Result<Self, GssError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let private_ccache = CString::new(format!(
            "MEMORY:kuipa-keytab-both-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
        .expect("no NUL in a generated name");
        let ccache_name = ccache.unwrap_or(&private_ccache);

        let principal = keytab_first_principal(kt_cstr)?;
        tgt_into_ccache(kt_cstr, &principal, ccache_name)?;

        // SAFETY: each handle is initialised here and released on every path in
        // reverse order of acquisition.
        unsafe {
            let mut ctx: ffi::Krb5Context = ptr::null_mut();
            let ret = ffi::krb5_init_context(&raw mut ctx);
            if ret != 0 {
                tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_init_context failed");
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_init_context",
                });
            }

            let mut cc_h: ffi::Krb5Ccache = ptr::null_mut();
            let ret = ffi::krb5_cc_resolve(ctx, ccache_name.as_ptr(), &raw mut cc_h);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_resolve failed");
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_cc_resolve",
                });
            }

            let mut keytab: ffi::Krb5Keytab = ptr::null_mut();
            let ret = ffi::krb5_kt_resolve(ctx, kt_cstr.as_ptr(), &raw mut keytab);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_kt_resolve failed");
                ffi::krb5_cc_close(ctx, cc_h);
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_kt_resolve",
                });
            }

            let mut minor: ffi::OmUint32 = 0;
            let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
            let major = ffi::gss_krb5_import_cred(
                &raw mut minor,
                cc_h,
                ptr::null_mut(),
                keytab,
                &raw mut cred_handle,
            );
            let error_minor = minor;
            ffi::krb5_kt_close(ctx, keytab);
            ffi::krb5_cc_close(ctx, cc_h);
            ffi::krb5_free_context(ctx);

            if major != ffi::GSS_S_COMPLETE {
                if !cred_handle.is_null() {
                    // SAFETY: set by gss_krb5_import_cred.
                    ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle);
                }
                let detail = format_gss_status(major, error_minor);
                tracing::warn!(keytab = %kt_cstr.to_string_lossy(), major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_krb5_import_cred (keytab combined) failed");
                return Err(GssError::AcquireCred {
                    detail,
                    major,
                    minor: error_minor,
                });
            }
            Ok(GssClientCred { raw: cred_handle })
        }
    }

    /// Acquire an initiator credential by getting a TGT from `keytab_file` for
    /// `principal` (equivalent to `kinit -k -t keytab principal`).
    ///
    /// Uses `krb5_get_init_creds_keytab` to obtain a TGT, stores it in the
    /// in-process ccache `MEMORY:kuipa-initiator`, then acquires a GSSAPI
    /// initiator credential from that ccache.  The resulting credential can be
    /// passed to [`GssClientCred::impersonate`] for S4U2Self LDAP binds.
    ///
    /// **Single-use ccache constraint**: this function writes to a fixed in-process
    /// `MEMORY:kuipa-initiator` ccache.  Calling it concurrently from multiple
    /// threads will race on that ccache.  The intended usage pattern is a single
    /// call at startup (inside a `spawn_blocking` task) followed by reuse of the
    /// returned credential handle.  For per-call ccache isolation use
    /// [`GssClientCred::from_keytab_initiate_named`] instead.
    ///
    /// The TGT is valid for the lifetime configured by the KDC (typically 24 h).
    /// Restart ahdapa to renew it.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::NulInUserPrincipal`] — `principal` contains a NUL byte.
    /// - [`GssError::KeytabNotReadable`] — keytab file cannot be opened.
    /// - [`GssError::Krb5`] — libkrb5 TGT acquisition failed.
    /// - [`GssError::AcquireCred`] — GSSAPI credential acquisition from ccache failed.
    pub fn from_keytab_initiate(keytab_file: &str, principal: &str) -> Result<Self, GssError> {
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;
        let principal_cstr = CString::new(principal).map_err(|_| GssError::NulInUserPrincipal)?;

        std::fs::File::open(keytab_file).map_err(|e| GssError::KeytabNotReadable {
            path: keytab_file.to_owned(),
            source: e,
        })?;

        tgt_into_ccache(&kt_cstr, &principal_cstr, DEFAULT_INITIATOR_CCACHE)?;
        let cred_handle = acquire_initiator_from_ccache(DEFAULT_INITIATOR_CCACHE)?;

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Like [`from_keytab_initiate`][Self::from_keytab_initiate] but stores the
    /// TGT into a caller-named ccache instead of the default
    /// `MEMORY:kuipa-initiator`.
    ///
    /// This is useful when multiple proxy threads need isolated credential
    /// stores (e.g. `MEMORY:kuipa-proxy-initiator`).
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInKeytabPath`] — `keytab_file` contains a NUL byte.
    /// - [`GssError::NulInCcacheName`] — `ccache_name` contains a NUL byte.
    /// - [`GssError::NulInUserPrincipal`] — `principal` contains a NUL byte.
    /// - [`GssError::KeytabNotReadable`] — keytab file cannot be opened.
    /// - [`GssError::Krb5`] — libkrb5 TGT acquisition failed.
    /// - [`GssError::AcquireCred`] — GSSAPI credential acquisition from ccache failed.
    pub fn from_keytab_initiate_named(
        keytab_file: &str,
        principal: &str,
        ccache_name: &str,
    ) -> Result<Self, GssError> {
        let kt_cstr = CString::new(keytab_file).map_err(|_| GssError::NulInKeytabPath)?;
        let principal_cstr = CString::new(principal).map_err(|_| GssError::NulInUserPrincipal)?;
        let ccache_cstr = CString::new(ccache_name).map_err(|_| GssError::NulInCcacheName)?;

        std::fs::File::open(keytab_file).map_err(|e| GssError::KeytabNotReadable {
            path: keytab_file.to_owned(),
            source: e,
        })?;

        tgt_into_ccache(&kt_cstr, &principal_cstr, &ccache_cstr)?;
        let cred_handle = acquire_initiator_from_ccache(&ccache_cstr)?;

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Acquire a delegated credential that acts as `user_principal` (S4U2Self).
    ///
    /// `initiator` must be an initiator credential obtained from the HTTP service
    /// keytab (e.g. via [`GssClientCred::from_keytab`]).  MIT Kerberos uses the
    /// keytab to authenticate as the service and then issues a service-for-user
    /// (S4U2Self) ticket.
    ///
    /// The returned credential can subsequently be stored into a thread-local
    /// credential cache and used for LDAP SASL GSSAPI binds.  When the KDC has
    /// constrained delegation configured for HTTP → LDAP, the SASL exchange
    /// automatically performs S4U2Proxy to obtain an LDAP ticket on behalf of
    /// the user.
    ///
    /// S4U2Self is a MIT Kerberos extension; a Heimdal build reports
    /// [`GssError::Unsupported`] instead.
    ///
    /// # Errors
    ///
    /// - [`GssError::Unsupported`] — this build links Heimdal.
    /// - [`GssError::NulInUserPrincipal`] — `user_principal` contains a NUL byte.
    /// - [`GssError::ImportName`] — `gss_import_name` rejected the principal.
    /// - [`GssError::ImpersonateCred`] — `gss_acquire_cred_impersonate_name` failed
    ///   (KDC policy, missing delegation config, or unknown principal).
    pub fn impersonate(initiator: &GssClientCred, user_principal: &str) -> Result<Self, GssError> {
        #[cfg(mit_kerberos)]
        return Self::impersonate_mit(initiator, user_principal);
        #[cfg(heimdal_kerberos)]
        {
            let _ = (&initiator, user_principal);
            Err(GssError::Unsupported {
                feature: "S4U2Self (gss_acquire_cred_impersonate_name)",
            })
        }
    }

    #[cfg(mit_kerberos)]
    fn impersonate_mit(initiator: &GssClientCred, user_principal: &str) -> Result<Self, GssError> {
        let principal_cstr =
            CString::new(user_principal).map_err(|_| GssError::NulInUserPrincipal)?;
        let mut minor: ffi::OmUint32 = 0;

        // Import the user principal as a Kerberos principal name.
        let principal_oid = ffi::gss_krb5_nt_principal_name();
        let principal_buf = ffi::GssBufferDesc {
            length: principal_cstr.to_bytes().len(),
            // SAFETY: gss_import_name treats the buffer as read-only.
            #[allow(clippy::as_ptr_cast_mut)]
            value: principal_cstr.as_ptr() as *mut _,
        };
        let mut user_name: ffi::GssNameT = ptr::null_mut();
        // SAFETY: minor, principal_buf, and principal_oid are valid stack values;
        // user_name is a valid output pointer.
        let major = unsafe {
            ffi::gss_import_name(
                &raw mut minor,
                &raw const principal_buf,
                &raw const principal_oid,
                &raw mut user_name,
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            let detail = format_gss_status(major, minor);
            tracing::warn!(principal = user_principal, major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_import_name (user principal for S4U2Self) failed");
            return Err(GssError::ImportName {
                detail,
                major,
                minor,
            });
        }

        let mut impersonated: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: initiator.raw is a live initiator credential; user_name was
        // returned by gss_import_name and is still valid; output pointers are
        // valid locals.
        let major = unsafe {
            ffi::gss_acquire_cred_impersonate_name(
                &raw mut minor,
                initiator.raw,
                user_name,
                0, // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw mut impersonated,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;

        // Release the user name and actual_mechs set regardless of outcome.
        // SAFETY: user_name was returned by gss_import_name above.
        unsafe {
            ffi::gss_release_name(&raw mut minor, &raw mut user_name);
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !impersonated.is_null() {
                // SAFETY: impersonated was set by gss_acquire_cred_impersonate_name.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut impersonated) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(principal = user_principal, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_impersonate_name (S4U2Self) failed");
            return Err(GssError::ImpersonateCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: impersonated })
    }

    /// Return the underlying `gss_cred_id_t` as a raw C pointer.
    ///
    /// The pointer is valid only as long as `self` is alive.  Intended for
    /// injection into Cyrus SASL via `sasl_setprop(conn, SASL_GSS_CREDS, ptr)`.
    pub fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.raw.cast()
    }

    /// Re-acquire an initiator credential from an existing named ccache.
    ///
    /// `ccache_name` must be a ccache previously populated by [`Self::store_into_ccache`].
    /// Calling this after `store_into_ccache` produces a credential whose backing
    /// store is the named ccache — MIT Kerberos can then find the evidence ticket
    /// in that ccache when performing S4U2Proxy inside `gss_init_sec_context`.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInCcacheName`] — `ccache_name` contains a NUL byte.
    /// - [`GssError::AcquireCred`] — acquisition failed (the ccache does not
    ///   exist or contains no usable credential).
    pub fn from_named_ccache(ccache_name: &str) -> Result<Self, GssError> {
        let ccache_cstr = CString::new(ccache_name).map_err(|_| GssError::NulInCcacheName)?;

        #[cfg(mit_kerberos)]
        return Self::from_named_ccache_mit(&ccache_cstr);
        #[cfg(heimdal_kerberos)]
        return Ok(GssClientCred {
            raw: acquire_initiator_from_ccache(&ccache_cstr)?,
        });
    }

    #[cfg(mit_kerberos)]
    fn from_named_ccache_mit(ccache_cstr: &CStr) -> Result<Self, GssError> {
        let key_ccache = c"ccache";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_ccache.as_ptr(),
            value: ccache_cstr.as_ptr(),
        };
        let cred_store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
        let mut time_rec: ffi::OmUint32 = 0;

        // SAFETY: ccache_cstr is a live CString; cred_store elements point to it
        // and to a static C string; output pointers are valid stack locals.
        let major = unsafe {
            ffi::gss_acquire_cred_from(
                &raw mut minor,
                ptr::null_mut(), // desired_name = GSS_C_NO_NAME
                0,               // GSS_C_INDEFINITE
                ffi::GSS_C_NO_OID_SET,
                ffi::GSS_C_INITIATE,
                &raw const cred_store,
                &raw mut cred_handle,
                &raw mut actual_mechs,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;
        // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
        unsafe {
            if !actual_mechs.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // SAFETY: cred_handle was written by gss_acquire_cred_from.
                unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(ccache = %ccache_cstr.to_string_lossy(), major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (named ccache) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok(GssClientCred { raw: cred_handle })
    }

    /// Store this credential into the named Kerberos credential cache.
    ///
    /// `ccache_name` should be a `MEMORY:` ccache name (e.g. `"MEMORY:kuipa-7"`).
    /// Under MIT Kerberos, after storing, call [`set_thread_ccache`] so that
    /// the SASL GSSAPI plugin finds this credential when it calls
    /// `gss_acquire_cred` on the same thread; Heimdal has no thread-local
    /// ccache, so there the credential is only visible to code that names the
    /// ccache itself.
    ///
    /// Heimdal copies the ccache behind the credential with
    /// `gss_krb5_copy_ccache`; a credential obtained from a keytab alone has no
    /// ccache and cannot be stored.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInCcacheName`] — `ccache_name` contains a NUL byte.
    /// - [`GssError::StoreCred`] — the store failed.
    /// - [`GssError::Krb5`] — Heimdal could not open `ccache_name`.
    pub fn store_into_ccache(&self, ccache_name: &str) -> Result<(), GssError> {
        let ccache_cstr = CString::new(ccache_name).map_err(|_| GssError::NulInCcacheName)?;

        #[cfg(mit_kerberos)]
        return self.store_into_ccache_mit(&ccache_cstr, ccache_name);
        #[cfg(heimdal_kerberos)]
        return self.store_into_ccache_heimdal(&ccache_cstr);
    }

    #[cfg(mit_kerberos)]
    fn store_into_ccache_mit(&self, ccache_cstr: &CStr, ccache_name: &str) -> Result<(), GssError> {
        let key_ccache = c"ccache";
        let mut element = ffi::GssKeyValueElementDesc {
            key: key_ccache.as_ptr(),
            value: ccache_cstr.as_ptr(),
        };
        let store = ffi::GssKeyValueSetDesc {
            count: 1,
            elements: &raw mut element,
        };

        let mut minor: ffi::OmUint32 = 0;
        let mut elements_stored: ffi::GssOidSetT = ptr::null_mut();
        let mut usage_stored: i32 = 0;

        // SAFETY: self.raw is a live credential; store elements point to live CStrings;
        // output pointers are valid locals.
        let major = unsafe {
            ffi::gss_store_cred_into(
                &raw mut minor,
                self.raw,
                ffi::GSS_C_INITIATE,
                ptr::null(), // desired_mech = NULL: store all mechs
                1,           // overwrite_cred
                0,           // default_cred (we set thread-local explicitly)
                &raw const store,
                &raw mut elements_stored,
                &raw mut usage_stored,
            )
        };

        let error_minor = minor;
        unsafe {
            if !elements_stored.is_null() {
                ffi::gss_release_oid_set(&raw mut minor, &raw mut elements_stored);
            }
        }

        if major != ffi::GSS_S_COMPLETE {
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(ccache = ccache_name, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_store_cred_into failed");
            return Err(GssError::StoreCred {
                detail,
                major,
                minor: error_minor,
            });
        }
        Ok(())
    }

    /// The Heimdal path: copy the credential's own ccache into `ccache_name`.
    /// Heimdal's copy initialises the destination itself, so no
    /// `krb5_cc_initialize` is needed.
    #[cfg(heimdal_kerberos)]
    fn store_into_ccache_heimdal(&self, ccache_cstr: &CStr) -> Result<(), GssError> {
        // SAFETY: the context and ccache are initialised here and released on
        // every path; self.raw is a live credential.
        unsafe {
            let mut ctx: ffi::Krb5Context = ptr::null_mut();
            let ret = ffi::krb5_init_context(&raw mut ctx);
            if ret != 0 {
                tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_init_context failed");
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_init_context",
                });
            }

            let mut ccache: ffi::Krb5Ccache = ptr::null_mut();
            let ret = ffi::krb5_cc_resolve(ctx, ccache_cstr.as_ptr(), &raw mut ccache);
            if ret != 0 {
                let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
                let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
                ffi::krb5_free_error_message(ctx, errmsg_ptr);
                tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_resolve failed");
                ffi::krb5_free_context(ctx);
                return Err(GssError::Krb5 {
                    code: ret,
                    msg: "krb5_cc_resolve",
                });
            }

            let mut minor: ffi::OmUint32 = 0;
            let major = ffi::gss_krb5_copy_ccache(&raw mut minor, self.raw, ccache);
            let error_minor = minor;
            ffi::krb5_cc_close(ctx, ccache);
            ffi::krb5_free_context(ctx);

            if major != ffi::GSS_S_COMPLETE {
                let detail = format_gss_status(major, error_minor);
                tracing::warn!(ccache = %ccache_cstr.to_string_lossy(), major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_krb5_copy_ccache failed");
                return Err(GssError::StoreCred {
                    detail,
                    major,
                    minor: error_minor,
                });
            }
            Ok(())
        }
    }

    /// Export this credential as a complete credential-cache file.
    ///
    /// Stores the GSSAPI credential into a temporary `FILE:` ccache via
    /// [`Self::store_into_ccache`], reads the file bytes, and deletes the file.
    /// This approach works under both direct keytab and gssproxy modes
    /// (unlike `MEMORY:` ccaches, which are invisible to the local krb5
    /// library when gssproxy manages the credential).
    ///
    /// The bytes are in the ccache format of the Kerberos library this build
    /// links: MIT's under `mit_kerberos`, Heimdal's under `heimdal_kerberos`.
    ///
    /// The temporary file is created by us, exclusively and mode 0600
    /// *before* any credential is stored into it, with an unguessable
    /// name: a predictable path on a shared temp directory would let a
    /// local attacker pre-plant a symlink at it and have the store write
    /// the credential through it, or read the file between the store and
    /// the delete.  krb5 truncates an existing `FILE:` ccache, so the
    /// store writes into the file we hold open, not a symlink's target.
    ///
    /// The file exists for microseconds.
    ///
    /// # Errors
    ///
    /// - [`GssError::ExportCred`] — store or file I/O failed.
    pub fn export(&self) -> Result<Vec<u8>, GssError> {
        debug_assert!(!self.raw.is_null(), "export called on null credential");
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt as _;
        // A random, unguessable name: 128 bits from OpenSSL's DRBG, the
        // same one that protects everything else, so no other process can
        // find the file (let alone pre-create it) during its short life.
        let mut id = [0u8; 16];
        native_ossl::rand::Rand::fill(&mut id).map_err(|e| GssError::ExportCred {
            major: 0,
            minor: 0,
            detail: format!("random temp name: {e}"),
        })?;
        let path = std::env::temp_dir().join(format!(
            ".kuipa-ccexport-{}-{}",
            std::process::id(),
            native_ossl::util::hex_encode(id)
        ));
        // Create it ourselves: exclusive, never following a symlink at
        // the path, and private from the first moment it exists.  The
        // handle also pins the inode, so the store (which opens by name)
        // writes into this very file even if the name were replaced.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| GssError::ExportCred {
                major: 0,
                minor: 0,
                detail: format!("create {}: {e}", path.display()),
            })?;
        drop(file);
        let ccache_name = format!("FILE:{}", path.display());

        let result = self.store_into_ccache(&ccache_name);
        if let Err(e) = result {
            let _ = std::fs::remove_file(&path);
            return Err(GssError::ExportCred {
                major: 0,
                minor: 0,
                detail: format!("store_into_ccache: {e}"),
            });
        }

        // Enforce 0600 regardless of umask or GSSAPI library behavior.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        let bytes = std::fs::read(&path).map_err(|e| {
            let _ = std::fs::remove_file(&path);
            GssError::ExportCred {
                major: 0,
                minor: 0,
                detail: format!("read ccache file: {e}"),
            }
        })?;

        let _ = std::fs::remove_file(&path);
        Ok(bytes)
    }
}

/// The in-process ccache [`GssClientCred::from_keytab_initiate`] stores its TGT in.
const DEFAULT_INITIATOR_CCACHE: &CStr = c"MEMORY:kuipa-initiator";

/// Get a TGT from `kt` for `principal` and store it in the `MEMORY:` ccache
/// named `ccache_name`.  Takes borrowed C strings so that either an owned
/// [`CString`] or a static [`CStr`] name works on both vendors.
///
/// Shared by [`GssClientCred::from_keytab_initiate`] and
/// [`GssClientCred::from_keytab_initiate_named`], which differ only in the
/// ccache name and in how they turn the stored TGT into a GSSAPI initiator
/// credential.
///
/// # Errors
///
/// - [`GssError::Krb5`] — the context, principal, keytab, ccache, TGT or
///   store step failed.
fn tgt_into_ccache(kt: &CStr, principal: &CStr, ccache_name: &CStr) -> Result<(), GssError> {
    // SAFETY: each pointer is initialised before use; on error we clean up in
    // reverse-acquisition order (no double-free, no leak).
    unsafe {
        let mut ctx: ffi::Krb5Context = ptr::null_mut();
        let ret = ffi::krb5_init_context(&raw mut ctx);
        if ret != 0 {
            tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_init_context failed");
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_init_context",
            });
        }

        let mut principal_h: ffi::Krb5Principal = ptr::null_mut();
        let ret = ffi::krb5_parse_name(ctx, principal.as_ptr(), &raw mut principal_h);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_parse_name failed");
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_parse_name",
            });
        }

        let mut kt_h: ffi::Krb5Keytab = ptr::null_mut();
        let ret = ffi::krb5_kt_resolve(ctx, kt.as_ptr(), &raw mut kt_h);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_kt_resolve failed");
            ffi::krb5_free_principal(ctx, principal_h);
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_kt_resolve",
            });
        }

        let mut ccache: ffi::Krb5Ccache = ptr::null_mut();
        let ret = ffi::krb5_cc_resolve(ctx, ccache_name.as_ptr(), &raw mut ccache);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_resolve failed");
            ffi::krb5_kt_close(ctx, kt_h);
            ffi::krb5_free_principal(ctx, principal_h);
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_cc_resolve",
            });
        }

        let ret = ffi::krb5_cc_initialize(ctx, ccache, principal_h);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_initialize failed");
            ffi::krb5_cc_close(ctx, ccache);
            ffi::krb5_kt_close(ctx, kt_h);
            ffi::krb5_free_principal(ctx, principal_h);
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_cc_initialize",
            });
        }

        let mut creds = ffi::Krb5Creds::new();
        let ret = ffi::krb5_get_init_creds_keytab(
            ctx,
            &raw mut creds,
            principal_h,
            kt_h,
            0,
            ptr::null(),
            ptr::null_mut(),
        );
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_get_init_creds_keytab failed");
            ffi::krb5_cc_close(ctx, ccache);
            ffi::krb5_kt_close(ctx, kt_h);
            ffi::krb5_free_principal(ctx, principal_h);
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_get_init_creds_keytab",
            });
        }

        let store_ret = ffi::krb5_cc_store_cred(ctx, ccache, &raw mut creds);
        ffi::krb5_free_cred_contents(ctx, &raw mut creds);
        if store_ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, store_ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{store_ret:#010x}"), errmsg, "krb5_cc_store_cred failed");
            ffi::krb5_cc_close(ctx, ccache);
            ffi::krb5_kt_close(ctx, kt_h);
            ffi::krb5_free_principal(ctx, principal_h);
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: store_ret,
                msg: "krb5_cc_store_cred",
            });
        }
        ffi::krb5_cc_close(ctx, ccache);
        ffi::krb5_kt_close(ctx, kt_h);
        ffi::krb5_free_principal(ctx, principal_h);
        ffi::krb5_free_context(ctx);
    }
    Ok(())
}

/// The printable name of the first principal in the keytab `kt`, allocated
/// here as a [`CString`].
///
/// For a caller that brought a keytab but named no principal: Heimdal has no
/// credential store that picks the principal for us, so the keytab's own
/// entry order decides which principal the TGT is asked for.
///
/// # Errors
///
/// - [`GssError::Krb5`] — the keytab could not be opened, has no entries, or
///   its principal could not be printed.
#[cfg(heimdal_kerberos)]
fn keytab_first_principal(kt: &CStr) -> Result<CString, GssError> {
    // SAFETY: every handle is initialised here and released on every path, in
    // reverse order of acquisition; the unparsed name is copied out before the
    // context that allocated it is freed.
    unsafe {
        let mut ctx: ffi::Krb5Context = ptr::null_mut();
        let ret = ffi::krb5_init_context(&raw mut ctx);
        if ret != 0 {
            tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_init_context failed");
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_init_context",
            });
        }

        let mut kt_h: ffi::Krb5Keytab = ptr::null_mut();
        let ret = ffi::krb5_kt_resolve(ctx, kt.as_ptr(), &raw mut kt_h);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_kt_resolve failed");
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_kt_resolve",
            });
        }

        let mut cursor = ffi::Krb5KtCursor::new();
        let ret = ffi::krb5_kt_start_seq_get(ctx, kt_h, &raw mut cursor);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_kt_start_seq_get failed");
            ffi::krb5_kt_close(ctx, kt_h);
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_kt_start_seq_get",
            });
        }

        let mut entry = ffi::Krb5KtEntry::new();
        let ret = ffi::krb5_kt_next_entry(ctx, kt_h, &raw mut entry, &raw mut cursor);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_kt_next_entry failed");
            ffi::krb5_kt_end_seq_get(ctx, kt_h, &raw mut cursor);
            ffi::krb5_kt_close(ctx, kt_h);
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_kt_next_entry",
            });
        }

        let mut name: *mut c_char = ptr::null_mut();
        let ret = ffi::krb5_unparse_name(ctx, entry.principal, &raw mut name);
        ffi::krb5_kt_free_entry(ctx, &raw mut entry);
        ffi::krb5_kt_end_seq_get(ctx, kt_h, &raw mut cursor);
        ffi::krb5_kt_close(ctx, kt_h);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_unparse_name failed");
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_unparse_name",
            });
        }

        // SAFETY: name is the NUL-terminated string krb5_unparse_name made; it
        // is copied out and freed before the context goes.
        let principal = CString::new(CStr::from_ptr(name).to_bytes())
            .expect("an unparsed name has no interior NUL byte");
        ffi::krb5_free_unparsed_name(ctx, name);
        ffi::krb5_free_context(ctx);
        Ok(principal)
    }
}

#[cfg(mit_kerberos)]
/// Acquire a Kerberos initiator credential from the `MEMORY:`/`FILE:` ccache
/// named `ccache_name`, via MIT's `gss_acquire_cred_from` credential store.
///
/// # Errors
///
/// - [`GssError::AcquireCred`] — acquisition failed.
fn acquire_initiator_from_ccache(ccache_name: &CStr) -> Result<ffi::GssCredIdT, GssError> {
    let key_ccache = c"ccache";
    let mut element = ffi::GssKeyValueElementDesc {
        key: key_ccache.as_ptr(),
        value: ccache_name.as_ptr(),
    };
    let cred_store = ffi::GssKeyValueSetDesc {
        count: 1,
        elements: &raw mut element,
    };

    let mut minor: ffi::OmUint32 = 0;
    let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
    let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
    let mut time_rec: ffi::OmUint32 = 0;

    // SAFETY: cred_store elements point to live C strings; output pointers are
    // valid stack locals.
    let major = unsafe {
        ffi::gss_acquire_cred_from(
            &raw mut minor,
            ptr::null_mut(), // desired_name = GSS_C_NO_NAME
            0,               // GSS_C_INDEFINITE
            ffi::GSS_C_NO_OID_SET,
            ffi::GSS_C_INITIATE,
            &raw const cred_store,
            &raw mut cred_handle,
            &raw mut actual_mechs,
            &raw mut time_rec,
        )
    };

    let error_minor = minor;
    // SAFETY: actual_mechs is non-null only when set by gss_acquire_cred_from.
    unsafe {
        if !actual_mechs.is_null() {
            ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
        }
    }

    if major != ffi::GSS_S_COMPLETE {
        if !cred_handle.is_null() {
            // SAFETY: set by gss_acquire_cred_from.
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle) };
        }
        let detail = format_gss_status(major, error_minor);
        tracing::warn!(ccache = %ccache_name.to_string_lossy(), major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_from (initiator ccache) failed");
        return Err(GssError::AcquireCred {
            detail,
            major,
            minor: error_minor,
        });
    }
    Ok(cred_handle)
}

#[cfg(heimdal_kerberos)]
/// Acquire a Kerberos initiator credential from the ccache named
/// `ccache_name`, via Heimdal's `gss_krb5_import_cred`.
///
/// Heimdal has no credential-store mechanism; importing a ccache handle
/// yields an INITIATE credential whose principal is the ccache's own
/// client.  Heimdal re-resolves the ccache by name inside its own context,
/// so the handle we pass is only needed for the duration of the call.
///
/// # Errors
///
/// - [`GssError::AcquireCred`] — the ccache could not be opened, parsed, or
///   imported.
fn acquire_initiator_from_ccache(ccache_name: &CStr) -> Result<ffi::GssCredIdT, GssError> {
    // SAFETY: all handles are initialised here and released on every path.
    unsafe {
        let mut ctx: ffi::Krb5Context = ptr::null_mut();
        let ret = ffi::krb5_init_context(&raw mut ctx);
        if ret != 0 {
            tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_init_context failed");
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_init_context",
            });
        }

        let mut ccache: ffi::Krb5Ccache = ptr::null_mut();
        let ret = ffi::krb5_cc_resolve(ctx, ccache_name.as_ptr(), &raw mut ccache);
        if ret != 0 {
            let errmsg_ptr = ffi::krb5_get_error_message(ctx, ret);
            let errmsg = CStr::from_ptr(errmsg_ptr).to_string_lossy().into_owned();
            ffi::krb5_free_error_message(ctx, errmsg_ptr);
            tracing::warn!(code = %format_args!("{ret:#010x}"), errmsg, "krb5_cc_resolve failed");
            ffi::krb5_free_context(ctx);
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_cc_resolve",
            });
        }

        let mut minor: ffi::OmUint32 = 0;
        let mut cred_handle: ffi::GssCredIdT = ptr::null_mut();
        let major = ffi::gss_krb5_import_cred(
            &raw mut minor,
            ccache,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut cred_handle,
        );
        let error_minor = minor;
        ffi::krb5_cc_close(ctx, ccache);
        ffi::krb5_free_context(ctx);

        if major != ffi::GSS_S_COMPLETE {
            if !cred_handle.is_null() {
                // Set by gss_krb5_import_cred; already inside the unsafe block.
                ffi::gss_release_cred(&raw mut minor, &raw mut cred_handle);
            }
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(ccache = %ccache_name.to_string_lossy(), major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_krb5_import_cred (initiator ccache) failed");
            return Err(GssError::AcquireCred {
                detail,
                major,
                minor: error_minor,
            });
        }
        Ok(cred_handle)
    }
}

// ── GssClientContext ──────────────────────────────────────────────────────────

/// In-progress GSSAPI client-side security context for multi-round-trip exchange.
///
/// Holds the evolving context handle and the imported target name so that
/// `gss_init_sec_context` can be called repeatedly with the server's response
/// tokens.  Use [`GssClientContext::new`] to create one and
/// [`GssClientContext::step`] to advance the exchange one HTTP round-trip at a time.
///
/// Drop releases the context handle via `gss_delete_sec_context` and the target
/// name via `gss_release_name`.
pub struct GssClientContext {
    raw: ffi::GssCtxIdT,
    target_name: ffi::GssNameT,
    /// Use the Kerberos V5 mechanism directly instead of SPNEGO.
    krb5: bool,
}

// SAFETY: moving a partially-initialised context to another thread is safe —
// only one thread ever calls step() at a time (no Sync impl).
unsafe impl Send for GssClientContext {}

impl std::fmt::Debug for GssClientContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssClientContext")
            .field("raw", &self.raw)
            .field("target_name", &self.target_name)
            .finish()
    }
}

impl Drop for GssClientContext {
    fn drop(&mut self) {
        let mut minor: ffi::OmUint32 = 0;
        if !self.raw.is_null() {
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: self.raw is a valid context handle set by gss_init_sec_context.
            unsafe {
                ffi::gss_delete_sec_context(&raw mut minor, &raw mut self.raw, &raw mut discard)
            };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard was populated by gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut discard) };
            }
        }
        if !self.target_name.is_null() {
            // SAFETY: self.target_name was returned by gss_import_name.
            unsafe { ffi::gss_release_name(&raw mut minor, &raw mut self.target_name) };
        }
    }
}

impl GssClientContext {
    /// Import `target_service` (e.g. `"HTTP@hostname"`) and prepare a new context.
    ///
    /// Call [`step`](Self::step) to begin the GSSAPI exchange.
    ///
    /// # Errors
    ///
    /// - [`GssError::NulInTargetName`] — `target_service` contains a NUL byte.
    /// - [`GssError::ImportName`] — `gss_import_name` rejected the name.
    pub fn new(target_service: &str) -> Result<Self, GssError> {
        Self::with_name_type(target_service, ffi::gss_c_nt_hostbased_service())
    }

    fn with_name_type(target_service: &str, svc_oid: ffi::GssOidDesc) -> Result<Self, GssError> {
        let svc_cstr = CString::new(target_service).map_err(|_| GssError::NulInTargetName)?;
        let mut minor: ffi::OmUint32 = 0;
        let svc_buf = ffi::GssBufferDesc {
            length: svc_cstr.to_bytes().len(),
            // SAFETY: gss_import_name treats the buffer as read-only.
            #[allow(clippy::as_ptr_cast_mut)]
            value: svc_cstr.as_ptr() as *mut _,
        };
        let mut target_name: ffi::GssNameT = ptr::null_mut();
        // SAFETY: svc_buf wraps a live CString; target_name is a valid output pointer.
        let major = unsafe {
            ffi::gss_import_name(
                &raw mut minor,
                &raw const svc_buf,
                &raw const svc_oid,
                &raw mut target_name,
            )
        };
        if major != ffi::GSS_S_COMPLETE {
            let detail = format_gss_status(major, minor);
            tracing::warn!(target = target_service, major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_import_name (target service) failed");
            return Err(GssError::ImportName {
                detail,
                major,
                minor,
            });
        }
        Ok(GssClientContext {
            raw: ffi::GSS_C_NO_CONTEXT,
            target_name,
            krb5: false,
        })
    }

    /// Like [`new`](Self::new), but with the Kerberos V5 mechanism itself
    /// rather than SPNEGO: without mutual authentication the initiator's
    /// context is then established by its first token, so both sides can
    /// call [`pseudo_random`](Self::pseudo_random) after one message.
    /// `target` is a host-based name (`service@host`) or, if it contains a
    /// `/`, a Kerberos principal name with its realm (`service/host@REALM`),
    /// which needs no realm lookup.
    ///
    /// # Errors
    ///
    /// As for [`new`](Self::new).
    pub fn new_krb5(target: &str) -> Result<Self, GssError> {
        let name_type = if target.contains('/') {
            ffi::gss_krb5_nt_principal_name()
        } else {
            ffi::gss_c_nt_hostbased_service()
        };
        let mut ctx = Self::with_name_type(target, name_type)?;
        ctx.krb5 = true;
        Ok(ctx)
    }

    /// `len` bytes from the established context's key and `input` (RFC
    /// 4401, `GSS_C_PRF_KEY_FULL`); the acceptor derives the same bytes.
    ///
    /// # Errors
    ///
    /// [`GssError::PseudoRandom`] if the context is not established or the
    /// mechanism cannot derive them.
    pub fn pseudo_random(&self, input: &[u8], len: usize) -> Result<Vec<u8>, GssError> {
        pseudo_random(self.raw, input, len)
    }

    /// Advance the exchange by one step.
    ///
    /// `input_token` is `None` on the first call.  On subsequent calls pass the
    /// base64-decoded token from the server's `WWW-Authenticate: Negotiate` header.
    ///
    /// Returns `(output_token, complete)`.  Encode `output_token` as
    /// `Authorization: Negotiate <base64(output_token)>` and send it to the server.
    /// When `complete` is `false` and the server responds with a new
    /// `WWW-Authenticate: Negotiate` token, feed it back into the next `step` call.
    /// When the server returns HTTP 200 the exchange is done regardless of `complete`.
    ///
    /// Both `GSS_S_COMPLETE` and `GSS_S_CONTINUE_NEEDED` are treated as success —
    /// SPNEGO returns `CONTINUE_NEEDED` on the first call even when the Kerberos
    /// AP-REQ is fully formed and ready to send.
    ///
    /// # Errors
    ///
    /// - [`GssError::InitContext`] — `gss_init_sec_context` returned a status
    ///   other than `GSS_S_COMPLETE` or `GSS_S_CONTINUE_NEEDED`.
    pub fn step(
        &mut self,
        cred: &GssClientCred,
        input_token: Option<&[u8]>,
        channel_binding: Option<&[u8]>,
    ) -> Result<(Vec<u8>, bool), GssError> {
        let mut minor: ffi::OmUint32 = 0;

        let input_storage;
        let input_ptr: *const ffi::GssBufferDesc = match input_token {
            None => ptr::null(),
            Some(data) => {
                input_storage = ffi::GssBufferDesc {
                    length: data.len(),
                    // SAFETY: gss_init_sec_context treats input_token as read-only.
                    #[allow(clippy::as_ptr_cast_mut)]
                    value: data.as_ptr() as *mut _,
                };
                &raw const input_storage
            }
        };

        let bindings_storage;
        let chan_bindings_ptr: *const ffi::GssChannelBindingsStruct = match channel_binding {
            None => ptr::null(),
            Some(data) => {
                bindings_storage = ffi::GssChannelBindingsStruct {
                    initiator_addrtype: ffi::GSS_C_AF_UNSET,
                    initiator_address: ffi::gss_c_no_buffer(),
                    acceptor_addrtype: ffi::GSS_C_AF_UNSET,
                    acceptor_address: ffi::gss_c_no_buffer(),
                    application_data: ffi::GssBufferDesc {
                        length: data.len(),
                        // SAFETY: application_data is treated as read-only.
                        #[allow(clippy::as_ptr_cast_mut)]
                        value: data.as_ptr() as *mut _,
                    },
                };
                &raw const bindings_storage
            }
        };

        let mut output_buf = ffi::gss_c_no_buffer();
        let mut ret_flags: ffi::OmUint32 = 0;
        let mut time_rec: ffi::OmUint32 = 0;
        let krb5_oid = ffi::gss_mech_krb5();
        let mech: *const ffi::GssOidDesc = if self.krb5 {
            &raw const krb5_oid
        } else {
            ptr::null() // default (SPNEGO)
        };

        // SAFETY: cred.raw is a live initiator credential; self.target_name was set
        // by gss_import_name and is retained for the struct's lifetime; self.raw
        // starts as GSS_C_NO_CONTEXT and is updated in-place by the library;
        // input_ptr is null or points to a live stack buffer; chan_bindings_ptr is
        // null or points to bindings_storage which lives until after this call.
        let major = unsafe {
            ffi::gss_init_sec_context(
                &raw mut minor,
                cred.raw,
                &raw mut self.raw,
                self.target_name,
                mech, // null or krb5_oid, which lives until after this call
                // No GSS_C_MUTUAL_FLAG: all callers use HTTPS where TLS
                // already provides server authentication.  Requesting mutual
                // auth forces a two-leg AP-REQ/AP-REP exchange; the IPA
                // JSON-RPC layer does not implement the second leg, causing
                // GSS_S_CONTINUE_NEEDED to be treated as an error.
                0,
                0, // time_req = library default
                chan_bindings_ptr,
                input_ptr,
                ptr::null_mut(), // actual_mech_type — not needed
                &raw mut output_buf,
                &raw mut ret_flags,
                &raw mut time_rec,
            )
        };

        let error_minor = minor;

        let out_token: Vec<u8> = if output_buf.length > 0 && !output_buf.value.is_null() {
            // SAFETY: output_buf.value points to output_buf.length valid bytes.
            let slice = unsafe {
                std::slice::from_raw_parts(output_buf.value as *const u8, output_buf.length)
            };
            let v = slice.to_vec();
            // SAFETY: output_buf was populated by gss_init_sec_context.
            unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut output_buf) };
            v
        } else {
            Vec::new()
        };

        if major != ffi::GSS_S_COMPLETE && major != ffi::GSS_S_CONTINUE_NEEDED {
            let detail = format_gss_status(major, error_minor);
            tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_init_sec_context failed");
            return Err(GssError::InitContext {
                detail,
                major,
                minor: error_minor,
            });
        }

        Ok((out_token, major == ffi::GSS_S_COMPLETE))
    }
}

// ── GssServerContext ──────────────────────────────────────────────────────────

/// Result of one GSSAPI server-side accept step.
///
/// Returned by [`accept_token`] and [`GssServerContext::step`].
#[derive(Debug)]
pub enum AcceptStep {
    /// Exchange is complete.  `principal` is the authenticated client identity
    /// (e.g. `"user@REALM"`).  `out_token` is the optional mutual-authentication
    /// response; encode it as `WWW-Authenticate: Negotiate <base64>` if non-empty.
    Complete {
        out_token: Vec<u8>,
        principal: String,
    },
    /// The mechanism needs another round-trip.  Send `out_token` as
    /// `WWW-Authenticate: Negotiate <base64>` with `401 Unauthorized`, then call
    /// [`GssServerContext::step`] with the client's next `Authorization: Negotiate`
    /// token.  `ctx` must be kept alive between the two HTTP requests.
    Continue {
        out_token: Vec<u8>,
        ctx: GssServerContext,
    },
}

/// In-progress GSSAPI server-side security context for multi-round-trip exchange.
///
/// Wraps the partially-initialized `gss_ctx_id_t` produced when
/// `gss_accept_sec_context` returns `GSS_S_CONTINUE_NEEDED`.  Call
/// [`GssServerContext::step`] with the client's next token to advance the exchange.
///
/// Drop releases the context handle via `gss_delete_sec_context`.
pub struct GssServerContext {
    raw: ffi::GssCtxIdT,
}

// SAFETY: moving a partially-initialized server context to another thread is
// safe — only one thread ever calls step() at a time (no Sync impl).
unsafe impl Send for GssServerContext {}

impl std::fmt::Debug for GssServerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssServerContext")
            .field("raw", &self.raw)
            .finish()
    }
}

impl Drop for GssServerContext {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let mut minor: ffi::OmUint32 = 0;
            let mut discard = ffi::gss_c_no_buffer();
            // SAFETY: self.raw is a valid context handle set by gss_accept_sec_context.
            unsafe {
                ffi::gss_delete_sec_context(&raw mut minor, &raw mut self.raw, &raw mut discard)
            };
            if discard.length > 0 && !discard.value.is_null() {
                // SAFETY: discard was populated by gss_delete_sec_context.
                unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut discard) };
            }
        }
    }
}

impl GssServerContext {
    /// Advance the server-side SPNEGO exchange by one step.
    ///
    /// `input_token` is the SPNEGO/Kerberos token from the client's
    /// `Authorization: Negotiate` header (base64-decoded).
    /// `channel_binding` should be the `tls-server-end-point` bytes (RFC 5929 §4)
    /// or `None`.
    ///
    /// Consumes `self`; on [`AcceptStep::Continue`] the new [`GssServerContext`]
    /// inside the variant must be stored for the next call.
    ///
    /// # Errors
    ///
    /// - [`GssError::AcceptContext`] — `gss_accept_sec_context` rejected the token.
    /// - [`GssError::DisplayName`] — the principal name could not be converted.
    /// - [`GssError::InvalidUtf8`] — the principal name is not valid UTF-8.
    pub fn step(
        self,
        cred: &GssServerCred,
        input_token: &[u8],
        channel_binding: Option<&[u8]>,
    ) -> Result<AcceptStep, GssError> {
        Ok(self.step_prf(cred, input_token, channel_binding, None)?.0)
    }

    /// [`step`](Self::step), and on completion also `prf.1` bytes of
    /// [`pseudo_random`] output for input `prf.0`, taken before the context
    /// is released.
    fn step_prf(
        mut self,
        cred: &GssServerCred,
        input_token: &[u8],
        channel_binding: Option<&[u8]>,
        prf: Option<(&[u8], usize)>,
    ) -> Result<(AcceptStep, Option<Vec<u8>>), GssError> {
        let mut minor: ffi::OmUint32 = 0;

        let input_buf = ffi::GssBufferDesc {
            length: input_token.len(),
            // SAFETY: gss_accept_sec_context treats input_token_buffer as read-only
            // per RFC 2744 §2; *const → *mut cast is safe for C APIs with that contract.
            #[allow(clippy::as_ptr_cast_mut)]
            value: input_token.as_ptr() as *mut _,
        };
        let mut output_buf = ffi::gss_c_no_buffer();
        let mut src_name: ffi::GssNameT = ptr::null_mut();
        let mut ret_flags: ffi::OmUint32 = 0;
        let mut time_rec: ffi::OmUint32 = 0;
        let mut delegated_cred: ffi::GssCredIdT = ptr::null_mut();

        // `bindings_storage` must outlive the FFI call below.
        let bindings_storage;
        let chan_bindings_ptr: *const ffi::GssChannelBindingsStruct = match channel_binding {
            None => ptr::null(),
            Some(data) => {
                bindings_storage = ffi::GssChannelBindingsStruct {
                    initiator_addrtype: ffi::GSS_C_AF_UNSET,
                    initiator_address: ffi::gss_c_no_buffer(),
                    acceptor_addrtype: ffi::GSS_C_AF_UNSET,
                    acceptor_address: ffi::gss_c_no_buffer(),
                    application_data: ffi::GssBufferDesc {
                        length: data.len(),
                        // SAFETY: gss_accept_sec_context treats application_data as
                        // read-only; *const → *mut cast is safe per RFC 2744 §2.
                        #[allow(clippy::as_ptr_cast_mut)]
                        value: data.as_ptr() as *mut _,
                    },
                };
                &raw const bindings_storage
            }
        };

        // SAFETY: self.raw is GSS_C_NO_CONTEXT (initial call) or a valid partial
        // context from a prior gss_accept_sec_context; cred.raw is a live acceptor
        // credential; chan_bindings_ptr is null or points to stack-allocated
        // bindings_storage which remains live until after this call returns.
        let major = unsafe {
            ffi::gss_accept_sec_context(
                &raw mut minor,
                &raw mut self.raw,
                cred.raw,
                &raw const input_buf,
                chan_bindings_ptr,
                &raw mut src_name,
                ptr::null_mut(), // mech_type — not needed
                &raw mut output_buf,
                &raw mut ret_flags,
                &raw mut time_rec,
                &raw mut delegated_cred,
            )
        };

        // Release delegated credential immediately — never used.
        if !delegated_cred.is_null() {
            // SAFETY: set by gss_accept_sec_context.
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut delegated_cred) };
        }

        // Copy output token before freeing the GSSAPI buffer.
        let out_token: Vec<u8> = if output_buf.length > 0 && !output_buf.value.is_null() {
            // SAFETY: output_buf.value is valid for output_buf.length bytes.
            let slice = unsafe {
                std::slice::from_raw_parts(output_buf.value as *const u8, output_buf.length)
            };
            let v = slice.to_vec();
            // SAFETY: output_buf was populated by gss_accept_sec_context.
            unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut output_buf) };
            v
        } else {
            Vec::new()
        };

        let error_minor = minor;

        match major {
            ffi::GSS_S_COMPLETE => {
                if ret_flags & ffi::GSS_C_REPLAY_FLAG == 0 {
                    // Expected when the client is a browser over TLS — TLS provides
                    // replay protection so Kerberos replay detection is typically not
                    // negotiated.  Not actionable; logged at debug to avoid noise.
                    tracing::debug!("GSSAPI context established without replay detection flag");
                }
                // Extract the principal name string.
                let mut name_buf = ffi::gss_c_no_buffer();
                // SAFETY: src_name is a valid GssNameT set by gss_accept_sec_context.
                let major_dn = unsafe {
                    ffi::gss_display_name(
                        &raw mut minor,
                        src_name,
                        &raw mut name_buf,
                        ptr::null_mut(),
                    )
                };
                // Snapshot minor before gss_release_name overwrites it.
                let dn_minor = minor;
                // SAFETY: src_name is valid; gss_release_name takes ownership.
                unsafe { ffi::gss_release_name(&raw mut minor, &raw mut src_name) };

                let principal = if major_dn == ffi::GSS_S_COMPLETE && !name_buf.value.is_null() {
                    // SAFETY: name_buf.value is valid for name_buf.length bytes.
                    let slice = unsafe {
                        std::slice::from_raw_parts(name_buf.value as *const u8, name_buf.length)
                    };
                    let s = std::str::from_utf8(slice)
                        .map(std::borrow::ToOwned::to_owned)
                        .map_err(|_| GssError::InvalidUtf8);
                    // SAFETY: name_buf was populated by gss_display_name.
                    unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut name_buf) };
                    s?
                } else {
                    // SAFETY: name_buf may be empty or null; gss_release_buffer handles both.
                    unsafe { ffi::gss_release_buffer(&raw mut minor, &raw mut name_buf) };
                    return Err(GssError::DisplayName {
                        detail: format_gss_status(major_dn, dn_minor),
                        major: major_dn,
                        minor: dn_minor,
                    });
                };

                let derived = prf
                    .map(|(input, len)| pseudo_random(self.raw, input, len))
                    .transpose()?;
                // self goes out of scope here; Drop deletes self.raw.
                Ok((
                    AcceptStep::Complete {
                        out_token,
                        principal,
                    },
                    derived,
                ))
            }

            ffi::GSS_S_CONTINUE_NEEDED => {
                if !src_name.is_null() {
                    // SAFETY: src_name is valid (may be set even on CONTINUE_NEEDED).
                    unsafe { ffi::gss_release_name(&raw mut minor, &raw mut src_name) };
                }
                // Transfer self.raw to a new GssServerContext for the caller to persist.
                // Setting self.raw to null prevents Drop from double-freeing.
                let raw = self.raw;
                self.raw = ffi::GSS_C_NO_CONTEXT;
                Ok((
                    AcceptStep::Continue {
                        out_token,
                        ctx: GssServerContext { raw },
                    },
                    None,
                ))
            }

            _ => {
                if !src_name.is_null() {
                    // SAFETY: src_name is valid.
                    unsafe { ffi::gss_release_name(&raw mut minor, &raw mut src_name) };
                }
                let detail = format_gss_status(major, error_minor);
                tracing::warn!(major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_accept_sec_context failed");
                // self goes out of scope here; Drop deletes self.raw.
                Err(GssError::AcceptContext {
                    detail,
                    major,
                    minor: error_minor,
                })
            }
        }
    }
}

// ── InitStep ──────────────────────────────────────────────────────────────────

/// Result of the first GSSAPI client-side init step.
///
/// Returned by [`init_token`].
#[derive(Debug)]
pub enum InitStep {
    /// The exchange is complete after the first token.  Encode `token` as
    /// `Authorization: Negotiate <base64>` and send it.
    Complete(Vec<u8>),
    /// The mechanism needs at least one more round-trip.  Send `token` to the
    /// server; if the server replies with `WWW-Authenticate: Negotiate <base64>`,
    /// decode the server token and pass it to [`GssClientContext::step`] on `ctx`.
    Continue {
        token: Vec<u8>,
        ctx: GssClientContext,
    },
}

/// Acquire a delegated credential acting as `user_principal` using the gssproxy-managed
/// server (acceptor) credential as the impersonator (S4U2Self).
///
/// This is the correct impersonation path when gssproxy manages the credential store.
/// Using a locally-acquired initiator credential as the impersonator causes the resulting
/// S4U2Self credential to also be local; when that credential is then passed to
/// `gss_init_sec_context`, gssproxy's proxymech falls back to `init_ctx_local`, which calls
/// `gpp_name_to_local` and crashes due to a static-OID free bug in gssproxy ≤ 0.9.2.
///
/// By contrast, the gssproxy-managed ACCEPT credential (from `GssServerCred::from_gssproxy`)
/// is already in gssproxy's credential table.  `gss_acquire_cred_impersonate_name` with that
/// credential produces a gssproxy-managed S4U2Self credential, so the subsequent
/// `gss_init_sec_context` is handled remotely without triggering `init_ctx_local`.
///
/// This mirrors the pattern used by mod_auth_gssapi for S4U2Self LDAP lookups.
///
/// # Errors
///
/// - [`GssError::Unsupported`] — this build links Heimdal, which has no
///   `gss_acquire_cred_impersonate_name`.
/// - [`GssError::NulInUserPrincipal`] — `user_principal` contains a NUL byte.
/// - [`GssError::ImportName`] — `gss_import_name` rejected the principal.
/// - [`GssError::ImpersonateCred`] — `gss_acquire_cred_impersonate_name` failed.
pub fn impersonate_with_server_cred(
    server: &GssServerCred,
    user_principal: &str,
) -> Result<GssClientCred, GssError> {
    #[cfg(mit_kerberos)]
    return impersonate_with_server_cred_mit(server, user_principal);
    #[cfg(heimdal_kerberos)]
    {
        let _ = (server, user_principal);
        Err(GssError::Unsupported {
            feature: "S4U2Self (gss_acquire_cred_impersonate_name)",
        })
    }
}

#[cfg(mit_kerberos)]
fn impersonate_with_server_cred_mit(
    server: &GssServerCred,
    user_principal: &str,
) -> Result<GssClientCred, GssError> {
    let principal_cstr = CString::new(user_principal).map_err(|_| GssError::NulInUserPrincipal)?;
    let mut minor: ffi::OmUint32 = 0;

    let principal_oid = ffi::gss_krb5_nt_principal_name();
    let principal_buf = ffi::GssBufferDesc {
        length: principal_cstr.to_bytes().len(),
        #[allow(clippy::as_ptr_cast_mut)]
        value: principal_cstr.as_ptr() as *mut _,
    };
    let mut user_name: ffi::GssNameT = ptr::null_mut();
    // SAFETY: minor, principal_buf, and principal_oid are valid stack values.
    let major = unsafe {
        ffi::gss_import_name(
            &raw mut minor,
            &raw const principal_buf,
            &raw const principal_oid,
            &raw mut user_name,
        )
    };
    if major != ffi::GSS_S_COMPLETE {
        let detail = format_gss_status(major, minor);
        tracing::warn!(principal = user_principal, major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "gss_import_name (user principal for server-cred S4U2Self) failed");
        return Err(GssError::ImportName {
            detail,
            major,
            minor,
        });
    }

    let mut impersonated: ffi::GssCredIdT = ptr::null_mut();
    let mut actual_mechs: ffi::GssOidSetT = ptr::null_mut();
    let mut time_rec: ffi::OmUint32 = 0;

    // SAFETY: server.raw is the gssproxy-managed ACCEPT credential; user_name was
    // returned by gss_import_name and is still valid; output pointers are valid locals.
    let major = unsafe {
        ffi::gss_acquire_cred_impersonate_name(
            &raw mut minor,
            server.raw,
            user_name,
            0,
            ffi::GSS_C_NO_OID_SET,
            ffi::GSS_C_INITIATE,
            &raw mut impersonated,
            &raw mut actual_mechs,
            &raw mut time_rec,
        )
    };

    let error_minor = minor;
    unsafe {
        ffi::gss_release_name(&raw mut minor, &raw mut user_name);
        if !actual_mechs.is_null() {
            ffi::gss_release_oid_set(&raw mut minor, &raw mut actual_mechs);
        }
    }

    if major != ffi::GSS_S_COMPLETE {
        if !impersonated.is_null() {
            unsafe { ffi::gss_release_cred(&raw mut minor, &raw mut impersonated) };
        }
        let detail = format_gss_status(major, error_minor);
        tracing::warn!(principal = user_principal, major = %format_args!("{major:#010x}"), minor = %format_args!("{error_minor:#010x}"), %detail, "gss_acquire_cred_impersonate_name (server-cred S4U2Self) failed");
        return Err(GssError::ImpersonateCred {
            detail,
            major,
            minor: error_minor,
        });
    }

    Ok(GssClientCred { raw: impersonated })
}

// ── init_token ────────────────────────────────────────────────────────────────

/// Produce the first SPNEGO/Kerberos token for `target_service`.
///
/// `target_service` must be in host-based format: `"HTTP@hostname"`.
/// `channel_binding` is the `tls-server-end-point` bytes (RFC 5929 §4) or `None`.
///
/// Returns [`InitStep::Complete`] when the token is ready to send and no
/// further steps are expected.  Returns [`InitStep::Continue`] when the
/// mechanism (e.g. IAKERB) requires additional round-trips; use the bundled
/// [`GssClientContext`] to drive the exchange to completion.
///
/// # Errors
///
/// - [`GssError::NulInTargetName`] — `target_service` contains a NUL byte.
/// - [`GssError::ImportName`] — `gss_import_name` rejected the target name.
/// - [`GssError::InitContext`] — `gss_init_sec_context` failed.
pub fn init_token(
    cred: &GssClientCred,
    target_service: &str,
    channel_binding: Option<&[u8]>,
) -> Result<InitStep, GssError> {
    let mut ctx = GssClientContext::new(target_service)?;
    let (token, complete) = ctx.step(cred, None, channel_binding)?;
    if complete {
        Ok(InitStep::Complete(token))
    } else {
        Ok(InitStep::Continue { token, ctx })
    }
}

// ── One-message exchanges bound to a key ─────────────────────────────────────

/// `len` bytes of RFC 4401 output from the established context `raw`.
fn pseudo_random(raw: ffi::GssCtxIdT, input: &[u8], len: usize) -> Result<Vec<u8>, GssError> {
    let mut minor: ffi::OmUint32 = 0;
    let in_buf = ffi::GssBufferDesc {
        length: input.len(),
        // SAFETY: gss_pseudo_random treats prf_in as read-only.
        #[allow(clippy::as_ptr_cast_mut)]
        value: input.as_ptr() as *mut _,
    };
    let mut out_buf = ffi::gss_c_no_buffer();
    let wanted = isize::try_from(len).map_err(|_| GssError::PseudoRandom {
        major: 0,
        minor: 0,
        detail: "output length too large".into(),
    })?;
    // SAFETY: raw is null or a context handle owned by the caller; in_buf
    // wraps a live slice; out_buf is a valid output buffer.
    let major = unsafe {
        ffi::gss_pseudo_random(
            &raw mut minor,
            raw,
            ffi::GSS_C_PRF_KEY_FULL,
            &raw const in_buf,
            wanted,
            &raw mut out_buf,
        )
    };
    let error_minor = minor;
    let out = if out_buf.length > 0 && !out_buf.value.is_null() {
        // SAFETY: out_buf.value points to out_buf.length valid bytes.
        let v = unsafe {
            std::slice::from_raw_parts(out_buf.value as *const u8, out_buf.length).to_vec()
        };
        // SAFETY: out_buf was populated by gss_pseudo_random; wipe it first.
        unsafe {
            ptr::write_bytes(out_buf.value.cast::<u8>(), 0, out_buf.length);
            ffi::gss_release_buffer(&raw mut minor, &raw mut out_buf);
        }
        v
    } else {
        Vec::new()
    };
    if major != ffi::GSS_S_COMPLETE || out.len() != len {
        return Err(GssError::PseudoRandom {
            detail: format_gss_status(major, error_minor),
            major,
            minor: error_minor,
        });
    }
    Ok(out)
}

/// One Kerberos V5 token for `target_service` (`service@host`, or a
/// principal `service/host@REALM`; no SPNEGO, no mutual
/// authentication) bound to `channel_binding`, and `len` bytes derived from
/// the context with `prf_input` (RFC 4401).  Only an acceptor that can
/// decrypt the service ticket derives the same bytes ([`accept_bound`]),
/// so a key mixed with them authenticates that acceptor.
///
/// # Errors
///
/// As for [`init_token`], [`GssError::NotComplete`] if the mechanism needs
/// another round trip, or [`GssError::PseudoRandom`].
pub fn init_bound(
    cred: &GssClientCred,
    target_service: &str,
    channel_binding: &[u8],
    prf_input: &[u8],
    len: usize,
) -> Result<(Vec<u8>, Vec<u8>), GssError> {
    let mut ctx = GssClientContext::new_krb5(target_service)?;
    let (token, complete) = ctx.step(cred, None, Some(channel_binding))?;
    if !complete {
        return Err(GssError::NotComplete);
    }
    let derived = ctx.pseudo_random(prf_input, len)?;
    Ok((token, derived))
}

/// Accept a one-message token from [`init_bound`] (or any token that
/// completes in one step) bound to `channel_binding`; return the client
/// principal and `len` bytes derived from the context with `prf_input`.
///
/// # Errors
///
/// As for [`accept_token`], [`GssError::NotComplete`] if the exchange
/// needs another round trip, or [`GssError::PseudoRandom`].
pub fn accept_bound(
    cred: &GssServerCred,
    input_token: &[u8],
    channel_binding: &[u8],
    prf_input: &[u8],
    len: usize,
) -> Result<(String, Vec<u8>), GssError> {
    let (step, derived) = GssServerContext {
        raw: ffi::GSS_C_NO_CONTEXT,
    }
    .step_prf(
        cred,
        input_token,
        Some(channel_binding),
        Some((prf_input, len)),
    )?;
    match (step, derived) {
        (AcceptStep::Complete { principal, .. }, Some(derived)) => Ok((principal, derived)),
        _ => Err(GssError::NotComplete),
    }
}

// ── accept_token ──────────────────────────────────────────────────────────────

/// Process one SPNEGO/Kerberos token received in `Authorization: Negotiate`.
///
/// `channel_binding` should be the `tls-server-end-point` bytes (RFC 5929 §4)
/// when TLS is terminated by this server, or `None` when running without TLS or
/// when the server certificate uses an algorithm with no defined binding hash
/// (e.g. ML-DSA).
///
/// Returns [`AcceptStep::Complete`] when the client is authenticated.
/// Returns [`AcceptStep::Continue`] when the mechanism needs another round-trip;
/// send the enclosed token in `WWW-Authenticate: Negotiate` with `401` and call
/// [`GssServerContext::step`] with the client's response.
///
/// # Errors
///
/// - [`GssError::AcceptContext`] — `gss_accept_sec_context` rejected the token
///   (expired ticket, wrong service, replay, or forged token).
/// - [`GssError::DisplayName`] — the authenticated name could not be converted
///   to a printable string by `gss_display_name`.
/// - [`GssError::InvalidUtf8`] — the display name returned by the GSSAPI
///   library is not valid UTF-8.
pub fn accept_token(
    cred: &GssServerCred,
    input_token: &[u8],
    channel_binding: Option<&[u8]>,
) -> Result<AcceptStep, GssError> {
    GssServerContext {
        raw: ffi::GSS_C_NO_CONTEXT,
    }
    .step(cred, input_token, channel_binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_nul_in_service_name_returns_error() {
        let err = GssServerCred::acquire("HTTP\0badname", "/tmp/fake.keytab").unwrap_err();
        assert!(matches!(err, GssError::NulInServiceName));
    }

    #[test]
    fn acquire_nul_in_keytab_path_returns_error() {
        let err = GssServerCred::acquire("HTTP", "/tmp/\0fake.keytab").unwrap_err();
        assert!(matches!(err, GssError::NulInKeytabPath));
    }

    #[test]
    fn from_keytab_nul_in_path_returns_error() {
        let err = GssClientCred::from_keytab("/tmp/\0bad.keytab").unwrap_err();
        assert!(matches!(err, GssError::NulInKeytabPath));
    }

    #[test]
    fn init_token_nul_in_target_returns_error() {
        // Safety: won't reach any FFI — NUL check fires before gss_import_name.
        // We use a zeroed cred to avoid a real keytab dependency; the NUL check
        // fires before any FFI call that would dereference the raw pointer.
        let cred = GssClientCred {
            raw: ptr::null_mut(),
        };
        let err = init_token(&cred, "HTTP\0bad.host", None).unwrap_err();
        assert!(matches!(err, GssError::NulInTargetName));
        // Prevent Drop from calling gss_release_cred on a null handle.
        std::mem::forget(cred);
    }
}
