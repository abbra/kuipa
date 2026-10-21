//! Safe, idiomatic Rust wrapper around the raw LDAP FFI layer.
//!
//! # Design
//!
//! [`LdapConnection`] is an RAII handle: it calls `ldap_unbind_ext_s` on drop
//! so connections are never leaked.  All unsafe pointer work is contained here;
//! nothing leaks raw C types into the public API.
//!
//! Synchronous `_s` variants of libldap functions are used throughout.
//! Callers should run this code in `tokio::task::spawn_blocking` when
//! integrating with async runtimes.

use std::collections::HashMap;
use std::ffi::{CStr, CString, NulError};
use std::ptr;

use libc::{c_char, c_int, c_void, timeval};
use tracing::debug;

use crate::ffi::{self, berval, BerElement, LDAP};
use crate::{Auth, LdapError, Scope};

// ── SASL interact callback ────────────────────────────────────────────────────

/// SASL interactive callback for GSSAPI binds.
///
/// Answers every SASL prompt with an empty string.  When `defaults` is
/// non-null it is treated as a `gss_cred_id_t` and injected into the SASL
/// context via `LDAP_OPT_X_SASL_GSS_CREDS`.  The callback is invoked by
/// Cyrus SASL's GSSAPI plugin (for the AUTHZID prompt) *after*
/// `ldap_int_sasl_open` has created the SASL context but *before*
/// `gss_init_sec_context` is called, so the credential is available for
/// the first GSSAPI token exchange.
///
/// When the credential cannot be injected, the callback fails the SASL
/// exchange: a bind that proceeds with the process's default Kerberos
/// identity instead of the injected one would silently act as another
/// principal.
pub(crate) unsafe extern "C" fn sasl_interact_gssapi(
    ld: *mut LDAP,
    _flags: libc::c_uint,
    defaults: *mut c_void,
    interact_raw: *mut c_void,
) -> c_int {
    if !defaults.is_null() {
        tracing::trace!(cred = ?defaults, "sasl_interact: injecting GSS credential");
        let rc = ffi::ldap_set_option(ld, ffi::LDAP_OPT_X_SASL_GSS_CREDS, defaults.cast_const());
        if rc != ffi::LDAP_SUCCESS {
            // Fail rather than continue with whatever identity the
            // process would otherwise use: the bind must not proceed as
            // the wrong principal.
            tracing::error!(rc, "ldap_set_option(LDAP_OPT_X_SASL_GSS_CREDS) failed");
            return rc;
        }
        tracing::trace!(rc, "ldap_set_option(LDAP_OPT_X_SASL_GSS_CREDS) succeeded");
    } else {
        tracing::trace!("sasl_interact: no credential (defaults is null)");
    }
    // SAFETY: libldap provides a non-null, properly aligned, SASL_CB_LIST_END-
    // terminated sasl_interact array for the lifetime of this callback. Advancing
    // by 1 element per iteration stays within the allocation until the sentinel.
    if interact_raw.is_null() {
        return ffi::LDAP_SUCCESS;
    }
    let mut interact = interact_raw.cast::<ffi::sasl_interact>();
    while (*interact).id != ffi::SASL_CB_LIST_END {
        (*interact).result = c"".as_ptr().cast::<c_void>();
        (*interact).len = 0;
        interact = interact.add(1);
    }
    ffi::LDAP_SUCCESS
}

// ── LdapConnection ────────────────────────────────────────────────────────────

/// A synchronous LDAP session handle.
///
/// The connection is opened immediately on construction.  Use [`Auth::Simple`]
/// or [`Auth::Gssapi`] to authenticate before calling [`search`][Self::search].
///
/// The underlying `LDAP *` handle is freed (via `ldap_unbind_ext_s`) when this
/// value is dropped, even if no explicit `unbind` call was made.
#[derive(Debug)]
pub struct LdapConnection {
    /// Raw `OpenLDAP` session pointer.  Always non-null after construction.
    ld: *mut LDAP,
}

// SAFETY: OpenLDAP connections use a single connection handle internally; we
// never share a raw *mut LDAP between threads — the caller must ensure the
// connection is used from one thread at a time (or inside spawn_blocking).
// Making the type Send allows moving it into a blocking task.
unsafe impl Send for LdapConnection {}

impl Drop for LdapConnection {
    fn drop(&mut self) {
        // ldap_unbind_ext_s always succeeds for session teardown; the return
        // value is discarded intentionally.
        // SAFETY: self.ld is always non-null after construction (guaranteed by connect); ldap_unbind_ext_s is valid to call exactly once on a live LDAP*.
        unsafe {
            ffi::ldap_unbind_ext_s(self.ld, ptr::null_mut(), ptr::null_mut());
        }
    }
}

impl LdapConnection {
    // ── Constructor ───────────────────────────────────────────────────────────

    /// Open an LDAP connection to `uri` (e.g. `"ldap://host:389"` or
    /// `"ldaps://host:636"`).
    ///
    /// When `tls_ca_cert_file` is `Some(path)`, the PEM file at `path` is
    /// used to verify the server's TLS certificate.  For `ldap://` URIs with a
    /// CA cert, STARTTLS is negotiated before any credentials are sent.  For
    /// `ldaps://` URIs the TLS handshake happens immediately on connect.
    ///
    /// When `force_starttls` is `true`, STARTTLS is negotiated on `ldap://` URIs
    /// even when no explicit CA cert is given (the system trust store is used).
    /// Ignored for `ldaps://` URIs (TLS is implicit) and has no effect when the
    /// URI already triggers STARTTLS via `tls_ca_cert_file`.
    ///
    /// For GSSAPI binds over plain `ldap://`, pass `tls_ca_cert_file = None` and
    /// `force_starttls = false`: GSSAPI provides its own cryptographic protection.
    ///
    /// `timeout_secs` sets both the TCP-level connect timeout and the default
    /// operation timeout (`LDAP_OPT_NETWORK_TIMEOUT` + `LDAP_OPT_TIMEOUT`).
    /// Pass 0 to use the OS default (no finite timeout).
    pub fn connect(
        uri: &str,
        tls_ca_cert_file: Option<&str>,
        force_starttls: bool,
        timeout_secs: u64,
    ) -> Result<Self, LdapError> {
        let needs_tls = tls_ca_cert_file.is_some() || uri.starts_with("ldaps://") || force_starttls;
        let starttls = needs_tls && uri.starts_with("ldap://");
        debug!(uri, tls = needs_tls, starttls, "LDAP connect");

        let uri_c = cstr(uri)?;
        let mut ld: *mut LDAP = ptr::null_mut();

        // SAFETY: uri_c is a valid NUL-terminated C string produced by CString::new; ldap_initialize writes into &mut ld which is properly initialised to null.
        let rc = unsafe { ffi::ldap_initialize(&raw mut ld, uri_c.as_ptr()) };
        check(rc, "ldap_initialize")?;

        // Wrap immediately so Drop (ldap_unbind_ext_s) runs on all error paths below.
        let conn = Self { ld };

        // Enforce LDAPv3.
        let v3: c_int = 3;
        // SAFETY: conn.ld is non-null (ldap_initialize returned LDAP_SUCCESS above); v3 is a stack-allocated c_int whose address is valid for the duration of this call.
        let rc = unsafe {
            ffi::ldap_set_option(
                conn.ld,
                ffi::LDAP_OPT_PROTOCOL_VERSION,
                (&raw const v3).cast(),
            )
        };
        if rc == ffi::LDAP_OPT_ERROR {
            return Err(LdapError::Protocol {
                code: rc,
                msg: "ldap_set_option(PROTOCOL_VERSION) failed".into(),
            });
        }

        // Set connect and operation timeouts to prevent indefinite blocking.
        if timeout_secs > 0 {
            let tv = timeval {
                tv_sec: timeout_secs as libc::time_t,
                tv_usec: 0,
            };
            // SAFETY: conn.ld is non-null; tv is a valid stack-allocated timeval whose address is valid for the duration of this call.
            let rc = unsafe {
                ffi::ldap_set_option(
                    conn.ld,
                    ffi::LDAP_OPT_NETWORK_TIMEOUT,
                    (&raw const tv).cast(),
                )
            };
            if rc == ffi::LDAP_OPT_ERROR {
                tracing::warn!(
                    "ldap_set_option(NETWORK_TIMEOUT) failed; LDAP connects may block indefinitely"
                );
            }
            // SAFETY: conn.ld is non-null; tv is a valid stack-allocated timeval (same object as above) whose address is valid for the duration of this call.
            let rc = unsafe {
                ffi::ldap_set_option(conn.ld, ffi::LDAP_OPT_TIMEOUT, (&raw const tv).cast())
            };
            if rc == ffi::LDAP_OPT_ERROR {
                tracing::warn!(
                    "ldap_set_option(TIMEOUT) failed; LDAP operations may block indefinitely"
                );
            }
        }

        if let Some(ca_path) = tls_ca_cert_file {
            std::fs::metadata(ca_path)
                .map_err(|e| LdapError::Tls(format!("cannot read TLS CA cert '{ca_path}': {e}")))?;
            let path_c = cstr(ca_path)?;
            // SAFETY: conn.ld is non-null; path_c is a valid NUL-terminated C string produced by CString::new and lives for the duration of this call.
            let rc = unsafe {
                ffi::ldap_set_option(
                    conn.ld,
                    ffi::LDAP_OPT_X_TLS_CACERTFILE,
                    path_c.as_ptr().cast(),
                )
            };
            if rc == ffi::LDAP_OPT_ERROR {
                return Err(LdapError::Tls(format!(
                    "ldap_set_option(CACERTFILE, '{ca_path}') failed"
                )));
            }
            // Rebuild the TLS context so the new CA takes effect.
            let zero: c_int = 0;
            // SAFETY: conn.ld is non-null; zero is a valid stack-allocated c_int whose address is valid for the duration of this call.
            let rc = unsafe {
                ffi::ldap_set_option(
                    conn.ld,
                    ffi::LDAP_OPT_X_TLS_NEWCTX,
                    (&raw const zero).cast(),
                )
            };
            if rc == ffi::LDAP_OPT_ERROR {
                return Err(LdapError::Tls(
                    "ldap_set_option(NEWCTX) failed — CA cert may be invalid or unsupported".into(),
                ));
            }
        }

        if starttls {
            // SAFETY: conn.ld is non-null; null server/client controls are valid per OpenLDAP documentation.
            let rc = unsafe { ffi::ldap_start_tls_s(conn.ld, ptr::null_mut(), ptr::null_mut()) };
            if rc != ffi::LDAP_SUCCESS {
                return Err(LdapError::Tls(format!(
                    "STARTTLS failed: {}",
                    err_string(rc)
                )));
            }
        }

        Ok(conn)
    }

    // ── Bind ──────────────────────────────────────────────────────────────────

    /// Authenticate the session.
    ///
    /// # Authentication methods
    ///
    /// | Variant | Mechanism | Pre-condition |
    /// |---------|-----------|---------------|
    /// | [`Auth::Simple`] | LDAP simple bind (DN + password) | `bind_dn` and `password` |
    /// | [`Auth::Gssapi`] | SASL GSSAPI (Kerberos) | valid TGT in the credential cache |
    pub fn bind(&mut self, auth: &Auth) -> Result<(), LdapError> {
        match auth {
            Auth::Simple { bind_dn, password } => {
                tracing::trace!(bind_dn, "LDAP simple bind");
                self.bind_simple(bind_dn, password.as_ref())
            }
            Auth::Gssapi => {
                debug!("LDAP GSSAPI bind");
                self.bind_gssapi()
            }
        }
    }

    fn bind_simple(&mut self, bind_dn: &str, password: &[u8]) -> Result<(), LdapError> {
        let dn_c = cstr(bind_dn)?;
        let pw_bytes = password;
        let mut pw_bv = berval {
            bv_len: pw_bytes.len() as ffi::ber_len_t,
            bv_val: pw_bytes.as_ptr() as *mut c_char,
        };
        let mut msgid: c_int = -1;
        // SAFETY: self.ld is non-null; dn_c and pw_bv are valid for this call; null mechanism pointer selects simple bind per the OpenLDAP API contract.
        let rc = unsafe {
            ffi::ldap_sasl_bind(
                self.ld,
                dn_c.as_ptr(),
                ptr::null(), // mechanism = NULL → simple bind
                &raw mut pw_bv,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut msgid,
            )
        };
        check(rc, "ldap_sasl_bind (simple)")?;
        self.collect_result(msgid, "simple bind")
    }

    /// Authenticate using GSSAPI with an S4U2Self impersonated credential.
    ///
    /// The credential is passed through the SASL interact callback's `defaults`
    /// parameter.  Cyrus SASL's GSSAPI plugin requests the AUTHZID via
    /// `SASL_INTERACT` *before* calling `gss_init_sec_context`, giving the
    /// callback a window to inject the credential via
    /// `LDAP_OPT_X_SASL_GSS_CREDS` (which calls `sasl_setprop` on the
    /// now-existing SASL context).
    ///
    /// Uses the `GSSAPI` SASL mechanism (not `GSS-SPNEGO`) because the SPNEGO
    /// mechglue calls `gssint_get_mechanism_cred` to extract the krb5
    /// sub-credential from the union handle — this fails silently for
    /// gssproxy/proxymech credential handles (non-standard structure), causing
    /// SPNEGO to fall back to the default service credential.  With `GSSAPI`,
    /// the interposer receives the proxymech handle directly and forwards it
    /// to the gssproxy daemon, which performs S4U2Proxy.
    pub fn bind_with_s4u_cred(
        &mut self,
        cred: &kuipa_gssapi::GssClientCred,
    ) -> Result<(), LdapError> {
        debug!("binding with S4U credential via SASL callback injection");
        self.bind_gssapi_impl(c"GSSAPI", cred.as_ptr())
    }

    fn bind_gssapi(&mut self) -> Result<(), LdapError> {
        self.bind_gssapi_impl(c"GSS-SPNEGO", ptr::null_mut())
    }

    /// Common SASL bind loop.
    ///
    /// `defaults` is passed through to the `sasl_interact_gssapi` callback.
    /// When non-null it is treated as a `gss_cred_id_t` to inject via
    /// `LDAP_OPT_X_SASL_GSS_CREDS`.
    fn bind_gssapi_impl(
        &mut self,
        mech: &std::ffi::CStr,
        defaults: *mut c_void,
    ) -> Result<(), LdapError> {
        debug!(mech = %mech.to_string_lossy(), "SASL bind starting");

        let mut result: *mut ffi::LDAPMessage = ptr::null_mut();
        let mut rmech: *const c_char = ptr::null();
        let mut iterations: u32 = 0;
        const MAX_SASL_ROUNDS: u32 = 10;
        loop {
            if iterations >= MAX_SASL_ROUNDS {
                if !result.is_null() {
                    // SAFETY: result is null-checked immediately above; it was obtained from ldap_result and has not yet been freed.
                    unsafe { ffi::ldap_msgfree(result) };
                }
                return Err(LdapError::Protocol {
                    code: -1,
                    msg: format!("GSSAPI SASL bind exceeded {MAX_SASL_ROUNDS} rounds; aborting"),
                });
            }
            iterations += 1;
            let mut msgid: c_int = -1;
            // SAFETY: self.ld is non-null; c"" is a valid static NUL-terminated
            // string; mech points to a valid CStr; result is either null (first
            // call) or a valid partial LDAPMessage* from ldap_result;
            // sasl_interact_gssapi satisfies the callback signature; defaults is
            // either null or a valid gss_cred_id_t pointer whose lifetime exceeds
            // this call.
            let rc = unsafe {
                ffi::ldap_sasl_interactive_bind(
                    self.ld,
                    c"".as_ptr(),
                    mech.as_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ffi::LDAP_SASL_QUIET,
                    Some(sasl_interact_gssapi),
                    defaults,
                    result, // NULL on first call; partial result on subsequent calls
                    &raw mut rmech,
                    &raw mut msgid,
                )
            };
            // Free the previous partial result, if any.
            if !result.is_null() {
                // SAFETY: result is null-checked immediately above; it was obtained from ldap_result and ownership passes to ldap_msgfree here.
                unsafe { ffi::ldap_msgfree(result) };
                result = ptr::null_mut();
            }
            if rc == ffi::LDAP_SUCCESS {
                return Ok(());
            }
            if rc != ffi::LDAP_SASL_BIND_IN_PROGRESS {
                return check(rc, "GSSAPI bind");
            }
            // More round-trips needed; collect the partial response.
            // SAFETY: self.ld is non-null; msgid is the value written by ldap_sasl_interactive_bind above; null timeout blocks until a result arrives.
            let rc2 = unsafe {
                ffi::ldap_result(
                    self.ld,
                    msgid,
                    ffi::LDAP_MSG_ALL,
                    ptr::null_mut(), // block until result arrives
                    &raw mut result,
                )
            };
            if rc2 <= 0 {
                if !result.is_null() {
                    // SAFETY: result is null-checked immediately above; it was obtained from ldap_result on error and has not yet been freed.
                    unsafe { ffi::ldap_msgfree(result) };
                }
                return Err(LdapError::Protocol {
                    code: rc2,
                    msg: "ldap_result during GSSAPI exchange failed".into(),
                });
            }
        }
    }

    /// Wait (blocking) for the result of a previously sent request identified
    /// by `msgid`, then assert it succeeded at both the transport and protocol
    /// level.
    ///
    /// `ldap_result` returns the message *type* (> 0) on success, 0 on timeout
    /// or connection drop, and < 0 on error.  The protocol-level result code
    /// (e.g. `LDAP_INVALID_CREDENTIALS`) is embedded in the message body and
    /// must be extracted with `ldap_parse_result` before the message is freed.
    fn collect_result(&mut self, msgid: c_int, context: &str) -> Result<(), LdapError> {
        let mut res: *mut ffi::LDAPMessage = ptr::null_mut();
        // SAFETY: self.ld is non-null; msgid was obtained from a preceding ldap_sasl_bind call; null timeout blocks until a result arrives.
        let rc = unsafe {
            ffi::ldap_result(
                self.ld,
                msgid,
                ffi::LDAP_MSG_ALL,
                ptr::null_mut(), // NULL timeout → block until result arrives
                &raw mut res,
            )
        };
        if rc <= 0 {
            // rc == 0: timeout / connection dropped; rc < 0: local error.
            if !res.is_null() {
                // SAFETY: res is null-checked immediately above; it was written by ldap_result and has not yet been freed.
                unsafe { ffi::ldap_msgfree(res) };
            }
            return Err(LdapError::Protocol {
                code: rc,
                msg: format!("ldap_result for {context} failed"),
            });
        }
        // Extract the LDAP protocol result code from the message body.
        // freeit=1: ldap_parse_result takes ownership of `res` and frees it.
        let mut errcode: c_int = ffi::LDAP_SUCCESS;
        // SAFETY: self.ld is non-null; res is a valid LDAPMessage* from ldap_result (rc > 0 checked above); freeit=1 transfers ownership of res to ldap_parse_result.
        let parse_rc = unsafe {
            ffi::ldap_parse_result(
                self.ld,
                res,
                &raw mut errcode,
                ptr::null_mut(), // matcheddnp — not needed
                ptr::null_mut(), // diagmsgp  — not needed
                ptr::null_mut(), // referralsp — not needed
                ptr::null_mut(), // serverctrls — not needed
                1,               // freeit: ldap_parse_result frees `res`
            )
        };
        if parse_rc != ffi::LDAP_SUCCESS {
            return Err(LdapError::Protocol {
                code: parse_rc,
                msg: format!(
                    "{context}: ldap_parse_result failed: {}",
                    err_string(parse_rc)
                ),
            });
        }
        if errcode != ffi::LDAP_SUCCESS {
            return Err(LdapError::Protocol {
                code: errcode,
                msg: format!("{context}: {}", err_string(errcode)),
            });
        }
        Ok(())
    }

    // ── Extended operations ───────────────────────────────────────────────────

    /// Perform an extended operation (RFC 4511 §4.12) and return its response
    /// value and the response controls.
    ///
    /// FreeIPA's `KEYTAB_GET` operation returns its reply in a response
    /// control rather than in the response value, so both are returned.
    pub fn extended_operation(
        &mut self,
        oid: &str,
        value: Option<&[u8]>,
    ) -> Result<ExtendedResult, LdapError> {
        let oid_c = cstr(oid)?;
        let mut req_bv = value.map(|v| ffi::berval {
            bv_len: v.len() as ffi::ber_len_t,
            bv_val: v.as_ptr() as *mut c_char,
        });
        let req_ptr = req_bv
            .as_mut()
            .map_or(ptr::null_mut(), |bv| bv as *mut ffi::berval);
        let mut msgid: c_int = -1;
        // SAFETY: self.ld is non-null; oid_c and the request berval (pointing
        // into `value`) outlive the call, which copies them into the request.
        let rc = unsafe {
            ffi::ldap_extended_operation(
                self.ld,
                oid_c.as_ptr(),
                req_ptr,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut msgid,
            )
        };
        check(rc, "ldap_extended_operation")?;

        let mut res: *mut ffi::LDAPMessage = ptr::null_mut();
        // SAFETY: self.ld is non-null; msgid comes from the call above; a null
        // timeout blocks until the result arrives.
        let rc = unsafe {
            ffi::ldap_result(
                self.ld,
                msgid,
                ffi::LDAP_MSG_ALL,
                ptr::null_mut(),
                &raw mut res,
            )
        };
        if rc <= 0 {
            if !res.is_null() {
                // SAFETY: res was written by ldap_result and not yet freed.
                unsafe { ffi::ldap_msgfree(res) };
            }
            return Err(LdapError::Protocol {
                code: rc,
                msg: "ldap_result for extended operation failed".into(),
            });
        }

        let mut retoid: *mut c_char = ptr::null_mut();
        let mut retdata: *mut ffi::berval = ptr::null_mut();
        // SAFETY: res is a valid result message; freeit=0 keeps it for the
        // ldap_parse_result call below.
        let rc = unsafe {
            ffi::ldap_parse_extended_result(self.ld, res, &raw mut retoid, &raw mut retdata, 0)
        };
        // SAFETY: retoid/retdata are either null or allocated by libldap;
        // they are copied and then freed exactly once.
        let (response_oid, response_value) = unsafe {
            let oid =
                (!retoid.is_null()).then(|| CStr::from_ptr(retoid).to_string_lossy().into_owned());
            let value = (!retdata.is_null()).then(|| berval_bytes(&*retdata));
            if !retoid.is_null() {
                ffi::ldap_memfree(retoid.cast());
            }
            if !retdata.is_null() {
                ffi::ber_bvfree(retdata);
            }
            (oid, value)
        };
        if rc != ffi::LDAP_SUCCESS {
            // SAFETY: res is still owned by us.
            unsafe { ffi::ldap_msgfree(res) };
            return Err(LdapError::Protocol {
                code: rc,
                msg: format!("ldap_parse_extended_result: {}", err_string(rc)),
            });
        }

        let mut errcode: c_int = ffi::LDAP_SUCCESS;
        let mut diag: *mut c_char = ptr::null_mut();
        let mut ctrls: *mut *mut ffi::LDAPControl = ptr::null_mut();
        // SAFETY: res is valid; freeit=1 transfers ownership of res.
        let parse_rc = unsafe {
            ffi::ldap_parse_result(
                self.ld,
                res,
                &raw mut errcode,
                ptr::null_mut(),
                &raw mut diag,
                ptr::null_mut(),
                &raw mut ctrls,
                1,
            )
        };
        // SAFETY: diag and ctrls are null or allocated by libldap; copied
        // and freed exactly once.
        let (diagnostic, controls) = unsafe {
            let d = (!diag.is_null()).then(|| CStr::from_ptr(diag).to_string_lossy().into_owned());
            if !diag.is_null() {
                ffi::ldap_memfree(diag.cast());
            }
            let mut out = Vec::new();
            if !ctrls.is_null() {
                let mut i = 0;
                while !(*ctrls.add(i)).is_null() {
                    let c = &**ctrls.add(i);
                    let oid = CStr::from_ptr(c.ldctl_oid).to_string_lossy().into_owned();
                    out.push((oid, berval_bytes(&c.ldctl_value)));
                    i += 1;
                }
                ffi::ldap_controls_free(ctrls);
            }
            (d, out)
        };
        if parse_rc != ffi::LDAP_SUCCESS {
            return Err(LdapError::Protocol {
                code: parse_rc,
                msg: format!("ldap_parse_result: {}", err_string(parse_rc)),
            });
        }
        if errcode != ffi::LDAP_SUCCESS {
            return Err(LdapError::Protocol {
                code: errcode,
                msg: format!(
                    "extended operation {oid}: {}{}",
                    err_string(errcode),
                    diagnostic.map(|d| format!(" ({d})")).unwrap_or_default()
                ),
            });
        }
        Ok(ExtendedResult {
            oid: response_oid,
            value: response_value,
            controls,
        })
    }

    // ── Search ────────────────────────────────────────────────────────────────

    /// Perform a synchronous LDAP search.
    ///
    /// Returns one [`SearchEntry`] per result entry, each containing every
    /// requested attribute decoded as both UTF-8 strings and raw bytes (for
    /// binary attributes like `certProfileConfig`).
    ///
    /// # Arguments
    ///
    /// * `base`   — Base DN for the search.
    /// * `scope`  — [`Scope::Base`], [`Scope::OneLevel`], or [`Scope::Subtree`].
    /// * `filter` — RFC 4515 filter string, e.g. `"(objectClass=certProfile)"`.
    /// * `attrs`  — Attribute names to retrieve.  An empty slice requests all
    ///   attributes.
    pub fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, LdapError> {
        debug!(base, ?scope, filter, "LDAP search");

        let base_c = cstr(base)?;
        let filter_c = cstr(filter)?;

        // Build a NULL-terminated *mut *mut c_char array for the attribute list.
        let attr_cstrings: Vec<CString> =
            attrs.iter().map(|a| cstr(a)).collect::<Result<_, _>>()?;
        let mut attr_ptrs: Vec<*mut c_char> = attr_cstrings
            .iter()
            .map(|s| s.as_ptr().cast_mut())
            .collect();
        attr_ptrs.push(ptr::null_mut()); // NULL sentinel

        let attrs_arg = if attrs.is_empty() {
            ptr::null_mut()
        } else {
            attr_ptrs.as_mut_ptr()
        };

        let mut msgid: c_int = -1;
        // SAFETY: self.ld is non-null; base_c and filter_c are valid NUL-terminated C strings; attrs_arg is either null (all attrs) or a null-terminated *mut *mut c_char array that remains valid for the duration of this call.
        let rc = unsafe {
            ffi::ldap_search_ext(
                self.ld,
                base_c.as_ptr(),
                scope.as_int(),
                filter_c.as_ptr(),
                attrs_arg,
                0, // attrsonly = false
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(), // no timeout
                0,               // no size limit
                &raw mut msgid,
            )
        };
        check(rc, "ldap_search_ext")?;

        let mut res: *mut ffi::LDAPMessage = ptr::null_mut();
        // SAFETY: self.ld is non-null; msgid was obtained from ldap_search_ext above; null timeout blocks until the complete result chain arrives.
        let rc = unsafe {
            ffi::ldap_result(
                self.ld,
                msgid,
                ffi::LDAP_MSG_ALL,
                ptr::null_mut(), // block until complete result arrives
                &raw mut res,
            )
        };
        if rc <= 0 {
            if !res.is_null() {
                // SAFETY: res is null-checked immediately above; it was written by ldap_result and has not yet been freed.
                unsafe { ffi::ldap_msgfree(res) };
            }
            return Err(LdapError::Protocol {
                code: rc,
                msg: "ldap_result for search failed".into(),
            });
        }

        // `res` now owns the result chain; walk it and build SearchEntry values.
        // SAFETY: self.ld is non-null; res is a valid result chain from ldap_result (rc > 0 checked above); collect_entries requires the caller to free res afterwards.
        let entries = unsafe { collect_entries(self.ld, res) };
        // Free the entire result chain.
        // SAFETY: res is a valid LDAPMessage* returned by ldap_result; collect_entries does not free it (per its contract), so this is the single owner freeing it.
        unsafe { ffi::ldap_msgfree(res) };
        entries
    }

    // ── Modify ────────────────────────────────────────────────────────────────

    /// Perform a synchronous LDAP modify operation on the entry at `dn`.
    ///
    /// Each element of `mods` is `(op, attr_name, values)`.  Use
    /// [`ModOp::Add`] to append values or [`ModOp::Delete`] to remove them.
    /// Passing an empty `values` vec with `Delete` removes the entire attribute.
    ///
    /// All allocations needed by libldap are on the stack for the duration of
    /// the call; nothing escapes.
    pub fn modify_s(
        &mut self,
        dn: &str,
        mods: &[(ModOp, &str, Vec<&[u8]>)],
    ) -> Result<(), LdapError> {
        let dn_c = cstr(dn)?;

        // For each modification we need:
        //   - CString for the attribute name
        //   - Vec<berval> for the values (pointers into the caller's slices)
        //   - Vec<*mut berval> (NULL-terminated) pointing into the berval vec
        //   - ffi::LDAPMod tying the above together
        //
        // All these live on the stack and must outlive the ldap_modify_ext_s call.
        // We build them separately so we can take pointers into them safely.
        let mut attr_cstrings: Vec<CString> = Vec::with_capacity(mods.len());
        let mut berval_vecs: Vec<Vec<ffi::berval>> = Vec::with_capacity(mods.len());
        let mut bvptr_vecs: Vec<Vec<*mut ffi::berval>> = Vec::with_capacity(mods.len());
        let mut ldap_mods: Vec<ffi::LDAPMod> = Vec::with_capacity(mods.len());

        for (_op, attr, values) in mods {
            attr_cstrings.push(cstr(attr)?);
            let bvs: Vec<ffi::berval> = values
                .iter()
                .map(|v| ffi::berval {
                    bv_len: v.len() as ffi::ber_len_t,
                    bv_val: v.as_ptr() as *mut c_char,
                })
                .collect();
            berval_vecs.push(bvs);
        }

        // Build pointer-to-berval vecs now that berval_vecs is fully populated
        // (and won't be reallocated).
        for bvs in &mut berval_vecs {
            let mut ptrs: Vec<*mut ffi::berval> = bvs.iter_mut().map(|b| b as *mut _).collect();
            ptrs.push(ptr::null_mut()); // NULL sentinel
            bvptr_vecs.push(ptrs);
        }

        // Build LDAPMod array, referencing into attr_cstrings and bvptr_vecs.
        // This must happen after all Vec pushes so pointers are stable.
        for (i, (op, _attr, _values)) in mods.iter().enumerate() {
            ldap_mods.push(ffi::LDAPMod {
                mod_op: op.as_int() | ffi::LDAP_MOD_BVALUES,
                mod_type: attr_cstrings[i].as_ptr().cast_mut(),
                mod_vals: bvptr_vecs[i].as_mut_ptr(),
            });
        }

        // NULL-terminated array of *mut LDAPMod.
        let mut mod_ptrs: Vec<*mut ffi::LDAPMod> =
            ldap_mods.iter_mut().map(|m| m as *mut _).collect();
        mod_ptrs.push(ptr::null_mut());

        // SAFETY: self.ld is non-null; dn_c is a valid NUL-terminated C string;
        // mod_ptrs is a NULL-terminated array of valid LDAPMod pointers; all
        // backing allocations (attr_cstrings, berval_vecs, bvptr_vecs, ldap_mods)
        // remain on the stack and live until after ldap_modify_ext_s returns.
        let rc = unsafe {
            ffi::ldap_modify_ext_s(
                self.ld,
                dn_c.as_ptr(),
                mod_ptrs.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        check(rc, "ldap_modify_ext_s")
    }
    /// LDAP simple bind that also sends the `OTP_REQUIRED_OID` client control.
    ///
    /// FreeIPA's `ipa-pwd-extop` plugin checks for this control and rejects the
    /// bind if the password does not contain a valid OTP code suffix, even when
    /// the password alone would be accepted.
    ///
    /// `credential` must be the concatenated `password+otp_code` string; the
    /// caller is responsible for zeroing it after this call returns.
    pub fn bind_simple_otp_required(
        &mut self,
        bind_dn: &str,
        credential: &str,
    ) -> Result<(), LdapError> {
        const OTP_REQUIRED_OID: &std::ffi::CStr = c"2.16.840.1.113730.3.8.10.7";

        let dn_c = cstr(bind_dn)?;
        let cred_bytes = credential.as_bytes();
        let mut cred_bv = ffi::berval {
            bv_len: cred_bytes.len() as ffi::ber_len_t,
            bv_val: cred_bytes.as_ptr() as *mut c_char,
        };
        let mut ctrl = ffi::LDAPControl {
            ldctl_oid: OTP_REQUIRED_OID.as_ptr().cast_mut(),
            ldctl_value: ffi::berval {
                bv_len: 0,
                bv_val: ptr::null_mut(),
            },
            ldctl_iscritical: 0,
        };
        let mut ctrl_list: [*mut ffi::LDAPControl; 2] = [&raw mut ctrl, ptr::null_mut()];
        let mut msgid: c_int = -1;
        // SAFETY: self.ld is non-null; dn_c, cred_bv, and ctrl live for the
        // duration of the call; OTP_REQUIRED_OID is a static C string.
        let rc = unsafe {
            ffi::ldap_sasl_bind(
                self.ld,
                dn_c.as_ptr(),
                ptr::null(),
                &raw mut cred_bv,
                ptr::null_mut(),
                ctrl_list.as_mut_ptr(),
                &raw mut msgid,
            )
        };
        check(rc, "ldap_sasl_bind (otp-required)")?;
        self.collect_result(msgid, "otp-required bind")
    }

    /// Add a new LDAP entry.
    ///
    /// `attrs` is a list of `(attr_name, values)` pairs.  All attributes are
    /// added with `LDAP_MOD_ADD | LDAP_MOD_BVALUES`, so values are binary-safe.
    pub fn add_s(&mut self, dn: &str, attrs: &[(&str, Vec<&[u8]>)]) -> Result<(), LdapError> {
        let dn_c = cstr(dn)?;

        let mut attr_cstrings: Vec<CString> = Vec::with_capacity(attrs.len());
        let mut berval_vecs: Vec<Vec<ffi::berval>> = Vec::with_capacity(attrs.len());
        let mut bvptr_vecs: Vec<Vec<*mut ffi::berval>> = Vec::with_capacity(attrs.len());
        let mut ldap_mods: Vec<ffi::LDAPMod> = Vec::with_capacity(attrs.len());

        for (_attr, values) in attrs {
            let bvs: Vec<ffi::berval> = values
                .iter()
                .map(|v| ffi::berval {
                    bv_len: v.len() as ffi::ber_len_t,
                    bv_val: v.as_ptr() as *mut c_char,
                })
                .collect();
            berval_vecs.push(bvs);
        }

        for (attr, _values) in attrs {
            attr_cstrings.push(cstr(attr)?);
        }

        for bvs in &mut berval_vecs {
            let mut ptrs: Vec<*mut ffi::berval> = bvs.iter_mut().map(|b| b as *mut _).collect();
            ptrs.push(ptr::null_mut());
            bvptr_vecs.push(ptrs);
        }

        for (i, _) in attrs.iter().enumerate() {
            ldap_mods.push(ffi::LDAPMod {
                mod_op: ffi::LDAP_MOD_ADD | ffi::LDAP_MOD_BVALUES,
                mod_type: attr_cstrings[i].as_ptr().cast_mut(),
                mod_vals: bvptr_vecs[i].as_mut_ptr(),
            });
        }

        let mut mod_ptrs: Vec<*mut ffi::LDAPMod> =
            ldap_mods.iter_mut().map(|m| m as *mut _).collect();
        mod_ptrs.push(ptr::null_mut());

        // SAFETY: self.ld is non-null; all backing allocations remain valid for
        // the duration of the ldap_add_ext_s call.
        let rc = unsafe {
            ffi::ldap_add_ext_s(
                self.ld,
                dn_c.as_ptr(),
                mod_ptrs.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        check(rc, "ldap_add_ext_s")
    }

    /// Query the LDAP rootDSE for the server's primary naming context.
    ///
    /// Prefers `defaultNamingContext` (set by FreeIPA / Active Directory) and falls
    /// back to the first value of `namingContexts`.  Does not require a prior bind
    /// (rootDSE is publicly readable in standard LDAP deployments).
    ///
    /// Returns `Ok(Some(suffix))` on success, `Ok(None)` when the server does not
    /// advertise a naming context, and `Err` on connection/protocol failures.
    pub fn fetch_naming_context(&mut self) -> Result<Option<String>, LdapError> {
        let entries = self.search(
            "",
            Scope::Base,
            "(objectClass=*)",
            &["defaultNamingContext", "namingContexts"],
        )?;
        Ok(entries.into_iter().next().and_then(|e| {
            e.attrs
                .get("defaultnamingcontext")
                .or_else(|| e.attrs.get("namingcontexts"))
                .and_then(|v| v.first())
                .cloned()
        }))
    }

    /// Delete an existing LDAP entry by DN.
    pub fn delete_s(&mut self, dn: &str) -> Result<(), LdapError> {
        let dn_c = cstr(dn)?;
        // SAFETY: self.ld is non-null; dn_c is a valid NUL-terminated string
        // that outlives the call.
        let rc = unsafe {
            ffi::ldap_delete_ext_s(self.ld, dn_c.as_ptr(), ptr::null_mut(), ptr::null_mut())
        };
        check(rc, "ldap_delete_ext_s")
    }
} // impl LdapConnection

// ── ModOp ─────────────────────────────────────────────────────────────────────

/// LDAP attribute modification operation used with [`LdapConnection::modify_s`].
#[derive(Debug, Clone, Copy)]
pub enum ModOp {
    /// Add one or more values to an attribute (creates the attribute if absent).
    Add,
    /// Delete specific values from an attribute, or remove the entire attribute
    /// if no values are supplied.
    Delete,
    /// Replace all values of an attribute (removes it when no values are
    /// supplied).
    Replace,
}

impl ModOp {
    fn as_int(self) -> libc::c_int {
        match self {
            ModOp::Add => ffi::LDAP_MOD_ADD,
            ModOp::Delete => ffi::LDAP_MOD_DELETE,
            ModOp::Replace => ffi::LDAP_MOD_REPLACE,
        }
    }
}

// ── SearchEntry ───────────────────────────────────────────────────────────────

/// One LDAP entry returned from a search.
#[derive(Debug, Default)]
pub struct SearchEntry {
    /// DN of the entry.
    pub dn: String,
    /// Attribute values decoded as UTF-8 strings (best-effort).
    ///
    /// Keys are lower-cased attribute names; values are lists of strings.
    /// Attributes whose values are not valid UTF-8 appear here with
    /// replacement characters; use [`bin_attrs`][Self::bin_attrs] for
    /// reliable binary access.
    pub attrs: HashMap<String, Vec<String>>,
    /// Raw binary attribute values.
    ///
    /// Keys are lower-cased attribute names; values are raw byte vectors.
    /// Always populated, even when [`attrs`][Self::attrs] contains the
    /// same value as valid UTF-8.
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Walk the libldap result chain and decode each entry's attributes.
///
/// # Safety
///
/// `res` must be a valid (possibly NULL) result chain from `ldap_search_ext_s`.
/// The caller must free `res` with `ldap_msgfree` after this function returns.
unsafe fn collect_entries(
    ld: *mut LDAP,
    res: *mut ffi::LDAPMessage,
) -> Result<Vec<SearchEntry>, LdapError> {
    let mut entries = Vec::new();
    let mut entry = ffi::ldap_first_entry(ld, res);
    while !entry.is_null() {
        entries.push(decode_entry(ld, entry)?);
        entry = ffi::ldap_next_entry(ld, entry);
    }
    Ok(entries)
}

/// Decode one LDAP entry into a [`SearchEntry`].
///
/// # Safety
///
/// `ld` and `entry` must be valid non-null pointers from `ldap_first/next_entry`.
/// The caller retains ownership of both; this function does not free them.
unsafe fn decode_entry(
    ld: *mut LDAP,
    entry: *mut ffi::LDAPMessage,
) -> Result<SearchEntry, LdapError> {
    let mut se = SearchEntry::default();

    // DN
    let dn_ptr = ffi::ldap_get_dn(ld, entry);
    if !dn_ptr.is_null() {
        se.dn = CStr::from_ptr(dn_ptr).to_string_lossy().into_owned();
        ffi::ldap_memfree(dn_ptr.cast::<c_void>());
    }

    // Attribute iteration
    let mut ber: *mut BerElement = ptr::null_mut();
    let mut attr_ptr = ffi::ldap_first_attribute(ld, entry, &raw mut ber);
    while !attr_ptr.is_null() {
        let attr_name = CStr::from_ptr(attr_ptr)
            .to_string_lossy()
            .to_ascii_lowercase();

        let vals_ptr = ffi::ldap_get_values_len(ld, entry, attr_ptr);
        if !vals_ptr.is_null() {
            let (str_vals, bin_vals) = decode_bervals(vals_ptr);
            se.attrs
                .entry(attr_name.clone())
                .or_default()
                .extend(str_vals);
            se.bin_attrs.entry(attr_name).or_default().extend(bin_vals);
            ffi::ldap_value_free_len(vals_ptr);
        }

        ffi::ldap_memfree(attr_ptr.cast::<c_void>());
        attr_ptr = ffi::ldap_next_attribute(ld, entry, ber);
    }
    if !ber.is_null() {
        ffi::ber_free(ber, 0);
    }

    Ok(se)
}

/// Decode a NULL-terminated `berval**` into parallel string and byte vectors.
///
/// # Safety
///
/// `vals_ptr` must be a valid non-null pointer returned by `ldap_get_values_len`.
/// The caller must free it with `ldap_value_free_len` after this function returns.
unsafe fn decode_bervals(vals_ptr: *mut *mut berval) -> (Vec<String>, Vec<Vec<u8>>) {
    let mut str_vals = Vec::new();
    let mut bin_vals = Vec::new();
    let mut i = 0usize;
    loop {
        let bv = *vals_ptr.add(i);
        if bv.is_null() {
            break;
        }
        // SAFETY: bv_val is null or points to bv_len readable bytes; the
        // null case yields an empty slice rather than UB, as in
        // `berval_bytes`.
        let bytes = if (*bv).bv_val.is_null() {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts((*bv).bv_val as *const u8, (*bv).bv_len as usize) }
        };
        bin_vals.push(bytes.to_vec());
        str_vals.push(String::from_utf8_lossy(bytes).into_owned());
        i += 1;
    }
    (str_vals, bin_vals)
}

/// Convert an `&str` to a `CString`, mapping interior-NUL errors to `LdapError`.
pub(crate) fn cstr(s: &str) -> Result<CString, LdapError> {
    CString::new(s).map_err(|e: NulError| LdapError::NulByte(e.to_string()))
}

/// Convert an LDAP result code to an owned error message string.
fn err_string(code: c_int) -> String {
    // SAFETY: ldap_err2string returns a pointer to a static string (never null
    // for any input); the string is valid UTF-8 ASCII and has static lifetime.
    let ptr = unsafe { ffi::ldap_err2string(code) };
    if ptr.is_null() {
        return format!("code {code}");
    }
    // SAFETY: ptr is a non-null pointer to a NUL-terminated static string
    // returned by ldap_err2string; it remains valid for the lifetime of this call.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .unwrap_or("(invalid UTF-8)")
        .to_owned()
}

/// Return `Ok(())` if `rc` is `LDAP_SUCCESS`, otherwise map to `LdapError`.
fn check(rc: c_int, context: &str) -> Result<(), LdapError> {
    if rc == ffi::LDAP_SUCCESS {
        Ok(())
    } else {
        Err(LdapError::Protocol {
            code: rc,
            msg: format!("{context}: {}", err_string(rc)),
        })
    }
}

/// Copy the bytes of a libldap `berval`.
///
/// # Safety
///
/// `bv.bv_val` must point to `bv.bv_len` readable bytes, or be null.
unsafe fn berval_bytes(bv: &ffi::berval) -> Vec<u8> {
    if bv.bv_val.is_null() {
        return Vec::new();
    }
    // SAFETY: guaranteed by the caller.
    unsafe { std::slice::from_raw_parts(bv.bv_val as *const u8, bv.bv_len as usize).to_vec() }
}

/// The result of [`LdapConnection::extended_operation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedResult {
    /// Response name (OID), if the server sent one.
    pub oid: Option<String>,
    /// Response value, if the server sent one.
    pub value: Option<Vec<u8>>,
    /// Response controls as `(oid, value)`.
    pub controls: Vec<(String, Vec<u8>)>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scope;

    #[test]
    fn connect_to_nonexistent_host_returns_error() {
        // ldap_initialize merely parses the URI; the error surfaces on first I/O.
        // A search against a host that is not listening should fail quickly.
        let mut conn =
            LdapConnection::connect("ldap://127.0.0.1:38999", None, false, 5).expect("initialize");
        let err = conn
            .search("dc=test", Scope::Base, "(objectClass=*)", &[])
            .expect_err("search to closed port should fail");
        assert!(
            matches!(err, LdapError::Protocol { .. }),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn connect_with_nonexistent_ca_cert_returns_tls_error() {
        let err = LdapConnection::connect(
            "ldap://127.0.0.1:389",
            Some("/nonexistent/ca.pem"),
            false,
            5,
        )
        .expect_err("should fail on missing CA cert");
        assert!(
            matches!(err, LdapError::Tls(_)),
            "unexpected error variant: {err:?}"
        );
    }

    #[test]
    fn scope_as_int_values_match_rfc() {
        assert_eq!(Scope::Base.as_int(), 0);
        assert_eq!(Scope::OneLevel.as_int(), 1);
        assert_eq!(Scope::Subtree.as_int(), 2);
    }

    #[test]
    fn cstr_valid_string_roundtrips() {
        let c = cstr("uid=alice,dc=example,dc=com").expect("no NUL");
        assert_eq!(c.to_str().unwrap(), "uid=alice,dc=example,dc=com");
    }

    #[test]
    fn cstr_nul_byte_returns_nul_byte_error() {
        let err = cstr("hel\0lo").expect_err("NUL byte must be rejected");
        assert!(
            matches!(err, LdapError::NulByte(_)),
            "unexpected variant: {err:?}"
        );
    }

    #[test]
    fn ldap_error_display_protocol() {
        let e = LdapError::Protocol {
            code: 49,
            msg: "Invalid credentials".into(),
        };
        let s = e.to_string();
        assert!(s.contains("49"), "got: {s}");
        assert!(s.contains("Invalid credentials"), "got: {s}");
    }

    #[test]
    fn ldap_error_display_tls() {
        let e = LdapError::Tls("cert verify failed".into());
        assert!(e.to_string().contains("cert verify failed"));
    }

    #[test]
    fn ldap_error_display_nul_byte() {
        let e = LdapError::NulByte("interior NUL".into());
        assert!(e.to_string().contains("interior NUL"));
    }

    #[test]
    fn search_entry_default_is_empty() {
        let e = SearchEntry::default();
        assert!(e.dn.is_empty());
        assert!(e.attrs.is_empty());
        assert!(e.bin_attrs.is_empty());
    }
}
