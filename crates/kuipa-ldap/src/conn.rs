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
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::time::Duration;

use libc::{c_char, c_int, c_void, timeval};
use tracing::debug;

use crate::ffi::{self, BerElement, LDAP, berval};
use crate::{Auth, LdapError, NO_SUCH_OBJECT, Scope};

/// How [`LdapConnection::connect`] secures an `ldap://` connection.
#[derive(Debug, Clone, Copy)]
pub enum Tls<'a> {
    /// No TLS (`ldaps://` URIs still use it).
    Off,
    /// STARTTLS, verified against the system trust store.
    StartTls,
    /// STARTTLS, verified against the PEM CA file at this path.
    CaFile(&'a Path),
}

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
    if defaults.is_null() {
        tracing::trace!("sasl_interact: no credential (defaults is null)");
    } else {
        // SAFETY: libldap passes the live session `ld`; `defaults` is the
        // credential handle bind_gssapi_impl gave it, stored as-is.
        let rc = unsafe {
            ffi::ldap_set_option(ld, ffi::LDAP_OPT_X_SASL_GSS_CREDS, defaults.cast_const())
        };
        if rc != ffi::LDAP_SUCCESS {
            // Fail rather than continue with whatever identity the
            // process would otherwise use: the bind must not proceed as
            // the wrong principal.
            tracing::error!(rc, "ldap_set_option(LDAP_OPT_X_SASL_GSS_CREDS) failed");
            return rc;
        }
    }
    // SAFETY: libldap provides a non-null, properly aligned, SASL_CB_LIST_END-
    // terminated sasl_interact array for the lifetime of this callback. Advancing
    // by 1 element per iteration stays within the allocation until the sentinel.
    if interact_raw.is_null() {
        return ffi::LDAP_SUCCESS;
    }
    let mut interact = interact_raw.cast::<ffi::sasl_interact>();
    // SAFETY: as above.
    unsafe {
        while (*interact).id != ffi::SASL_CB_LIST_END {
            (*interact).result = c"".as_ptr().cast::<c_void>();
            (*interact).len = 0;
            interact = interact.add(1);
        }
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
    /// `tls` only matters for `ldap://` URIs: [`Tls::StartTls`] and
    /// [`Tls::CaFile`] negotiate STARTTLS before any credentials are sent
    /// (`CaFile` verifies the server against the PEM file, `StartTls` against
    /// the system trust store).  `ldaps://` URIs do the TLS handshake on
    /// connect whatever `tls` says.  For GSSAPI binds over plain `ldap://`
    /// pass [`Tls::Off`]: GSSAPI provides its own cryptographic protection.
    ///
    /// `timeout` sets both the TCP-level connect timeout and the default
    /// operation timeout (`LDAP_OPT_NETWORK_TIMEOUT` + `LDAP_OPT_TIMEOUT`);
    /// `None` leaves the OS default (no finite timeout).
    ///
    /// # Errors
    ///
    /// Returns [`LdapError::Protocol`] if `ldap_initialize` or protocol setup fails,
    /// [`LdapError::Tls`] if the CA file cannot be read or TLS/STARTTLS negotiation fails, and
    /// [`LdapError::NulByte`] if the CA file path has an interior NUL.
    pub fn connect(uri: &str, tls: Tls<'_>, timeout: Option<Duration>) -> Result<Self, LdapError> {
        let starttls = !matches!(tls, Tls::Off) && uri.starts_with("ldap://");
        debug!(uri, ?tls, starttls, "LDAP connect");

        let uri_c = CString::new(uri)?;
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
        if let Some(timeout) = timeout {
            let tv = timeval {
                tv_sec: libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX),
                tv_usec: timeout.subsec_micros().into(),
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

        if let Tls::CaFile(ca_path) = tls {
            let shown = ca_path.display();
            std::fs::metadata(ca_path)
                .map_err(|e| LdapError::Tls(format!("cannot read TLS CA cert '{shown}': {e}")))?;
            let path_c = CString::new(ca_path.as_os_str().as_bytes())?;
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
                    "ldap_set_option(CACERTFILE, '{shown}') failed"
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
    ///
    /// # Errors
    ///
    /// Every failure is reported as [`LdapError::Protocol`], either from
    /// the server-side bind result or from SASL mechanism negotiation.
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
        let dn_c = CString::new(bind_dn)?;
        let mut pw_bv = berval_of(password);
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
        let msg = self.wait(msgid, "simple bind")?;
        self.parse(&msg, "simple bind").map(drop)
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
    ///
    /// # Errors
    ///
    /// Returns [`LdapError::Protocol`] if the SASL bind loop exceeds
    /// `MAX_SASL_ROUNDS`, `ldap_result` fails mid-exchange, or the server
    /// rejects the bind.
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
        const MAX_SASL_ROUNDS: u32 = 10;
        debug!(mech = %mech.to_string_lossy(), "SASL bind starting");

        // The previous round's partial response; freed on drop each round.
        let mut result: Option<Message> = None;
        let mut rmech: *const c_char = ptr::null();
        for _ in 0..MAX_SASL_ROUNDS {
            let mut msgid: c_int = -1;
            // SAFETY: self.ld is non-null; c"" is a valid static NUL-terminated
            // string; mech points to a valid CStr; the result pointer is either
            // null (first call) or a valid partial LDAPMessage* from ldap_result;
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
                    result.as_ref().map_or(ptr::null_mut(), |m| m.0), // NULL on first call
                    &raw mut rmech,
                    &raw mut msgid,
                )
            };
            drop(result.take());
            if rc == ffi::LDAP_SUCCESS {
                return Ok(());
            }
            if rc != ffi::LDAP_SASL_BIND_IN_PROGRESS {
                return check(rc, "GSSAPI bind");
            }
            // More round-trips needed; collect the partial response.
            result = Some(self.wait(msgid, "GSSAPI exchange")?);
        }
        Err(LdapError::Protocol {
            code: -1,
            msg: format!("GSSAPI SASL bind exceeded {MAX_SASL_ROUNDS} rounds; aborting"),
        })
    }

    /// Block until the complete response to `msgid` arrives.
    ///
    /// `ldap_result` returns the message *type* (> 0) on success, 0 on timeout
    /// or connection drop, and < 0 on error.  The protocol-level result code
    /// (e.g. `LDAP_INVALID_CREDENTIALS`) is inside the message; [`Self::parse`]
    /// extracts it.
    fn wait(&self, msgid: c_int, context: &str) -> Result<Message, LdapError> {
        let mut res: *mut ffi::LDAPMessage = ptr::null_mut();
        // SAFETY: self.ld is non-null; msgid comes from a request just sent on
        // this connection; a null timeout blocks until the complete result arrives.
        let rc = unsafe {
            ffi::ldap_result(
                self.ld,
                msgid,
                ffi::LDAP_MSG_ALL,
                ptr::null_mut(),
                &raw mut res,
            )
        };
        // Wrapped before the check so a message written on error is freed too.
        let msg = Message(res);
        if rc <= 0 {
            return Err(LdapError::Protocol {
                code: rc,
                msg: format!("ldap_result for {context} failed"),
            });
        }
        Ok(msg)
    }

    /// Assert `msg` carries `LDAP_SUCCESS` and return its response controls.
    ///
    /// Borrows `msg` (`freeit = 0`) so a search result can still be walked.
    fn parse(&self, msg: &Message, context: &str) -> Result<Vec<(String, Vec<u8>)>, LdapError> {
        let mut errcode: c_int = ffi::LDAP_SUCCESS;
        let mut diag: *mut c_char = ptr::null_mut();
        let mut ctrls: *mut *mut ffi::LDAPControl = ptr::null_mut();
        // SAFETY: self.ld is non-null; msg.0 is a valid message from ldap_result.
        let parse_rc = unsafe {
            ffi::ldap_parse_result(
                self.ld,
                msg.0,
                &raw mut errcode,
                ptr::null_mut(),
                &raw mut diag,
                ptr::null_mut(),
                &raw mut ctrls,
                0,
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
                msg: format!(
                    "{context}: ldap_parse_result failed: {}",
                    err_string(parse_rc)
                ),
            });
        }
        if errcode != ffi::LDAP_SUCCESS {
            return Err(LdapError::Protocol {
                code: errcode,
                msg: format!(
                    "{context}: {}{}",
                    err_string(errcode),
                    diagnostic.map(|d| format!(" ({d})")).unwrap_or_default()
                ),
            });
        }
        Ok(controls)
    }

    // ── Extended operations ───────────────────────────────────────────────────

    /// Perform an extended operation (RFC 4511 §4.12) and return its response
    /// value and the response controls.
    ///
    /// FreeIPA's `KEYTAB_GET` operation returns its reply in a response
    /// control rather than in the response value, so both are returned.
    ///
    /// # Errors
    ///
    /// Returns [`LdapError::Protocol`] if the extended request is rejected,
    /// `ldap_result` times out, or the result code is not
    /// `LDAP_SUCCESS`; [`LdapError::NulByte`] if `oid` has an interior NUL.
    pub fn extended_operation(
        &mut self,
        oid: &str,
        value: Option<&[u8]>,
    ) -> Result<ExtendedResult, LdapError> {
        let oid_c = CString::new(oid)?;
        let mut req_bv = value.map(berval_of);
        let req_ptr = req_bv.as_mut().map_or(ptr::null_mut(), ptr::from_mut);
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
        let msg = self.wait(msgid, "extended operation")?;

        let mut retoid: *mut c_char = ptr::null_mut();
        let mut retdata: *mut ffi::berval = ptr::null_mut();
        // SAFETY: msg.0 is a valid result message; freeit=0 keeps it for
        // the parse below.
        let rc = unsafe {
            ffi::ldap_parse_extended_result(self.ld, msg.0, &raw mut retoid, &raw mut retdata, 0)
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
        check(rc, "ldap_parse_extended_result")?;

        let controls = self.parse(&msg, &format!("extended operation {oid}"))?;
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
    ///
    /// # Errors
    ///
    /// Returns [`LdapError::Protocol`] if the search request or result
    /// retrieval fails, or the server's result code is not success (for
    /// example [`NO_SUCH_OBJECT`] when `base` is absent);
    /// [`LdapError::NulByte`] if `base`, `filter`, or any entry of `attrs`
    /// has an interior NUL.
    pub fn search(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, LdapError> {
        debug!(base, ?scope, filter, "LDAP search");

        let base_c = CString::new(base)?;
        let filter_c = CString::new(filter)?;

        // Build a NULL-terminated *mut *mut c_char array for the attribute list.
        let attr_cstrings: Vec<CString> = attrs
            .iter()
            .map(|a| CString::new(*a))
            .collect::<Result<_, _>>()?;
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

        let msg = self.wait(msgid, "search")?;
        self.parse(&msg, "search")?;
        // SAFETY: self.ld is non-null; msg.0 is a valid result chain that
        // outlives the call; collect_entries does not free it.
        Ok(unsafe { collect_entries(self.ld, msg.0) })
    }

    /// [`search`](Self::search), but an absent `base` ([`NO_SUCH_OBJECT`])
    /// yields no entries instead of an error.
    ///
    /// # Errors
    ///
    /// As [`search`](Self::search), except [`NO_SUCH_OBJECT`].
    pub fn search_if_exists(
        &mut self,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>, LdapError> {
        match self.search(base, scope, filter, attrs) {
            Err(e) if e.code() == Some(NO_SUCH_OBJECT) => Ok(Vec::new()),
            r => r,
        }
    }

    // ── Modify ────────────────────────────────────────────────────────────────

    /// Perform a synchronous LDAP modify operation on the entry at `dn`.
    ///
    /// # Errors
    ///
    /// Returns [`LdapError::Protocol`] if the server rejects the modify;
    /// [`LdapError::NulByte`] if `dn` or any attribute name has an interior
    /// NUL.
    pub fn modify_s(&mut self, dn: &str, mods: &[Mod<'_>]) -> Result<(), LdapError> {
        let dn_c = CString::new(dn)?;
        let mut mods = Mods::new(mods.iter().map(|m| (m.op.as_int(), m.attr, &m.values[..])))?;
        // SAFETY: self.ld is non-null; dn_c is a valid NUL-terminated C string;
        // mods.ptrs is a NULL-terminated array of LDAPMod pointers whose backing
        // storage `mods` owns until after the call returns.
        let rc = unsafe {
            ffi::ldap_modify_ext_s(
                self.ld,
                dn_c.as_ptr(),
                mods.ptrs.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        check(rc, "ldap_modify_ext_s")
    }

    /// Add a new LDAP entry with the given attributes (binary-safe values);
    /// each `attrs` item's `op` is ignored, build them with [`Mod::add`].
    ///
    /// # Errors
    ///
    /// Returns [`LdapError::Protocol`] if the server rejects the add;
    /// [`LdapError::NulByte`] if `dn` or any attribute name has an interior
    /// NUL.
    pub fn add_s(&mut self, dn: &str, attrs: &[Mod<'_>]) -> Result<(), LdapError> {
        let dn_c = CString::new(dn)?;
        let mut mods = Mods::new(
            attrs
                .iter()
                .map(|m| (ffi::LDAP_MOD_ADD, m.attr, &m.values[..])),
        )?;
        // SAFETY: as in `modify_s`.
        let rc = unsafe {
            ffi::ldap_add_ext_s(
                self.ld,
                dn_c.as_ptr(),
                mods.ptrs.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        check(rc, "ldap_add_ext_s")
    }

    /// Delete an existing LDAP entry by DN.
    ///
    /// # Errors
    ///
    /// Returns [`LdapError::Protocol`] if the server rejects the delete
    /// (including `NO_SUCH_OBJECT`); [`LdapError::NulByte`] if `dn` has an
    /// interior NUL.
    pub fn delete_s(&mut self, dn: &str) -> Result<(), LdapError> {
        let dn_c = CString::new(dn)?;
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

/// One change in [`LdapConnection::modify_s`], or one attribute of
/// [`LdapConnection::add_s`] (built with [`Mod::add`]).
#[derive(Debug, Clone)]
pub struct Mod<'a> {
    /// What to do with the values.
    pub op: ModOp,
    /// Attribute name.
    pub attr: &'a str,
    /// Values; with [`ModOp::Delete`] none removes the whole attribute.
    pub values: Vec<&'a [u8]>,
}

impl<'a> Mod<'a> {
    /// Add `values` to `attr`.
    pub fn add<T: AsRef<[u8]> + ?Sized + 'a>(
        attr: &'a str,
        values: impl IntoIterator<Item = &'a T>,
    ) -> Self {
        Self::new(ModOp::Add, attr, values)
    }

    /// Delete `values` from `attr`.
    pub fn delete<T: AsRef<[u8]> + ?Sized + 'a>(
        attr: &'a str,
        values: impl IntoIterator<Item = &'a T>,
    ) -> Self {
        Self::new(ModOp::Delete, attr, values)
    }

    /// Replace all values of `attr` with `values`.
    pub fn replace<T: AsRef<[u8]> + ?Sized + 'a>(
        attr: &'a str,
        values: impl IntoIterator<Item = &'a T>,
    ) -> Self {
        Self::new(ModOp::Replace, attr, values)
    }

    /// Remove `attr` altogether.
    #[must_use]
    pub fn remove(attr: &'a str) -> Self {
        Self {
            op: ModOp::Delete,
            attr,
            values: Vec::new(),
        }
    }

    fn new<T: AsRef<[u8]> + ?Sized + 'a>(
        op: ModOp,
        attr: &'a str,
        values: impl IntoIterator<Item = &'a T>,
    ) -> Self {
        Self {
            op,
            attr,
            values: values.into_iter().map(AsRef::as_ref).collect(),
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

impl SearchEntry {
    /// The values of `attr` (any case); empty when the entry has none.
    #[must_use]
    pub fn values(&self, attr: &str) -> &[String] {
        self.attrs
            .get(&attr.to_ascii_lowercase())
            .map_or(&[], Vec::as_slice)
    }

    /// The first value of `attr` (any case).
    #[must_use]
    pub fn first(&self, attr: &str) -> Option<&str> {
        self.values(attr).first().map(String::as_str)
    }

    /// Whether the entry has `attr` (any case), whatever its values.
    #[must_use]
    pub fn has(&self, attr: &str) -> bool {
        self.bin_attrs.contains_key(&attr.to_ascii_lowercase())
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// An owned `LDAPMessage` chain, freed with `ldap_msgfree` on drop.
struct Message(*mut ffi::LDAPMessage);

impl Drop for Message {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 came from ldap_result and is owned by this wrapper.
            unsafe { ffi::ldap_msgfree(self.0) };
        }
    }
}

/// Borrow `v` as a `berval`; libldap only reads through it.
fn berval_of(v: &[u8]) -> berval {
    berval {
        bv_len: v.len() as ffi::ber_len_t,
        bv_val: v.as_ptr().cast_mut().cast(),
    }
}

/// A NULL-terminated `LDAPMod *` array for `ldap_add_ext_s`/`ldap_modify_ext_s`,
/// with the storage the pointers refer to.
struct Mods {
    /// Points into the fields below, which are never touched after `new`.
    ptrs: Vec<*mut ffi::LDAPMod>,
    _entries: Vec<ffi::LDAPMod>,
    _bvptrs: Vec<Vec<*mut berval>>,
    _bvals: Vec<Vec<berval>>,
    _names: Vec<CString>,
}

impl Mods {
    /// `items` are `(mod_op, attribute, values)`; `LDAP_MOD_BVALUES` is added.
    fn new<'a>(
        items: impl Iterator<Item = (c_int, &'a str, &'a [&'a [u8]])>,
    ) -> Result<Self, LdapError> {
        let (mut ops, mut names, mut bvals) = (Vec::new(), Vec::new(), Vec::new());
        for (op, attr, values) in items {
            ops.push(op | ffi::LDAP_MOD_BVALUES);
            names.push(CString::new(attr)?);
            bvals.push(values.iter().map(|v| berval_of(v)).collect::<Vec<_>>());
        }
        // The inner vectors' heap buffers do not move when the outer ones do.
        let mut bvptrs: Vec<Vec<*mut berval>> = bvals
            .iter_mut()
            .map(|bvs| {
                bvs.iter_mut()
                    .map(ptr::from_mut)
                    .chain([ptr::null_mut()])
                    .collect()
            })
            .collect();
        let mut mods: Vec<ffi::LDAPMod> = ops
            .iter()
            .zip(&names)
            .zip(&mut bvptrs)
            .map(|((&mod_op, name), vals)| ffi::LDAPMod {
                mod_op,
                mod_type: name.as_ptr().cast_mut(),
                mod_vals: vals.as_mut_ptr(),
            })
            .collect();
        let ptrs = mods
            .iter_mut()
            .map(ptr::from_mut)
            .chain([ptr::null_mut()])
            .collect();
        Ok(Self {
            ptrs,
            _entries: mods,
            _bvptrs: bvptrs,
            _bvals: bvals,
            _names: names,
        })
    }
}

/// Walk the libldap result chain and decode each entry's attributes.
///
/// # Safety
///
/// `res` must be a valid (possibly NULL) result chain from `ldap_search_ext_s`.
/// The caller must free `res` with `ldap_msgfree` after this function returns.
unsafe fn collect_entries(ld: *mut LDAP, res: *mut ffi::LDAPMessage) -> Vec<SearchEntry> {
    let mut entries = Vec::new();
    // SAFETY: the caller's contract; every `entry` comes from ldap_first/next_entry.
    unsafe {
        let mut entry = ffi::ldap_first_entry(ld, res);
        while !entry.is_null() {
            entries.push(decode_entry(ld, entry));
            entry = ffi::ldap_next_entry(ld, entry);
        }
    }
    entries
}

/// Decode one LDAP entry into a [`SearchEntry`].
///
/// # Safety
///
/// `ld` and `entry` must be valid non-null pointers from `ldap_first/next_entry`.
/// The caller retains ownership of both; this function does not free them.
unsafe fn decode_entry(ld: *mut LDAP, entry: *mut ffi::LDAPMessage) -> SearchEntry {
    // SAFETY: the caller's contract; libldap owns what it hands out until the
    // matching free below.
    unsafe {
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
        se
    }
}

/// Decode a NULL-terminated `berval**` into parallel string and byte vectors.
///
/// # Safety
///
/// `vals_ptr` must be a valid non-null pointer returned by `ldap_get_values_len`.
/// The caller must free it with `ldap_value_free_len` after this function returns.
unsafe fn decode_bervals(vals_ptr: *mut *mut berval) -> (Vec<String>, Vec<Vec<u8>>) {
    let mut bin_vals = Vec::new();
    // SAFETY: the caller's contract; the array ends with a null pointer and
    // every other element is a valid berval.
    unsafe {
        let mut i = 0usize;
        while !(*vals_ptr.add(i)).is_null() {
            bin_vals.push(berval_bytes(&**vals_ptr.add(i)));
            i += 1;
        }
    }
    let str_vals = bin_vals
        .iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect();
    (str_vals, bin_vals)
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
    let len = usize::try_from(bv.bv_len).unwrap_or(0);
    unsafe { std::slice::from_raw_parts(bv.bv_val as *const u8, len).to_vec() }
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
            LdapConnection::connect("ldap://127.0.0.1:38999", Tls::Off, Some(Duration::from_secs(5))).expect("initialize");
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
            Tls::CaFile(Path::new("/nonexistent/ca.pem")),
            Some(Duration::from_secs(5)),
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
    fn nul_byte_in_argument_is_rejected() {
        let mut conn =
            LdapConnection::connect("ldap://127.0.0.1:38999", Tls::Off, Some(Duration::from_secs(5))).expect("initialize");
        let err = conn
            .delete_s("uid=a\0,dc=test")
            .expect_err("NUL byte must be rejected");
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
    fn mods_array_is_null_terminated_and_binary_safe() {
        let (a, b): (&[u8], &[u8]) = (b"x", b"\0y");
        let m = Mods::new(
            [
                (ffi::LDAP_MOD_ADD, "cn", &[a, b][..]),
                (ffi::LDAP_MOD_DELETE, "sn", &[][..]),
            ]
            .into_iter(),
        )
        .expect("no NUL in names");
        assert_eq!(m.ptrs.len(), 3);
        assert!(m.ptrs[2].is_null());
        // SAFETY: ptrs[0] points into `m`'s storage, alive here.
        unsafe {
            let first = &*m.ptrs[0];
            assert_eq!(first.mod_op, ffi::LDAP_MOD_ADD | ffi::LDAP_MOD_BVALUES);
            assert_eq!(berval_bytes(&**first.mod_vals.add(1)), b"\0y");
            assert!((*first.mod_vals.add(2)).is_null());
            assert!((*(*m.ptrs[1]).mod_vals).is_null());
        }
        assert!(Mods::new([(0, "c\0n", &[][..])].into_iter()).is_err());
    }

    #[test]
    fn search_entry_lookup_ignores_case() {
        let mut e = SearchEntry::default();
        e.attrs.insert("memberof".into(), vec!["a".into(), "b".into()]);
        e.bin_attrs.insert("memberof".into(), vec![b"a".to_vec()]);
        assert_eq!(e.values("memberOf"), ["a", "b"]);
        assert_eq!(e.first("MEMBEROF"), Some("a"));
        assert!(e.has("memberOf"));
        assert!(e.values("cn").is_empty() && e.first("cn").is_none() && !e.has("cn"));
    }

    #[test]
    fn search_entry_default_is_empty() {
        let e = SearchEntry::default();
        assert_eq!(e.dn, "");
        assert!(e.attrs.is_empty());
        assert!(e.bin_attrs.is_empty());
    }
}
