//! Error type for GSSAPI operations.

use crate::ffi::OmUint32;

/// An error from a GSSAPI call, carrying the major and minor status codes.
///
/// The `major` code follows the GSS-API bit layout defined in RFC 2743 §1.2.1.
/// The `minor` code is mechanism-specific; for Kerberos it is a MIT krb5 error
/// code that `com_err` can render as a human-readable string.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum GssError {
    /// `gss_import_name` failed to parse the service name string.
    ///
    /// This typically indicates an empty or structurally invalid service name.
    #[error("gss_import_name failed: {detail}")]
    ImportName {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// `gss_acquire_cred_from` failed to load acceptor credentials from the
    /// keytab.
    ///
    /// Common causes: the keytab file does not exist or is not readable by the
    /// akamu process, the file does not contain a key for the requested
    /// service principal, or the Kerberos libraries are not installed.
    #[error("gss_acquire_cred_from failed: {detail}")]
    AcquireCred {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// `gss_accept_sec_context` rejected the client token.
    ///
    /// Common causes: the service ticket has expired, the client targeted the
    /// wrong service principal, the token was replayed, or it was forged.
    #[error("gss_accept_sec_context failed: {detail}")]
    AcceptContext {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// `gss_display_name` failed to convert the authenticated name to a
    /// printable string.
    #[error("gss_display_name failed: {detail}")]
    DisplayName {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// The display name returned by `gss_display_name` is not valid UTF-8.
    ///
    /// In practice this should not occur with MIT Kerberos, which always
    /// returns ASCII-compatible principal name strings.
    #[error("principal name is not valid UTF-8")]
    InvalidUtf8,

    /// `service_name` passed to [`crate::GssServerCred::acquire`] contains an
    /// interior NUL byte and cannot be passed to the C GSSAPI library.
    #[error("service name contains an interior NUL byte")]
    NulInServiceName,

    /// `keytab_file` passed to [`crate::GssServerCred::acquire`] contains an
    /// interior NUL byte and cannot be passed to the C GSSAPI library.
    #[error("keytab path contains an interior NUL byte")]
    NulInKeytabPath,

    /// The keytab file does not exist or is not readable by the current process.
    ///
    /// Checked before calling into the GSSAPI library so the error message names
    /// the missing path explicitly rather than surfacing an opaque minor status.
    #[error("keytab file not readable: {path}: {source}")]
    KeytabNotReadable {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// `target_service` passed to [`crate::init_token`] or [`crate::GssClientContext::new`] contains an interior NUL byte.
    #[error("target service name contains an interior NUL byte")]
    NulInTargetName,

    /// `user_principal` passed to [`crate::GssClientCred::impersonate`] contains an interior NUL byte.
    #[error("user principal contains an interior NUL byte")]
    NulInUserPrincipal,

    /// A ccache name passed to a credential function contains an interior NUL byte.
    #[error("ccache name contains an interior NUL byte")]
    NulInCcacheName,

    /// `gss_init_sec_context` failed to produce the initial token.
    ///
    /// Common causes: the Kerberos TGT in the default ccache has expired
    /// (run `kinit` to obtain a new one), the KDC is unreachable, or the
    /// target service principal does not exist in the Kerberos database.
    #[error("gss_init_sec_context failed: {detail}")]
    InitContext {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// `gss_acquire_cred_impersonate_name` failed (S4U2Self).
    ///
    /// Common causes: the KDC does not allow protocol transition for this
    /// service, the user principal does not exist, or constrained delegation
    /// is not configured.
    #[error("gss_acquire_cred_impersonate_name failed: {detail}")]
    ImpersonateCred {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// Credential export via FILE: ccache failed.
    #[error("credential export failed: {detail}")]
    ExportCred {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// `gss_store_cred_into` failed to write the credential to the named cache.
    #[error("gss_store_cred_into failed: {detail}")]
    StoreCred {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// `gss_krb5_ccache_name` failed to set the thread-local credential cache.
    #[error("gss_krb5_ccache_name failed: {detail}")]
    SetCcache {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// A libkrb5 function failed (TGT acquisition or ccache operation).
    #[error("krb5 error in {msg}: code {code:#010x}")]
    Krb5 { code: i32, msg: &'static str },

    /// `gss_pseudo_random` failed, or the mechanism returned a short output.
    #[error("gss_pseudo_random failed: {detail}")]
    PseudoRandom {
        major: OmUint32,
        minor: OmUint32,
        detail: String,
    },

    /// The exchange needs another round trip where one token must suffice.
    #[error("the GSS-API exchange needs more than one token")]
    NotComplete,

    /// A password contains an interior NUL byte.
    #[error("password contains an interior NUL byte")]
    NulInPassword,

    /// The Kerberos configuration path contains an interior NUL byte.
    #[error("configuration path contains an interior NUL byte")]
    NulInConfigPath,

    /// libkrb5 rejected a request, with its own message.
    #[error("{msg}: {detail}")]
    Krb5Detail {
        code: i32,
        msg: &'static str,
        detail: String,
    },

    /// The KDC offered a pre-authentication method whose answer could not be
    /// collected: there was no terminal to ask on, or the asking failed.
    /// `detail` says which method was wanted and why it could not be had.
    #[error("pre-authentication: {detail}")]
    Preauth { detail: String },
}

const GSS_S_CALL_INACCESSIBLE_READ: OmUint32 = 0x01000000;
const GSS_CALLING_ERROR_MASK: OmUint32 = 0xFF000000;

impl GssError {
    /// Whether this error indicates the credential handle has become stale
    /// (e.g. gssproxy restarted, TGT expired and was purged).
    ///
    /// Re-acquiring the server credential from the original source
    /// (keytab / gssproxy) and retrying the operation usually succeeds.
    pub fn is_stale_credential(&self) -> bool {
        let major = match self {
            GssError::ImpersonateCred { major, .. }
            | GssError::AcquireCred { major, .. }
            | GssError::InitContext { major, .. } => *major,
            _ => return false,
        };
        major & GSS_CALLING_ERROR_MASK == GSS_S_CALL_INACCESSIBLE_READ
    }
}
