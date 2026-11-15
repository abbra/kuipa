//! Error type for GSSAPI operations.

use std::ffi::CString;

use crate::ffi::OmUint32;
use crate::status::format_gss_status;

/// An error from a GSSAPI call, carrying the major and minor status codes.
///
/// The `major` code follows the GSS-API bit layout defined in RFC 2743 §1.2.1.
/// The `minor` code is mechanism-specific; for Kerberos it is a MIT krb5 error
/// code that `com_err` can render as a human-readable string.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum GssError {
    /// A GSS-API call failed.
    ///
    /// Common causes: for `gss_acquire_cred_from`, an unreadable keytab or one
    /// without a key for the service; for `gss_accept_sec_context`, an
    /// expired ticket, the wrong service, a replay or a forged token; for
    /// `gss_init_sec_context`, an expired TGT, an unreachable KDC or an
    /// unknown service principal; for `gss_acquire_cred_impersonate_name`
    /// (S4U2Self), KDC policy that forbids protocol transition.
    #[error("{op} failed: {detail}")]
    Gss {
        /// The failing C function.
        op: &'static str,
        /// GSS major status code.
        major: OmUint32,
        /// Mechanism-specific minor status code.
        minor: OmUint32,
        /// Formatted status text.
        detail: String,
    },

    /// A string passed in cannot go to the C library: it has an interior NUL
    /// byte.
    #[error("{what} contains an interior NUL byte")]
    Nul {
        /// Which argument.
        what: &'static str,
    },

    /// The display name returned by `gss_display_name` is not valid UTF-8.
    ///
    /// In practice this should not occur with MIT Kerberos, which always
    /// returns ASCII-compatible principal name strings.
    #[error("principal name is not valid UTF-8")]
    InvalidUtf8,

    /// The keytab file does not exist or is not readable by the current process.
    ///
    /// Checked before calling into the GSSAPI library so the error message names
    /// the missing path explicitly rather than surfacing an opaque minor status.
    #[error("keytab file not readable: {path}: {source}")]
    KeytabNotReadable {
        /// Path involved.
        path: String,
        #[source]
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// A libkrb5 function failed (TGT acquisition or ccache operation).
    #[error("krb5 error in {msg}: code {code:#010x}")]
    Krb5 {
        /// libkrb5 error code.
        code: i32,
        /// The failing operation.
        msg: &'static str,
    },

    /// The principal has no realm to name the KDC by.
    #[error("user principal has no realm")]
    NoRealm,

    /// The exchange needs another round trip where one token must suffice.
    #[error("the GSS-API exchange needs more than one token")]
    NotComplete,

    /// libkrb5 rejected a request, with its own message.
    #[error("{msg}: {detail}")]
    Krb5Detail {
        /// Numeric error code.
        code: i32,
        /// Message.
        msg: &'static str,
        /// Formatted status text.
        detail: String,
    },

    /// The KDC offered a pre-authentication method whose answer could not be
    /// collected: there was no terminal to ask on, or the asking failed.
    /// `detail` says which method was wanted and why it could not be had.
    #[error("pre-authentication: {detail}")]
    Preauth {
        /// Which method was wanted and why it could not be had.
        detail: String,
    },

    /// The Kerberos library this build is linked against has no equivalent of
    /// `feature`.  Heimdal lacks MIT's credential-store, S4U2Self, responder
    /// and thread-local-ccache extensions; builds that ask for one of them
    /// fail here rather than half-working.
    #[error("{feature} is not supported by the Kerberos library this build uses")]
    Unsupported {
        /// The missing capability.
        feature: &'static str,
    },
}

impl GssError {
    /// A failed GSS-API call `op`, with the status codes rendered; logged
    /// once here for every caller.
    pub(crate) fn gss(op: &'static str, major: OmUint32, minor: OmUint32) -> Self {
        let detail = format_gss_status(major, minor);
        tracing::warn!(op, major = %format_args!("{major:#010x}"), minor = %format_args!("{minor:#010x}"), %detail, "GSS-API call failed");
        Self::Gss { op, major, minor, detail }
    }
}

/// `s` as a C string, or [`GssError::Nul`] naming `what`.
pub(crate) fn cstring(s: impl Into<Vec<u8>>, what: &'static str) -> Result<CString, GssError> {
    CString::new(s).map_err(|_| GssError::Nul { what })
}
