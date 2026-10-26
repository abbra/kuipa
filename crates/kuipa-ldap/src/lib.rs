//! Synchronous LDAP client (from `ahdapa-ldap`): simple, GSSAPI and S4U
//! binds, search, add, modify, delete and extended operations, as a thin
//! safe wrapper around the `OpenLDAP` C library.  Call it from blocking
//! code (or `tokio::task::spawn_blocking`).
//!
//! # Quick start
//!
//! ```rust,no_run
//! use kuipa_ldap::{Auth, LdapConnection, Scope};
//!
//! # fn example() -> Result<(), kuipa_ldap::LdapError> {
//! let mut conn = LdapConnection::connect("ldapi://%2Frun%2Fslapd-EXAMPLE-COM.socket", None, false, 10)?;
//! conn.bind(&Auth::Gssapi)?;
//! for e in conn.search("cn=accounts,dc=example,dc=com", Scope::Subtree, "(fqdn=web1.example.com)", &["cn"])? {
//!     println!("{}: {:?}", e.dn, e.attrs);
//! }
//! conn.extended_operation("1.3.6.1.4.1.4203.1.11.3", None)?; // Who am I?
//! # Ok(())
//! # }
//! ```

pub mod conn;
pub mod ffi;

pub use conn::{ExtendedResult, LdapConnection, ModOp, SearchEntry};

use libc::c_int;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("LDAP protocol error {code}: {msg}")]
    Protocol { code: c_int, msg: String },
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("NUL byte in argument: {0}")]
    NulByte(String),
    #[error("background task panicked")]
    TaskPanic,
}

impl From<std::ffi::NulError> for LdapError {
    fn from(e: std::ffi::NulError) -> Self {
        LdapError::NulByte(e.to_string())
    }
}

/// LDAP search scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The base object only.
    Base,
    /// Immediate children of the base only.
    OneLevel,
    /// The base object and all descendants.
    Subtree,
}

impl Scope {
    pub(crate) fn as_int(self) -> c_int {
        match self {
            Scope::Base => ffi::LDAP_SCOPE_BASE,
            Scope::OneLevel => ffi::LDAP_SCOPE_ONELEVEL,
            Scope::Subtree => ffi::LDAP_SCOPE_SUBTREE,
        }
    }
}

/// Authentication credentials for an LDAP bind.
///
/// `password` is a `SecretBuf`, cleansed via `OPENSSL_cleanse` on drop,
/// to reduce the window during which the cleartext password lives in
/// process memory after the bind completes. `bind_dn` is not secret.
pub enum Auth {
    /// LDAP simple bind: DN + cleartext password.
    Simple {
        bind_dn: String,
        password: native_ossl::util::SecretBuf,
    },
    /// SASL GSSAPI bind using the Kerberos ticket-granting ticket in the
    /// current credential cache.  No explicit credentials are required.
    Gssapi,
}

/// Escape a string for use as a filter assertion value (RFC 4515 §4).
///
/// The characters `*`, `(`, `)`, `\`, and `\0` must be encoded as their
/// hex escape (`\2a`, `\28`, `\29`, `\5c`, `\00`).  Every other character
/// passes through unchanged.
#[must_use]
pub fn filter_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape a string for use as an attribute value in a DN (RFC 4514 §2.4).
///
/// Leading `#`, leading/trailing space, and the characters `\`, `"`, `+`,
/// `,`, `;`, `<`, `>`, `=`, and `\0` are escaped.  All other characters
/// pass through unchanged.
#[must_use]
pub fn dn_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.char_indices() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '+' => out.push_str("\\+"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            '<' => out.push_str("\\<"),
            '>' => out.push_str("\\>"),
            '=' => out.push_str("\\="),
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || i == s.len() - 1 => out.push_str("\\ "),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{dn_escape, filter_escape};

    // ── filter_escape: RFC 4515 §4 filter-value special characters ───────────

    #[test]
    fn filter_escape_asterisk() {
        assert_eq!(filter_escape("*"), "\\2a");
    }

    #[test]
    fn filter_escape_open_paren() {
        assert_eq!(filter_escape("("), "\\28");
    }

    #[test]
    fn filter_escape_close_paren() {
        assert_eq!(filter_escape(")"), "\\29");
    }

    #[test]
    fn filter_escape_backslash() {
        assert_eq!(filter_escape("\\"), "\\5c");
    }

    #[test]
    fn filter_escape_nul_byte() {
        assert_eq!(filter_escape("\0"), "\\00");
    }

    #[test]
    fn filter_escape_safe_string_unchanged() {
        assert_eq!(filter_escape("alice.smith"), "alice.smith");
    }

    #[test]
    fn filter_escape_injection_payload_neutralised() {
        // Classic LDAP injection attempt: )(uid=*)( must not pass through.
        let escaped = filter_escape(")(uid=*)(");
        assert!(!escaped.contains('('), "unescaped ( in: {escaped}");
        assert!(!escaped.contains(')'), "unescaped ) in: {escaped}");
        assert!(!escaped.contains('*'), "unescaped * in: {escaped}");
        assert_eq!(escaped, "\\29\\28uid=\\2a\\29\\28");
    }

    #[test]
    fn filter_escape_mixed_safe_and_special() {
        assert_eq!(filter_escape("user*(a)"), "user\\2a\\28a\\29");
    }

    // ── dn_escape: RFC 4514 DN special characters ─────────────────────────────

    #[test]
    fn dn_escape_backslash() {
        assert_eq!(dn_escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn dn_escape_double_quote() {
        assert_eq!(dn_escape(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn dn_escape_plus() {
        assert_eq!(dn_escape("a+b"), "a\\+b");
    }

    #[test]
    fn dn_escape_comma() {
        assert_eq!(dn_escape("a,b"), "a\\,b");
    }

    #[test]
    fn dn_escape_semicolon() {
        assert_eq!(dn_escape("a;b"), "a\\;b");
    }

    #[test]
    fn dn_escape_angle_brackets() {
        assert_eq!(dn_escape("a<b>c"), "a\\<b\\>c");
    }

    #[test]
    fn dn_escape_equals() {
        assert_eq!(dn_escape("a=b"), "a\\=b");
    }

    #[test]
    fn dn_escape_hash_at_start() {
        assert_eq!(dn_escape("#foo"), "\\#foo");
    }

    #[test]
    fn dn_escape_hash_not_at_start_unchanged() {
        assert_eq!(dn_escape("foo#bar"), "foo#bar");
    }

    #[test]
    fn dn_escape_leading_space() {
        assert_eq!(dn_escape(" foo"), "\\ foo");
    }

    #[test]
    fn dn_escape_trailing_space() {
        assert_eq!(dn_escape("foo "), "foo\\ ");
    }

    #[test]
    fn dn_escape_interior_space_unchanged() {
        assert_eq!(dn_escape("foo bar"), "foo bar");
    }

    #[test]
    fn dn_escape_nul_byte() {
        assert_eq!(dn_escape("\0"), "\\00");
    }

    #[test]
    fn dn_escape_safe_string_unchanged() {
        assert_eq!(dn_escape("alice.smith"), "alice.smith");
    }
}
