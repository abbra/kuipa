//! Error type.

use std::fmt;

/// Errors returned by this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error from the underlying `tang-pqc` primitives or OpenSSL.
    Crypto(tang_pqc::Error),
    /// An encoded object could not be parsed.
    Malformed(&'static str),
    /// A delegation or bundle is not signed by a pinned anchor.
    UntrustedAnchor,
    /// A delegation, advertisement or bundle is expired or not yet valid.
    Expired,
    /// The advertisement does not belong to the expected realm.
    WrongRealm,
    /// A value does not match what the verified advertisement promises (for
    /// example a CA certificate whose hash is not advertised).
    Mismatch(&'static str),
    /// The server refused the request.  Deliberately carries no detail: the
    /// server answers every failure after decapsulation the same way.
    Refused,
    /// The response does not belong to this request, or was tampered with.
    BadResponse,
    /// A recipient key or secret cannot open this bundle.
    WrongRecipient,
    /// A required item is missing (e.g. no join key in the advertisement).
    Missing(&'static str),
    /// The operation needs an explicit opt-in (e.g. a signed-only bundle).
    Insecure(&'static str),
    /// A peer sync is not for this server, or its token does not
    /// authenticate the sender it names (§4.2).
    PeerSync(&'static str),
    /// The advertisement verifies but describes another deployment than
    /// the client was told to join (§4.6): the message names both.
    Deployment(String),
    /// A vault policy or operation is refused (§7.6).
    Policy(String),
    /// An advertised CA certificate or PKINIT anchor is not a certificate a
    /// host may install as a CA: which list, which entry (from 1), and
    /// what it is instead ([`check_ca`](crate::certs::check_ca)).
    NotCa {
        /// `"CA certificate"` or `"PKINIT anchor"`.
        list: &'static str,
        /// The entry's place in its list, from 1.
        entry: usize,
        /// What it is instead.
        what: crate::certs::NotCa,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Malformed(what) => write!(f, "malformed {what}"),
            Self::UntrustedAnchor => f.write_str("not signed by a trusted realm anchor"),
            Self::Expired => f.write_str("expired or not yet valid"),
            Self::WrongRealm => f.write_str("advertisement is for another realm"),
            Self::Mismatch(what) => write!(f, "{what} does not match the advertisement"),
            Self::Refused => f.write_str("the server refused the request"),
            Self::BadResponse => f.write_str("the server response is not valid for this request"),
            Self::WrongRecipient => f.write_str("this key or secret cannot open the bundle"),
            Self::Missing(what) => write!(f, "missing {what}"),
            Self::Insecure(what) => write!(f, "{what} requires an explicit opt-in"),
            Self::PeerSync(what) => write!(f, "peer sync refused: {what}"),
            Self::Deployment(why) | Self::Policy(why) => f.write_str(why),
            Self::NotCa { list, entry, what } => write!(f, "{list} {entry} is {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<tang_pqc::Error> for Error {
    fn from(e: tang_pqc::Error) -> Self {
        match e {
            tang_pqc::Error::Malformed(what) => Self::Malformed(what),
            e => Self::Crypto(e),
        }
    }
}

impl From<native_ossl::error::ErrorStack> for Error {
    fn from(e: native_ossl::error::ErrorStack) -> Self {
        Self::Crypto(e.into())
    }
}

/// Convenience alias for `Result<T, kuipa_enroll::Error>`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
