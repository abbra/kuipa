//! Error type.

use std::fmt;

use native_ossl::error::ErrorStack;

use crate::keys::Thumbprint;

/// Errors returned by this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An OpenSSL operation failed.
    OpenSsl(ErrorStack),
    /// An encoded object could not be parsed.
    Malformed(&'static str),
    /// An algorithm identifier is unknown or not allowed here.
    UnsupportedAlgorithm(u8),
    /// An OpenSSL key is not of a supported type.
    UnsupportedKey,
    /// The advertisement is not signed by the trusted key, or does not list it.
    UntrustedAdvertisement,
    /// The advertisement is expired or not yet valid.
    StaleAdvertisement,
    /// The advertisement violates the client's [`Policy`](crate::Policy).
    Policy(&'static str),
    /// A signature did not verify.
    InvalidSignature,
    /// The advertisement has no usable exchange key.
    NoExchangeKey,
    /// The server has no exchange key with this id.
    UnknownKey(Thumbprint),
    /// The server's response did not yield the provisioned key.
    RecoveryFailed,
    /// The exchange key offered for recovery is not the binding's key.
    KeyMismatch,
    /// The system crypto policy (OpenSSL's `system_default` configuration,
    /// e.g. Fedora/RHEL crypto-policies) disables this algorithm.
    DisabledBySystemPolicy(&'static str),
    /// The system crypto policy allows none of the supported algorithms of
    /// this kind.
    NoAllowedAlgorithm(&'static str),
    /// OpenSSL's configuration exists but cannot be read, so the system
    /// policy is unknown; operations fail closed.
    SystemPolicy(ErrorStack),
    /// The private key's seed is not available, so it cannot be written as a
    /// JWK (RFC 9964 and the ML-KEM JOSE draft allow only the seed form).
    SeedUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenSsl(e) => write!(f, "OpenSSL error: {e}"),
            Self::Malformed(what) => write!(f, "malformed {what}"),
            Self::UnsupportedAlgorithm(id) => write!(f, "unsupported algorithm id 0x{id:02x}"),
            Self::UnsupportedKey => f.write_str("unsupported key type"),
            Self::UntrustedAdvertisement => {
                f.write_str("advertisement is not signed by the trusted key")
            }
            Self::StaleAdvertisement => f.write_str("advertisement is expired or not yet valid"),
            Self::Policy(why) => write!(f, "policy violation: {why}"),
            Self::InvalidSignature => f.write_str("signature verification failed"),
            Self::NoExchangeKey => f.write_str("advertisement has no usable exchange key"),
            Self::UnknownKey(kid) => write!(f, "no exchange key with id {kid}"),
            Self::RecoveryFailed => f.write_str("key recovery failed"),
            Self::KeyMismatch => f.write_str("exchange key does not match the binding"),
            Self::SeedUnavailable => f.write_str("private key seed is not available"),
            Self::DisabledBySystemPolicy(alg) => {
                write!(f, "{alg} is disabled by the system crypto policy")
            }
            Self::NoAllowedAlgorithm(kind) => {
                write!(f, "the system crypto policy allows no {kind} variant")
            }
            Self::SystemPolicy(e) => write!(f, "cannot read the system crypto policy: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenSsl(e) | Self::SystemPolicy(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Self::OpenSsl(e)
    }
}

/// Convenience alias for `Result<T, tang_pqc::Error>`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
