//! Error type.

use std::fmt;

use native_ossl::error::ErrorStack;

use crate::params::ParameterSet;

/// Errors returned by this crate.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An OpenSSL operation failed.
    OpenSsl(ErrorStack),
    /// The key is not an ML-DSA key (ML-DSA-44, ML-DSA-65 or ML-DSA-87).
    UnsupportedKey,
    /// An ML-DSA context string longer than 255 bytes was supplied.
    ContextTooLong(usize),
    /// An encoded object had the wrong length.
    InvalidLength {
        /// What was being decoded.
        what: &'static str,
        /// Length required by the parameter set.
        expected: usize,
        /// Length actually supplied.
        actual: usize,
    },
    /// A signature did not verify.
    InvalidSignature,
    /// A signature just produced by the signer failed verification, which
    /// indicates a fault.  It was not released.
    SigningFault,
    /// The system crypto policy (OpenSSL's `system_default` configuration,
    /// e.g. Fedora/RHEL crypto-policies) disables this parameter set.
    DisabledBySystemPolicy(ParameterSet),
    /// The system crypto policy allows no ML-DSA parameter set.
    NoAllowedParameterSet,
    /// OpenSSL's configuration exists but cannot be read, so the system
    /// policy is unknown; operations fail closed.
    SystemPolicy(ErrorStack),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenSsl(e) => write!(f, "OpenSSL error: {e}"),
            Self::UnsupportedKey => f.write_str("key is not an ML-DSA key"),
            Self::ContextTooLong(n) => {
                write!(f, "ML-DSA context string is {n} bytes, at most 255 allowed")
            }
            Self::InvalidLength {
                what,
                expected,
                actual,
            } => write!(f, "{what} must be {expected} bytes, got {actual}"),
            Self::InvalidSignature => f.write_str("signature verification failed"),
            Self::SigningFault => {
                f.write_str("signer produced an invalid signature (possible fault); withheld")
            }
            Self::DisabledBySystemPolicy(set) => {
                write!(f, "{set} is disabled by the system crypto policy")
            }
            Self::NoAllowedParameterSet => {
                f.write_str("the system crypto policy allows no ML-DSA parameter set")
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

/// Convenience alias for `Result<T, ml_dsa_blind::Error>`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
