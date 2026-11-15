//! Algorithm identifiers (FIPS 203 ML-KEM and FIPS 204 ML-DSA).

use std::ffi::CStr;
use std::fmt;
use std::str::FromStr;

use native_ossl::pkey::{HasPublic, Pkey};
use native_ossl::system_policy::SystemPolicy;

use crate::error::{Error, Result};

fn system_policy() -> Result<&'static SystemPolicy> {
    SystemPolicy::current().map_err(Error::SystemPolicy)
}

/// KEM used for key recovery.
///
/// ML-KEM-512 is deliberately not offered: binding ciphertexts sit on disk
/// for the lifetime of the encrypted volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemAlg {
    /// ML-KEM-768 (NIST category 3).
    MlKem768,
    /// ML-KEM-1024 (NIST category 5, CNSA 2.0).
    MlKem1024,
}

impl KemAlg {
    /// All supported KEMs.
    pub const ALL: [Self; 2] = [Self::MlKem768, Self::MlKem1024];

    /// Order in which the library picks a KEM when the caller does not.
    pub const PREFERENCE: [Self; 2] = [Self::MlKem768, Self::MlKem1024];

    /// FIPS 203 parameter set number.
    const fn level(self) -> u16 {
        match self {
            Self::MlKem768 => 768,
            Self::MlKem1024 => 1024,
        }
    }

    /// OpenSSL algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static CStr {
        match self {
            Self::MlKem768 => c"ML-KEM-768",
            Self::MlKem1024 => c"ML-KEM-1024",
        }
    }

    /// JOSE `alg` value (draft-ietf-jose-pqc-kem; provisional).
    #[must_use]
    pub const fn jose_name(self) -> &'static str {
        match self {
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// Hash for HKDF and transcript hashing: SHA-256 at category 3,
    /// SHA-384 at category 5 (CNSA 2.0).
    #[must_use]
    pub const fn hash(self) -> &'static CStr {
        match self {
            Self::MlKem768 => crate::primitives::SHA256,
            Self::MlKem1024 => crate::primitives::SHA384,
        }
    }

    /// Length of the FIPS 203 private-key seed `d ‖ z`.
    pub(crate) const SEED_LEN: usize = 64;

    /// Wire identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::MlKem768 => 0x01,
            Self::MlKem1024 => 0x02,
        }
    }

    /// Encapsulation (public) key length in bytes.
    #[must_use]
    pub const fn encapsulation_key_len(self) -> usize {
        match self {
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Ciphertext length in bytes.
    #[must_use]
    pub const fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// The KEM whose ciphertexts are `len` bytes long.
    #[must_use]
    pub fn from_ciphertext_len(len: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.ciphertext_len() == len)
    }

    /// The KEM whose encapsulation keys are `len` bytes long.
    #[must_use]
    pub fn from_key_len(len: usize) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.encapsulation_key_len() == len)
    }

    /// Inverse of [`id`](Self::id).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedAlgorithm`] for an unknown id.
    pub fn from_id(id: u8) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.id() == id)
            .ok_or(Error::UnsupportedAlgorithm(id))
    }
}

/// Signature algorithm used to sign advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlg {
    /// ML-DSA-44 (NIST category 2).
    MlDsa44,
    /// ML-DSA-65 (NIST category 3).
    MlDsa65,
    /// ML-DSA-87 (NIST category 5, CNSA 2.0).
    MlDsa87,
}

impl SignatureAlg {
    /// All supported signature algorithms.
    pub const ALL: [Self; 3] = [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87];

    /// Order in which the library picks an algorithm for new signing keys.
    /// ML-DSA-44 is left out of new keys; the default client policy still
    /// accepts it, for witnesses and cosigners that use it.
    pub const PREFERENCE: [Self; 2] = [Self::MlDsa65, Self::MlDsa87];

    /// FIPS 204 parameter set number.
    const fn level(self) -> u16 {
        match self {
            Self::MlDsa44 => 44,
            Self::MlDsa65 => 65,
            Self::MlDsa87 => 87,
        }
    }

    /// OpenSSL algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static CStr {
        match self {
            Self::MlDsa44 => c"ML-DSA-44",
            Self::MlDsa65 => c"ML-DSA-65",
            Self::MlDsa87 => c"ML-DSA-87",
        }
    }

    /// JOSE `alg` value (RFC 9964).
    #[must_use]
    pub const fn jose_name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Length of the FIPS 204 private-key seed `ξ`.
    pub(crate) const SEED_LEN: usize = 32;

    /// Public key length in bytes.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Signature length in bytes.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

/// What [`KemAlg`] and [`SignatureAlg`] share: the system-policy queries,
/// `of` and the JOSE name as `Display`/`FromStr`.  `$family` names the
/// algorithm family in errors and `$allows` is its [`SystemPolicy`] query.
macro_rules! alg_family {
    ($ty:ident, $family:literal, $allows:ident) => {
        impl $ty {
            /// Does the system crypto policy allow this algorithm?
            ///
            /// ML-KEM-*n* is allowed when any TLS group the policy allows
            /// contains it, pure or hybrid; ML-DSA-*n* when it allows the
            /// TLS signature algorithm `mldsa<n>`.
            ///
            /// # Errors
            ///
            /// [`Error::SystemPolicy`] if OpenSSL's configuration cannot be read.
            pub fn allowed_by_system(self) -> Result<bool> {
                Ok(system_policy()?.$allows(self.level()))
            }

            /// Fail unless the system crypto policy allows this algorithm.
            ///
            /// # Errors
            ///
            /// [`Error::DisabledBySystemPolicy`] or [`Error::SystemPolicy`].
            pub fn ensure_allowed(self) -> Result<()> {
                if self.allowed_by_system()? {
                    Ok(())
                } else {
                    Err(Error::DisabledBySystemPolicy(self.jose_name()))
                }
            }

            /// The algorithms of [`ALL`](Self::ALL) that the system policy allows.
            ///
            /// # Errors
            ///
            /// [`Error::SystemPolicy`] if OpenSSL's configuration cannot be read.
            pub fn allowed() -> Result<Vec<Self>> {
                let mut out = Vec::new();
                for alg in Self::ALL {
                    if alg.allowed_by_system()? {
                        out.push(alg);
                    }
                }
                Ok(out)
            }

            /// The first algorithm in [`PREFERENCE`](Self::PREFERENCE) that the
            /// system policy allows.
            ///
            /// # Errors
            ///
            /// [`Error::NoAllowedAlgorithm`] if the policy allows none.
            pub fn preferred() -> Result<Self> {
                for alg in Self::PREFERENCE {
                    if alg.allowed_by_system()? {
                        return Ok(alg);
                    }
                }
                Err(Error::NoAllowedAlgorithm($family))
            }

            pub(crate) fn of<T: HasPublic>(key: &Pkey<T>) -> Option<Self> {
                Self::ALL.into_iter().find(|a| key.is_a(a.name()))
            }
        }

        /// The JOSE `alg` value.
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.jose_name())
            }
        }

        impl FromStr for $ty {
            type Err = Error;

            fn from_str(name: &str) -> Result<Self> {
                Self::ALL
                    .into_iter()
                    .find(|a| a.jose_name() == name)
                    .ok_or(Error::Malformed("algorithm name"))
            }
        }
    };
}

alg_family!(KemAlg, "ML-KEM", allows_ml_kem);
alg_family!(SignatureAlg, "ML-DSA", allows_ml_dsa);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jose_names_round_trip() {
        for alg in KemAlg::ALL {
            assert_eq!(alg.to_string().parse::<KemAlg>().unwrap(), alg);
        }
        for alg in SignatureAlg::ALL {
            assert_eq!(alg.to_string().parse::<SignatureAlg>().unwrap(), alg);
        }
        assert!("ML-KEM-512".parse::<KemAlg>().is_err());
        assert!("ML-KEM-768".parse::<SignatureAlg>().is_err());
    }

    #[test]
    fn kems_are_found_by_length() {
        for alg in KemAlg::ALL {
            assert_eq!(KemAlg::from_key_len(alg.encapsulation_key_len()), Some(alg));
        }
        assert_eq!(KemAlg::from_ciphertext_len(1088), Some(KemAlg::MlKem768));
        assert_eq!(KemAlg::from_ciphertext_len(1568), Some(KemAlg::MlKem1024));
        assert_eq!(KemAlg::from_ciphertext_len(1), None);
    }
}
