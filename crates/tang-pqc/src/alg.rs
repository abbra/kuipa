//! Algorithm identifiers (FIPS 203 ML-KEM and FIPS 204 ML-DSA).

use std::ffi::CStr;

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

    /// Does the system crypto policy allow this KEM?
    ///
    /// ML-KEM-*n* is allowed when any TLS group the policy allows contains
    /// it, pure or hybrid (see [`SystemPolicy::allows_ml_kem`]).
    ///
    /// # Errors
    ///
    /// [`Error::SystemPolicy`] if OpenSSL's configuration cannot be read.
    pub fn allowed_by_system(self) -> Result<bool> {
        Ok(system_policy()?.allows_ml_kem(self.level()))
    }

    /// Fail unless the system crypto policy allows this KEM.
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

    /// The first KEM in [`PREFERENCE`](Self::PREFERENCE) that the system
    /// policy allows.
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
        Err(Error::NoAllowedAlgorithm("ML-KEM"))
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
            Self::MlKem768 => c"SHA2-256",
            Self::MlKem1024 => c"SHA2-384",
        }
    }

    /// Length of the FIPS 203 private-key seed `d ‖ z`.
    pub(crate) const SEED_LEN: usize = 64;

    pub(crate) fn from_jose_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.jose_name() == name)
    }

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

    pub(crate) fn of<T: HasPublic>(key: &Pkey<T>) -> Option<Self> {
        Self::ALL.into_iter().find(|a| key.is_a(a.name()))
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
    /// ML-DSA-44 is left out: the default client policy does not accept it.
    pub const PREFERENCE: [Self; 2] = [Self::MlDsa65, Self::MlDsa87];

    /// FIPS 204 parameter set number.
    const fn level(self) -> u16 {
        match self {
            Self::MlDsa44 => 44,
            Self::MlDsa65 => 65,
            Self::MlDsa87 => 87,
        }
    }

    /// Does the system crypto policy allow this algorithm (TLS signature
    /// algorithm `mldsa44`/`mldsa65`/`mldsa87`)?
    ///
    /// # Errors
    ///
    /// [`Error::SystemPolicy`] if OpenSSL's configuration cannot be read.
    pub fn allowed_by_system(self) -> Result<bool> {
        Ok(system_policy()?.allows_ml_dsa(self.level()))
    }

    pub(crate) fn ensure_allowed(self) -> Result<()> {
        if self.allowed_by_system()? {
            Ok(())
        } else {
            Err(Error::DisabledBySystemPolicy(self.jose_name()))
        }
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
        Err(Error::NoAllowedAlgorithm("ML-DSA"))
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

    pub(crate) fn from_jose_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.jose_name() == name)
    }

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

    pub(crate) fn of<T: HasPublic>(key: &Pkey<T>) -> Option<Self> {
        Self::ALL.into_iter().find(|a| key.is_a(a.name()))
    }
}
