//! ML-DSA parameter sets (FIPS 204, Table 1 and Table 2).

use std::ffi::CStr;

use native_ossl::pkey::{HasPublic, Pkey};
use native_ossl::system_policy::SystemPolicy;

use crate::error::{Error, Result};

/// One of the three ML-DSA parameter sets standardised in FIPS 204.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterSet {
    /// ML-DSA-44 (NIST security category 2).
    MlDsa44,
    /// ML-DSA-65 (NIST security category 3).
    MlDsa65,
    /// ML-DSA-87 (NIST security category 5).
    MlDsa87,
}

impl ParameterSet {
    /// All parameter sets, in increasing order of security.
    pub const ALL: [Self; 3] = [Self::MlDsa44, Self::MlDsa65, Self::MlDsa87];

    /// Order in which [`preferred`](Self::preferred) picks a parameter set.
    pub const PREFERENCE: [Self; 3] = [Self::MlDsa65, Self::MlDsa87, Self::MlDsa44];

    /// FIPS 204 parameter set number.
    #[must_use]
    pub const fn level(self) -> u16 {
        match self {
            Self::MlDsa44 => 44,
            Self::MlDsa65 => 65,
            Self::MlDsa87 => 87,
        }
    }

    /// Does the system crypto policy allow this parameter set?
    ///
    /// The policy is the `SignatureAlgorithms` list of OpenSSL's
    /// `system_default` configuration (on Fedora/RHEL, crypto-policies);
    /// this parameter set is allowed when it lists `mldsa44`/`65`/`87`.
    /// OpenSSL itself does not apply that list outside TLS.
    ///
    /// # Errors
    ///
    /// [`Error::SystemPolicy`] if OpenSSL's configuration cannot be read.
    pub fn allowed_by_system(self) -> Result<bool> {
        let policy = SystemPolicy::current().map_err(Error::SystemPolicy)?;
        Ok(policy.allows_ml_dsa(self.level()))
    }

    pub(crate) fn ensure_allowed(self) -> Result<()> {
        if self.allowed_by_system()? {
            Ok(())
        } else {
            Err(Error::DisabledBySystemPolicy(self))
        }
    }

    /// The first parameter set in [`PREFERENCE`](Self::PREFERENCE) that the
    /// system crypto policy allows.
    ///
    /// # Errors
    ///
    /// [`Error::NoAllowedParameterSet`] if the policy allows none.
    pub fn preferred() -> Result<Self> {
        for set in Self::PREFERENCE {
            if set.allowed_by_system()? {
                return Ok(set);
            }
        }
        Err(Error::NoAllowedParameterSet)
    }

    /// The OpenSSL algorithm name, e.g. `"ML-DSA-65"`.
    #[must_use]
    pub const fn algorithm_name(self) -> &'static CStr {
        match self {
            Self::MlDsa44 => c"ML-DSA-44",
            Self::MlDsa65 => c"ML-DSA-65",
            Self::MlDsa87 => c"ML-DSA-87",
        }
    }

    /// Length of an encoded public key in bytes.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Length of an encoded ML-DSA signature in bytes.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Identify the parameter set of an OpenSSL key, if it is an ML-DSA key.
    pub(crate) fn of<T: HasPublic>(key: &Pkey<T>) -> Option<Self> {
        Self::ALL.into_iter().find(|p| key.is_a(p.algorithm_name()))
    }
}

impl std::fmt::Display for ParameterSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.algorithm_name().to_string_lossy())
    }
}
