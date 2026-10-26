//! A software security key (the `soft-fido2` feature), for the playground
//! and tests: credentials of any algorithm under their relying parties, an
//! optional PIN, and an `hmac-secret` that answers differently with the
//! user verified, as CTAP 2.1 has it.  `kuipa` uses one instead of the
//! attached keys when `$KUIPA_SOFT_FIDO2` names its file ([`from_env`]).
//!
//! The file holds the private keys in the clear: it stands in for a
//! security key only where nothing is worth protecting.
//!
//! [`from_env`]: super::from_env

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kuipa_enroll::passkey::Algorithm;
use kuipa_enroll::passkey::soft::SoftAuthenticator;
use kuipa_fido2::{Assertion, AssertionRequest, Credential, CredentialRequest};
use native_ossl::util::SecretBuf;
use serde_json::{Value, json};

use super::Authenticator;
use crate::paths::{self, Error};

/// What the key holds.
#[derive(Default)]
struct State {
    pin: Option<String>,
    credentials: Vec<(String, SoftAuthenticator)>,
    touches: u64,
}

impl State {
    fn to_json(&self) -> Value {
        json!({
            "pin": self.pin,
            "touches": self.touches,
            "credentials": self
                .credentials
                .iter()
                .map(|(rp_id, c)| json!({ "rp_id": rp_id, "credential": c.to_json() }))
                .collect::<Vec<_>>(),
        })
    }

    fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            pin: v.get("pin")?.as_str().map(str::to_owned),
            touches: v.get("touches")?.as_u64()?,
            credentials: v
                .get("credentials")?
                .as_array()?
                .iter()
                .map(|c| {
                    Some((
                        c.get("rp_id")?.as_str()?.to_owned(),
                        SoftAuthenticator::from_json(c.get("credential")?)?,
                    ))
                })
                .collect::<Option<_>>()?,
        })
    }
}

/// One software security key, in memory or kept in a file.
pub struct SoftFido2 {
    path: Option<PathBuf>,
    state: Mutex<State>,
}

impl SoftFido2 {
    /// A key in memory, with `pin` set or none.
    #[must_use]
    pub fn new(pin: Option<&str>) -> Self {
        Self {
            path: None,
            state: Mutex::new(State {
                pin: pin.map(str::to_owned),
                ..State::default()
            }),
        }
    }

    /// The key kept in `path`; a new one, without a PIN, if there is no
    /// such file yet.
    ///
    /// # Errors
    ///
    /// An unreadable or malformed file.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let state = match std::fs::read(path) {
            Ok(bytes) => State::from_json(&serde_json::from_slice(&bytes)?)
                .ok_or_else(|| format!("{}: not a software security key", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: Some(path.to_path_buf()),
            state: Mutex::new(state),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn save(&self, state: &State) -> Result<(), Error> {
        if let Some(path) = &self.path {
            paths::write_file(path, &serde_json::to_vec_pretty(&state.to_json())?, 0o600)?;
        }
        Ok(())
    }

    /// Set the key's PIN, or remove it.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn set_pin(&self, pin: Option<&str>) -> Result<(), Error> {
        let mut state = self.lock();
        state.pin = pin.map(str::to_owned);
        self.save(&state)
    }

    /// Make a credential of `alg` for `rp_id`, as `ipa user-add-passkey
    /// --register` does, and answer the `ipaPassKey` value IPA stores.
    ///
    /// # Errors
    ///
    /// The file cannot be written.
    pub fn add_ipa_passkey(&self, rp_id: &str, alg: Algorithm) -> Result<String, Error> {
        let cred = SoftAuthenticator::new(alg);
        let value = cred.ipa_value();
        let mut state = self.lock();
        state.credentials.push((rp_id.to_owned(), cred));
        self.save(&state)?;
        Ok(value)
    }

    /// How many times the key was touched.
    #[must_use]
    pub fn touches(&self) -> u64 {
        self.lock().touches
    }

    /// Whether `pin` verifies the user: an error for a wrong one, or one
    /// given to a key without a PIN, as libfido2 reports them.
    fn verify(state: &State, pin: Option<&str>) -> Result<bool, Error> {
        match (pin, &state.pin) {
            (None, _) => Ok(false),
            (Some(given), Some(set)) if given == set => Ok(true),
            (Some(_), Some(_)) => Err("software security key: FIDO_ERR_PIN_INVALID".into()),
            (Some(_), None) => Err("software security key: FIDO_ERR_PIN_NOT_SET".into()),
        }
    }
}

impl Authenticator for SoftFido2 {
    fn assert(&self, req: &AssertionRequest<'_>, pin: Option<&str>) -> Result<Assertion, Error> {
        let mut state = self.lock();
        let uv = Self::verify(&state, pin)?;
        if req.user_verification && !uv {
            return Err("software security key: FIDO_ERR_PIN_REQUIRED".into());
        }
        let (_, cred) = state
            .credentials
            .iter()
            .find(|(rp, c)| {
                rp == req.rp_id && (req.allow.is_empty() || req.allow.iter().any(|id| id == c.id()))
            })
            .ok_or("software security key: FIDO_ERR_NO_CREDENTIALS")?;
        tracing::info!(
            rp_id = req.rp_id,
            alg = cred.alg().name(),
            user_verified = uv,
            hmac_secret = req.hmac_salt.is_some(),
            "software security key touched"
        );
        let flags = 0x01 | if uv { 0x04 } else { 0 };
        let a = cred.assert_with(req.rp_id, req.client_data_hash, flags);
        let hmac_secret = req.hmac_salt.map(|salt| {
            let mut out = cred.hmac_secret(salt);
            if uv {
                // CredRandomWithUV differs from CredRandomWithoutUV.
                for b in &mut out {
                    *b ^= 0x5a;
                }
            }
            SecretBuf::new(out.to_vec())
        });
        state.touches += 1;
        self.save(&state)?;
        Ok(Assertion {
            credential_id: a.credential_id,
            authenticator_data: a.authenticator_data,
            signature: a.signature,
            hmac_secret,
        })
    }

    fn make_credential(
        &self,
        req: &CredentialRequest<'_>,
        pin: Option<&str>,
    ) -> Result<Credential, Error> {
        let mut state = self.lock();
        Self::verify(&state, pin)?;
        let alg = req
            .algorithms
            .iter()
            .find_map(|&c| Algorithm::from_cose(i64::from(c)))
            .ok_or("software security key: FIDO_ERR_UNSUPPORTED_ALGORITHM")?;
        tracing::info!(
            rp_id = req.rp_id,
            alg = alg.name(),
            "software security key touched: a new credential"
        );
        let cred = SoftAuthenticator::new(alg);
        let id = cred.id().to_vec();
        state.credentials.push((req.rp_id.to_owned(), cred));
        state.touches += 1;
        self.save(&state)?;
        Ok(Credential {
            id,
            alg: i32::try_from(alg.cose()).unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_in_a_file_keeps_its_credentials_and_pin() {
        let dir = std::env::temp_dir().join(format!("kuipa-soft-fido2-{}", std::process::id()));
        let path = dir.join("key.json");
        let key = SoftFido2::open(&path).unwrap();
        key.set_pin(Some("1234")).unwrap();
        key.add_ipa_passkey("example.test", Algorithm::Es384)
            .unwrap();
        let again = SoftFido2::open(&path).unwrap();
        let cdh = [1u8; 32];
        let req = AssertionRequest {
            rp_id: "example.test",
            client_data_hash: &cdh,
            allow: &[],
            user_verification: true,
            hmac_salt: Some(&cdh),
        };
        assert!(again.assert(&req, None).is_err(), "the PIN is required");
        assert!(again.assert(&req, Some("0000")).is_err(), "a wrong PIN");
        let a = again.assert(&req, Some("1234")).unwrap();
        assert_eq!(a.authenticator_data[32], 0x05);
        assert!(a.hmac_secret.is_some());
        assert_eq!(SoftFido2::open(&path).unwrap().touches(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
