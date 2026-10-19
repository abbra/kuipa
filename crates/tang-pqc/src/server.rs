//! Server side (the Tang daemon).

use std::sync::{PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use crate::adv::{Lifetime, SignedAdvertisement};
use crate::error::{Error, Result};
use crate::keys::{ExchangeKey, ExchangeKeyPair, SigningKey, Thumbprint};
use crate::policy::unix_seconds;
use crate::primitives::Domain;
use crate::protocol::{RecoveryRequest, RecoveryResponse};

/// Default advertisement validity.  Clients reject anything longer than
/// their policy's maximum (30 days by default).
pub const DEFAULT_ADVERTISEMENT_VALIDITY: Duration = Duration::from_secs(7 * 24 * 3600);

/// Sign with, and advertise, only keys the system crypto policy allows, so a
/// server holding keys of several strengths falls back to the allowed ones.
fn sign_advertisement(
    signing: &[SigningKey],
    exchange: &[ExchangeKeyPair],
    validity: Duration,
    now: u64,
) -> Result<SignedAdvertisement> {
    let mut allowed_signing = Vec::new();
    for key in signing {
        if key.public().alg().allowed_by_system()? {
            allowed_signing.push(key);
        }
    }
    if allowed_signing.is_empty() {
        return Err(Error::NoAllowedAlgorithm("ML-DSA signing key"));
    }
    let mut publics = Vec::new();
    for key in exchange {
        if key.public().alg().allowed_by_system()? {
            publics.push(key.public());
        }
    }
    if publics.is_empty() {
        return Err(Error::NoAllowedAlgorithm("ML-KEM exchange key"));
    }
    let lifetime = Lifetime {
        iat: now,
        exp: now.saturating_add(validity.as_secs()),
    };
    SignedAdvertisement::sign(&allowed_signing, &publics, Some(lifetime))
}

/// A stateless recovery server.
///
/// Holds no per-client state: everything needed to answer a recovery request
/// is in the request and the server's keys.
#[derive(Debug)]
pub struct Server {
    signing_keys: Vec<SigningKey>,
    exchange_keys: Vec<ExchangeKeyPair>,
    retired_keys: Vec<ExchangeKeyPair>,
    validity: Duration,
    /// The current advertisement and when it was issued.
    advertisement: RwLock<(SignedAdvertisement, u64)>,
}

impl Server {
    /// Create a server that advertises `exchange_keys`, signed by every key
    /// in `signing_keys`, with [`DEFAULT_ADVERTISEMENT_VALIDITY`].
    ///
    /// # Errors
    ///
    /// [`Error::NoExchangeKey`] if either list is empty,
    /// [`Error::NoAllowedAlgorithm`] if the system crypto policy allows none
    /// of the signing or exchange keys, or an OpenSSL error while signing the
    /// advertisement.
    pub fn new(signing_keys: Vec<SigningKey>, exchange_keys: Vec<ExchangeKeyPair>) -> Result<Self> {
        Self::with_validity(signing_keys, exchange_keys, DEFAULT_ADVERTISEMENT_VALIDITY)
    }

    /// As [`new`](Self::new), with an explicit advertisement validity.
    ///
    /// # Errors
    ///
    /// As for [`new`](Self::new); [`Error::Policy`] for a zero validity.
    pub fn with_validity(
        signing_keys: Vec<SigningKey>,
        exchange_keys: Vec<ExchangeKeyPair>,
        validity: Duration,
    ) -> Result<Self> {
        if signing_keys.is_empty() || exchange_keys.is_empty() {
            return Err(Error::NoExchangeKey);
        }
        if validity.as_secs() == 0 {
            return Err(Error::Policy("advertisement validity must be at least 1 s"));
        }
        let now = unix_seconds(SystemTime::now());
        let adv = sign_advertisement(&signing_keys, &exchange_keys, validity, now)?;
        Ok(Self {
            signing_keys,
            exchange_keys,
            retired_keys: Vec::new(),
            validity,
            advertisement: RwLock::new((adv, now)),
        })
    }

    /// Add rotated-out exchange keys: still used to answer recovery requests
    /// from existing bindings, but no longer advertised (Tang's hidden
    /// `.jwk` files).
    #[must_use]
    pub fn with_retired_keys(mut self, retired: Vec<ExchangeKeyPair>) -> Self {
        self.retired_keys = retired;
        self
    }

    /// The signed advertisement to serve at `GET /adv`.
    ///
    /// It carries `iat`/`exp` and is re-signed once half of its validity has
    /// passed, so clients always receive one with at least half its lifetime
    /// left.
    ///
    /// # Errors
    ///
    /// An OpenSSL error if re-signing fails.
    pub fn advertisement(&self) -> Result<SignedAdvertisement> {
        let now = unix_seconds(SystemTime::now());
        let refresh_after = self.validity.as_secs() / 2;
        {
            let current = self
                .advertisement
                .read()
                .unwrap_or_else(PoisonError::into_inner);
            if now.saturating_sub(current.1) < refresh_after.max(1) {
                return Ok(current.0.clone());
            }
        }
        let adv = sign_advertisement(&self.signing_keys, &self.exchange_keys, self.validity, now)?;
        *self
            .advertisement
            .write()
            .unwrap_or_else(PoisonError::into_inner) = (adv.clone(), now);
        Ok(adv)
    }

    /// The public exchange key `kid`, advertised or retired, to serve at
    /// `GET /key/{kid}` ([`ExchangeKey::to_jwk_json`]).
    ///
    /// A client needs it to seal a recovery request.  The thumbprint
    /// authenticates the key, so the client needs no signature check and no
    /// clock.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownKey`] if the server has no such exchange key.
    pub fn exchange_key(&self, kid: &Thumbprint) -> Result<&ExchangeKey> {
        Ok(self.key_pair(kid)?.public())
    }

    fn key_pair(&self, kid: &Thumbprint) -> Result<&ExchangeKeyPair> {
        self.exchange_keys
            .iter()
            .chain(&self.retired_keys)
            .find(|k| k.public().kid() == kid)
            .ok_or(Error::UnknownKey(*kid))
    }

    /// Answer `POST /rec/{kid}`.
    ///
    /// Applications should authenticate or rate-limit callers as their policy
    /// requires: anyone holding a binding's metadata can ask for recovery.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownKey`] if the server has no such exchange key,
    /// [`Error::Malformed`] if the request does not match it or does not
    /// open under it, or [`Error::DisabledBySystemPolicy`] if the system
    /// crypto policy disables its KEM.
    pub fn recover(&self, request: &RecoveryRequest) -> Result<RecoveryResponse> {
        let key = self.key_pair(request.kid())?;
        if key.public().alg() != request.alg() {
            return Err(Error::Malformed("recovery request"));
        }
        request.respond(key, Domain::TANG)
    }
}
