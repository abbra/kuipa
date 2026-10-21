//! A general post-quantum Tang server (`tang-pqc`), next to enrollment
//! (§11.5).
//!
//! It is stateless, like Tang, and shares nothing with the realm's keys:
//! its own ML-DSA signing keys and ML-KEM exchange keys live in
//! `<key_dir>/tang/`, laid out like Tang's key directory — `<thumbprint>.jwk`
//! per key, a leading `.` for a retired key. Endpoints, under `/ipa/ku/tang/`
//! so that clients use `https://<server>/ipa/ku/tang` as the Tang URL:
//!
//! * `GET adv`: the advertisement, signed by every current signing key;
//! * `GET adv/{thp}`: the same, also signed by signing key `thp` if it is
//!   retired, so a client that pinned it can verify the new keys after a
//!   rotation (Tang's behaviour);
//! * `POST rec/{kid}`: recovery with any current or retired exchange key, in
//!   `tang-pqc`'s own protocol domain.
//!
//! Anyone holding a binding can recover its key: the only guard is the
//! per-address rate limit, as for Tang behind a firewall.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};
use std::time::SystemTime;

use tang_pqc::{
    AdvertisementBuilder, DEFAULT_ADVERTISEMENT_VALIDITY, ExchangeKey, ExchangeKeyPair,
    RecoveryRequest, RecoveryResponse, Server, SignedAdvertisement, SigningKey, Thumbprint,
    unix_seconds,
};

use crate::keystore::Error;

/// The Tang key directory.
pub struct TangKeys {
    dir: PathBuf,
}

/// The keys of one kind, current and retired.
#[derive(Default)]
struct Loaded {
    signing: Vec<SigningKey>,
    retired_signing: Vec<SigningKey>,
    exchange: Vec<ExchangeKeyPair>,
    retired_exchange: Vec<ExchangeKeyPair>,
}

impl TangKeys {
    /// The Tang keys under `key_dir`.
    #[must_use]
    pub fn new(key_dir: &Path) -> Self {
        Self {
            dir: key_dir.join("tang"),
        }
    }

    fn files(&self) -> Result<Vec<(String, bool)>, Error> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut names = Vec::new();
        for entry in entries {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".jwk") {
                let (retired, _) = stem.strip_prefix('.').map_or((false, stem), |s| (true, s));
                names.push((name, retired));
            }
        }
        names.sort();
        Ok(names)
    }

    fn load(&self) -> Result<Loaded, Error> {
        let mut keys = Loaded::default();
        for (name, retired) in self.files()? {
            // Wiping buffer: the bytes hold the private seed.
            let bytes = native_ossl::util::SecretBuf::new(fs::read(self.dir.join(&name))?);
            if let Ok(k) = SigningKey::from_jwk(bytes.as_ref()) {
                if retired {
                    keys.retired_signing.push(k);
                } else {
                    keys.signing.push(k);
                }
            } else {
                let k = ExchangeKeyPair::from_jwk(bytes.as_ref())
                    .map_err(|e| format!("{}: {e}", self.dir.join(&name).display()))?;
                if retired {
                    keys.retired_exchange.push(k);
                } else {
                    keys.exchange.push(k);
                }
            }
        }
        Ok(keys)
    }

    /// The current signing keys' thumbprints: what clients pin.
    ///
    /// # Errors
    ///
    /// I/O or a malformed key.
    pub fn thumbprints(&self) -> Result<Vec<Thumbprint>, Error> {
        Ok(self
            .load()?
            .signing
            .iter()
            .map(|k| *k.public().thumbprint())
            .collect())
    }

    /// Create a signing and an exchange key (the system's preferred
    /// parameter sets), as `tangd-keygen` does; returns the signing key's
    /// thumbprint.
    ///
    /// # Errors
    ///
    /// Current keys exist already, or I/O.
    pub fn generate(&self) -> Result<Thumbprint, Error> {
        if self.files()?.iter().any(|(_, retired)| !retired) {
            return Err("Tang keys exist already (use tang-rotate)".into());
        }
        fs::create_dir_all(&self.dir)?;
        let signing = SigningKey::generate_preferred()?;
        let exchange = ExchangeKeyPair::generate_preferred()?;
        let thp = *signing.public().thumbprint();
        crate::keystore::write_private(
            &self.dir.join(format!("{thp}.jwk")),
            signing.to_jwk()?.as_ref(),
        )?;
        crate::keystore::write_private(
            &self.dir.join(format!("{}.jwk", exchange.public().kid())),
            exchange.to_jwk()?.as_ref(),
        )?;
        Ok(thp)
    }

    /// Retire every current key and create new ones, as `tangd-rotate-keys`
    /// does; returns the new signing key's thumbprint.  Retired exchange
    /// keys keep answering existing bindings; delete their `.`-files once
    /// every client has rebound (`clevis luks regen`).
    ///
    /// # Errors
    ///
    /// I/O.
    pub fn rotate(&self) -> Result<Thumbprint, Error> {
        for (name, retired) in self.files()? {
            if !retired {
                fs::rename(self.dir.join(&name), self.dir.join(format!(".{name}")))?;
            }
        }
        self.generate()
    }

    /// The server, or `None` without current keys.
    ///
    /// # Errors
    ///
    /// I/O, a malformed key, or keys the system policy disables.
    pub fn server(&self) -> Result<Option<Tang>, Error> {
        let keys = self.load()?;
        if keys.signing.is_empty() && keys.exchange.is_empty() {
            return Ok(None);
        }
        if keys.signing.is_empty() || keys.exchange.is_empty() {
            return Err(format!(
                "{} needs both a signing and an exchange key",
                self.dir.display()
            )
            .into());
        }
        // The server owns its keys; the copies sign `adv/{thp}`.
        let signing = keys
            .signing
            .iter()
            .map(|k| Ok(SigningKey::from_jwk(k.to_jwk()?.as_ref())?))
            .collect::<Result<Vec<_>, Error>>()?;
        let exchange: Vec<ExchangeKey> = keys.exchange.iter().map(|k| k.public().clone()).collect();
        let server =
            Server::new(keys.signing, keys.exchange)?.with_retired_keys(keys.retired_exchange);
        Ok(Some(Tang {
            server,
            signing,
            retired_signing: keys.retired_signing,
            exchange,
            countersigned: RwLock::new(HashMap::new()),
        }))
    }
}

/// The running Tang service.
pub struct Tang {
    server: Server,
    signing: Vec<SigningKey>,
    retired_signing: Vec<SigningKey>,
    exchange: Vec<ExchangeKey>,
    /// Advertisements also signed by a retired key, and when.
    countersigned: RwLock<HashMap<Thumbprint, (SignedAdvertisement, u64)>>,
}

impl Tang {
    /// `GET adv`.
    ///
    /// # Errors
    ///
    /// A signing error.
    pub fn advertisement(&self) -> tang_pqc::Result<SignedAdvertisement> {
        self.server.advertisement()
    }

    /// `GET adv/{thp}`: `None` for a key this server never had.
    ///
    /// # Errors
    ///
    /// A signing error.
    pub fn advertisement_for(
        &self,
        thp: &Thumbprint,
    ) -> tang_pqc::Result<Option<SignedAdvertisement>> {
        if self.signing.iter().any(|k| k.public().thumbprint() == thp) {
            return self.server.advertisement().map(Some);
        }
        let Some(retired) = self
            .retired_signing
            .iter()
            .find(|k| k.public().thumbprint() == thp)
        else {
            return Ok(None);
        };
        let now = unix_seconds(SystemTime::now());
        let validity = DEFAULT_ADVERTISEMENT_VALIDITY.as_secs();
        if let Some((adv, iat)) = self
            .countersigned
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(thp)
            && now.saturating_sub(*iat) < validity / 2
        {
            return Ok(Some(adv.clone()));
        }
        let signers: Vec<&SigningKey> = self.signing.iter().chain([retired]).collect();
        let mut builder = AdvertisementBuilder::new(&signers);
        for k in &self.exchange {
            builder = builder.exchange_key(k);
        }
        let adv = builder.validity(now, now + validity).sign()?;
        self.countersigned
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(*thp, (adv.clone(), now));
        Ok(Some(adv))
    }

    /// `GET key/{kid}`: the public exchange key, advertised or retired, that
    /// clients seal recovery requests to.
    ///
    /// # Errors
    ///
    /// [`tang_pqc::Error::UnknownKey`] for a key this server does not have.
    pub fn exchange_key(&self, kid: &Thumbprint) -> tang_pqc::Result<&ExchangeKey> {
        self.server.exchange_key(kid)
    }

    /// `POST rec/{kid}`.
    ///
    /// # Errors
    ///
    /// An unknown key or a malformed request.
    pub fn recover(&self, request: &RecoveryRequest) -> tang_pqc::Result<RecoveryResponse> {
        self.server.recover(request)
    }
}

#[cfg(test)]
mod tests {
    use tang_pqc::Binding;

    use super::*;

    fn temp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kuipa-tang-{}-{}",
            std::process::id(),
            unix_seconds(SystemTime::now())
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn keys_rotate_like_tang() {
        let dir = temp();
        let keys = TangKeys::new(&dir);
        assert!(keys.server().unwrap().is_none(), "no keys, no Tang");
        let old = keys.generate().unwrap();
        assert!(keys.generate().is_err());
        let tang = keys.server().unwrap().unwrap();
        let adv = tang.advertisement().unwrap();
        let verified = SignedAdvertisement::from_json(adv.to_json().as_bytes())
            .unwrap()
            .verify(&old)
            .unwrap();
        let (binding, key) = verified.provision(None).unwrap();

        let new = keys.rotate().unwrap();
        assert_ne!(old, new);
        assert_eq!(keys.thumbprints().unwrap(), [new]);
        let tang = keys.server().unwrap().unwrap();
        // The old pin still verifies the new keys through adv/{old}…
        let adv = tang.advertisement_for(&old).unwrap().unwrap();
        let reparsed = SignedAdvertisement::from_json(adv.to_json().as_bytes()).unwrap();
        assert!(reparsed.verify(&old).is_ok());
        assert!(reparsed.verify(&new).is_ok());
        // …but not the plain advertisement, and unknown keys get nothing.
        let plain = tang.advertisement().unwrap().to_json();
        assert!(
            SignedAdvertisement::from_json(plain.as_bytes())
                .unwrap()
                .verify(&old)
                .is_err()
        );
        assert!(
            tang.advertisement_for(&Thumbprint::from_bytes([9; 32]))
                .unwrap()
                .is_none()
        );
        // The retired exchange key still recovers the old binding.
        let binding = Binding::from_bytes(&binding.to_bytes()).unwrap();
        let ek = tang.exchange_key(binding.kid()).unwrap();
        let (request, pending) = binding.recovery_request(ek).unwrap();
        let response = tang.recover(&request).unwrap();
        assert_eq!(pending.finish(&response).unwrap().as_ref(), key.as_ref());
        let _ = fs::remove_dir_all(&dir);
    }
}
