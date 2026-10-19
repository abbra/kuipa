//! Server key directory (`/var/lib/ipa/ku/`, §4.1): seed-form private JWKs
//! as in Tang's key directory, plus the state of the anchor exchange.
//!
//! ```text
//! anchor.jwk           this server's anchor (ML-DSA)
//! signing.jwk          server ML-DSA signing key
//! join-<kid>.jwk       advertised join keys
//! escrow-<kid>.jwk     advertised escrow keys
//! trust-<kid>.jwk      advertised trust keys (§17.4)
//! .join-<kid>.jwk      retired join keys: answered, not advertised
//! .escrow-<kid>.jwk    retired escrow keys: answered, not advertised
//! .trust-<kid>.jwk     retired trust keys: answered, not advertised
//! delegation.json      the advertised delegation, with its cosignatures
//! succession-<thp>.json  a rotated anchor's signed succession (§4.7); the
//!                      rotated anchor's private key is gone
//! peers.state          the anchor exchange state (§4.2)
//! ```

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use kuipa_enroll::anchors::AnchorState;
use kuipa_enroll::delegation::{Delegation, SignedSuccession};
use kuipa_enroll::realm::ServerKeys;
use tang_pqc::{ExchangeKeyPair, SigningKey, Thumbprint, VerifyingKey};

/// Errors from the key store.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Which keys [`KeyStore::rotate`] replaces, one flag per
/// `rotate-keys` option.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Rotation {
    /// Retire the join keys and create a new one.
    pub join: bool,
    /// Retire the escrow keys and create a new one.
    pub escrow: bool,
    /// Retire the trust keys and create a new one.
    pub trust: bool,
    /// Replace the signing key.  The old one is not kept: it only signs
    /// advertisements and bundles, and the next claim names the new one.
    pub signing: bool,
}

/// What [`KeyStore::rotate`] or [`KeyStore::prune`] changed: file names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    /// Keys created.
    pub created: Vec<String>,
    /// Keys retired (still answered, no longer advertised).
    pub retired: Vec<String>,
    /// Keys removed.
    pub removed: Vec<String>,
}

/// The key directory.
#[derive(Clone, Debug)]
pub struct KeyStore {
    dir: PathBuf,
}

/// Write `data` to `path` atomically with mode 0600.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<(), Error> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

impl KeyStore {
    /// A key store at `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Load the server's keys.
    ///
    /// # Errors
    ///
    /// I/O errors, malformed keys, or a missing signing key.
    pub fn load(&self) -> Result<ServerKeys, Error> {
        let signing = SigningKey::from_jwk(&fs::read(self.path("signing.jwk"))?)?;
        let mut keys = ServerKeys {
            signing,
            join: Vec::new(),
            escrow: Vec::new(),
            trust: Vec::new(),
            vouchers: Vec::new(),
            retired: Vec::new(),
        };
        for name in self.names()? {
            let load =
                || ExchangeKeyPair::from_jwk(&fs::read(self.path(&name))?).map_err(Error::from);
            if [".join-", ".escrow-", ".trust-"]
                .iter()
                .any(|p| name.starts_with(p))
            {
                keys.retired.push(load()?);
            } else if name.starts_with("join-") {
                keys.join.push(load()?);
            } else if name.starts_with("escrow-") {
                keys.escrow.push(load()?);
            } else if name.starts_with("trust-") {
                keys.trust.push(load()?);
            } else if name.starts_with("voucher-") {
                keys.vouchers
                    .push(VerifyingKey::from_jwk_json(&fs::read(self.path(&name))?)?);
            }
        }
        if keys.join.is_empty() || keys.escrow.is_empty() {
            return Err("key directory has no join or escrow key".into());
        }
        Ok(keys)
    }

    /// Accept vouchers signed under the public key `jwk` (§9), stored as
    /// `voucher-<thumbprint>.jwk`.  Returns the thumbprint.  Remove the
    /// file to stop accepting them.
    ///
    /// # Errors
    ///
    /// Not a public ML-DSA JWK, or an I/O error.
    pub fn add_voucher_key(&self, jwk: &[u8]) -> Result<Thumbprint, Error> {
        let value: serde_json::Value = serde_json::from_slice(jwk)?;
        if value.get("priv").is_some() {
            return Err("give the voucher key's public JWK, not the private key".into());
        }
        let key = VerifyingKey::from_jwk_json(jwk)?;
        let thp = *key.thumbprint();
        fs::write(self.path(&format!("voucher-{thp}.jwk")), key.to_jwk_json())?;
        Ok(thp)
    }

    /// Generate this server's anchor, a signing key, and one join and one
    /// escrow key, refusing to overwrite existing ones.  Returns the
    /// anchor.
    ///
    /// # Errors
    ///
    /// I/O errors, or a key the system crypto policy disables.
    pub fn generate(&self) -> Result<SigningKey, Error> {
        fs::create_dir_all(&self.dir)?;
        if self.path("signing.jwk").exists() || self.path("anchor.jwk").exists() {
            return Err("keys already exist".into());
        }
        let anchor = SigningKey::generate_preferred()?;
        write_private(&self.path("anchor.jwk"), anchor.to_jwk()?.as_ref())?;
        let signing = SigningKey::generate_preferred()?;
        write_private(&self.path("signing.jwk"), signing.to_jwk()?.as_ref())?;
        for role in ["join", "escrow", "trust"] {
            let key = ExchangeKeyPair::generate_preferred()?;
            let name = format!("{role}-{}.jwk", key.public().kid());
            write_private(&self.path(&name), key.to_jwk()?.as_ref())?;
        }
        Ok(anchor)
    }

    fn names(&self) -> Result<Vec<String>, Error> {
        let mut names: Vec<String> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| Path::new(n).extension().is_some_and(|e| e == "jwk"))
            .collect();
        names.sort();
        Ok(names)
    }

    fn create(&self, role: &str, changes: &mut Changes) -> Result<(), Error> {
        let key = ExchangeKeyPair::generate_preferred()?;
        let name = format!("{role}-{}.jwk", key.public().kid());
        write_private(&self.path(&name), key.to_jwk()?.as_ref())?;
        changes.created.push(name);
        Ok(())
    }

    /// Rotate the keys selected by `which`: new join and escrow keys are
    /// created first, then the current ones are retired (renamed to
    /// `.<name>`, with the time of retirement as their modification time),
    /// so the store always has a key of each role.  The daemon picks the
    /// changes up when it restarts.
    ///
    /// # Errors
    ///
    /// I/O errors, or a key the system crypto policy disables.
    pub fn rotate(&self, which: Rotation) -> Result<Changes, Error> {
        let mut changes = Changes::default();
        let current = self.names()?;
        for (role, wanted) in [
            ("join", which.join),
            ("escrow", which.escrow),
            ("trust", which.trust),
        ] {
            if !wanted {
                continue;
            }
            self.create(role, &mut changes)?;
            for name in current
                .iter()
                .filter(|n| n.starts_with(&format!("{role}-")))
            {
                let retired = format!(".{name}");
                fs::rename(self.path(name), self.path(&retired))?;
                fs::OpenOptions::new()
                    .write(true)
                    .open(self.path(&retired))?
                    .set_modified(SystemTime::now())?;
                changes.retired.push(retired);
            }
        }
        if which.signing {
            let signing = SigningKey::generate_preferred()?;
            let path = self.path("signing.jwk");
            let _ = fs::remove_file(path.with_extension("tmp"));
            write_private(&path, signing.to_jwk()?.as_ref())?;
            changes.created.push("signing.jwk".into());
        }
        Ok(changes)
    }

    /// Remove retired join and trust keys retired more than `join` ago,
    /// retired escrow keys retired more than `escrow` ago, and expired
    /// successions.
    ///
    /// Join keys need to outlive the advertisements that name them (7 days);
    /// escrow keys need to outlive every sealed keytab bound to them, which
    /// hosts rebind whenever they rotate their keys.
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn prune(&self, join: Duration, escrow: Duration) -> Result<Changes, Error> {
        let mut changes = Changes::default();
        let now = SystemTime::now();
        for name in self.names()? {
            let age = match () {
                () if name.starts_with(".join-") || name.starts_with(".trust-") => join,
                () if name.starts_with(".escrow-") => escrow,
                () => continue,
            };
            let retired = fs::metadata(self.path(&name))?.modified()?;
            if now.duration_since(retired).unwrap_or_default() >= age {
                fs::remove_file(self.path(&name))?;
                changes.removed.push(name);
            }
        }
        // Successions are useless once they expire.
        let at = tang_pqc::unix_seconds(now);
        for name in self.succession_files()? {
            let expired = serde_json::from_slice::<SignedSuccession>(&fs::read(self.path(&name))?)
                .ok()
                .and_then(|s| s.statement().ok())
                .is_some_and(|s| !s.valid_at(at));
            if expired {
                fs::remove_file(self.path(&name))?;
                changes.removed.push(name);
            }
        }
        Ok(changes)
    }

    /// Replace this server's anchor (§4.7): create a new one, have the
    /// current one sign the succession to it for `realm`, valid for
    /// `validity`, store the succession, and only then replace
    /// `anchor.jwk`, which deletes the old private key.  Returns the old
    /// and the new thumbprint.  The daemon picks the new anchor up when it
    /// restarts; its next claim names it.
    ///
    /// # Errors
    ///
    /// No anchor, I/O errors, or a key the system crypto policy disables.
    pub fn rotate_anchor(
        &self,
        realm: &str,
        validity: Duration,
    ) -> Result<(Thumbprint, Thumbprint), Error> {
        let old = self.anchor()?;
        let new = SigningKey::generate_preferred()?;
        let now = tang_pqc::unix_seconds(SystemTime::now());
        let succession = SignedSuccession::issue(
            &old,
            realm,
            new.public().thumbprint(),
            now,
            now + validity.as_secs(),
        )?;
        let old = *old.public().thumbprint();
        self.replace(
            &format!("succession-{old}.json"),
            serde_json::to_string(&succession)?.as_bytes(),
        )?;
        self.replace("anchor.jwk", new.to_jwk()?.as_ref())?;
        Ok((old, *new.public().thumbprint()))
    }

    /// The successions of this server's rotated anchors.
    ///
    /// # Errors
    ///
    /// I/O errors or a malformed file.
    pub fn successions(&self) -> Result<Vec<SignedSuccession>, Error> {
        self.succession_files()?
            .iter()
            .map(|name| Ok(serde_json::from_slice(&fs::read(self.path(name))?)?))
            .collect()
    }

    fn succession_files(&self) -> Result<Vec<String>, Error> {
        let mut names: Vec<String> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| {
                n.starts_with("succession-")
                    && Path::new(n).extension().is_some_and(|e| e == "json")
            })
            .collect();
        names.sort();
        Ok(names)
    }

    /// Load this server's anchor.
    ///
    /// # Errors
    ///
    /// I/O errors or a malformed key.
    pub fn anchor(&self) -> Result<SigningKey, Error> {
        Ok(SigningKey::from_jwk(&fs::read(self.path("anchor.jwk"))?)?)
    }

    /// The advertised delegation, if one was stored.
    ///
    /// # Errors
    ///
    /// I/O errors other than a missing file, or a malformed delegation.
    pub fn delegation(&self) -> Result<Option<Delegation>, Error> {
        match fs::read(self.path("delegation.json")) {
            Ok(json) => Ok(Some(Delegation::from_json(&json)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Store the advertised delegation.
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn store_delegation(&self, delegation: &Delegation) -> Result<(), Error> {
        self.replace("delegation.json", delegation.to_json().as_bytes())
    }

    /// The anchor exchange state (empty if none was stored).
    ///
    /// # Errors
    ///
    /// I/O errors other than a missing file, or a malformed state.
    pub fn peer_state(&self) -> Result<AnchorState, Error> {
        match fs::read(self.path("peers.state")) {
            Ok(bytes) => Ok(AnchorState::from_bytes(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AnchorState::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Store the anchor exchange state.
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn store_peer_state(&self, state: &AnchorState) -> Result<(), Error> {
        self.replace("peers.state", &state.to_bytes())
    }

    fn replace(&self, name: &str, data: &[u8]) -> Result<(), Error> {
        let path = self.path(name);
        let _ = fs::remove_file(path.with_extension("tmp"));
        write_private(&path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_anchor_leaves_a_succession() {
        let dir = std::env::temp_dir().join(format!("kuipa-keystore-rot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = KeyStore::new(&dir);
        let old = store.generate().unwrap();
        assert_eq!(store.successions().unwrap(), []);
        let (was, now) = store
            .rotate_anchor("R", Duration::from_secs(400 * 86400))
            .unwrap();
        assert_eq!(&was, old.public().thumbprint());
        let current = store.anchor().unwrap();
        assert_eq!(current.public().thumbprint(), &now);
        assert_ne!(was, now);
        assert!(
            !fs::read_dir(&dir).unwrap().any(|e| {
                fs::read(e.unwrap().path()).is_ok_and(|b| {
                    b.windows(old.to_jwk().unwrap().as_ref().len())
                        .any(|w| w == old.to_jwk().unwrap().as_ref())
                })
            }),
            "the old private key is gone"
        );
        let successions = store.successions().unwrap();
        assert_eq!(successions.len(), 1);
        let at = tang_pqc::unix_seconds(SystemTime::now());
        let s = successions[0]
            .check("R", &tang_pqc::Policy::default(), at)
            .unwrap();
        assert_eq!((s.old, s.new), (was, now));
        // Kept by prune until it expires.
        let pruned = store
            .prune(Duration::from_secs(1), Duration::from_secs(1))
            .unwrap();
        assert_eq!(pruned.removed, Vec::<String>::new());
        assert_eq!(store.successions().unwrap().len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn generate_then_load() {
        let dir = std::env::temp_dir().join(format!("kuipa-keystore-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = KeyStore::new(&dir);
        let anchor = store.generate().unwrap();
        let keys = store.load().unwrap();
        assert_eq!((keys.join.len(), keys.escrow.len()), (1, 1));
        assert_eq!(
            store.anchor().unwrap().public().thumbprint(),
            anchor.public().thumbprint()
        );
        assert!(store.generate().is_err(), "never overwrites keys");

        assert!(store.delegation().unwrap().is_none());
        assert!(store.peer_state().unwrap().is_empty());
        let d = Delegation::issue(&anchor, "R", "s", keys.signing.public(), 1, 2).unwrap();
        store.store_delegation(&d).unwrap();
        assert_eq!(store.delegation().unwrap(), Some(d));
        store.store_peer_state(&AnchorState::default()).unwrap();
        assert!(store.peer_state().unwrap().is_empty());

        for name in ["anchor.jwk", "signing.jwk", "delegation.json"] {
            let mode = fs::metadata(dir.join(name)).unwrap();
            assert_eq!(
                std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rotate_and_prune() {
        let dir = std::env::temp_dir().join(format!("kuipa-rotate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = KeyStore::new(&dir);
        store.generate().unwrap();
        let before = store.load().unwrap();
        let old_join = *before.join[0].public().kid();
        let old_signing = *before.signing.public().thumbprint();

        let changes = store
            .rotate(Rotation {
                join: true,
                signing: true,
                ..Rotation::default()
            })
            .unwrap();
        assert_eq!(changes.created.len(), 2, "{changes:?}");
        assert_eq!(changes.retired, [format!(".join-{old_join}.jwk")]);
        let after = store.load().unwrap();
        assert_eq!(after.join.len(), 1);
        assert_ne!(after.join[0].public().kid(), &old_join);
        assert!(
            after.join_key(&old_join).is_some(),
            "the old join key is still answered"
        );
        assert_eq!(after.escrow.len(), 1, "escrow keys untouched");
        assert_ne!(after.signing.public().thumbprint(), &old_signing);

        // Escrow keys are kept longer than join keys.
        store
            .rotate(Rotation {
                escrow: true,
                ..Rotation::default()
            })
            .unwrap();
        let pruned = store
            .prune(Duration::ZERO, Duration::from_secs(3600))
            .unwrap();
        assert_eq!(pruned.removed, [format!(".join-{old_join}.jwk")]);
        let keys = store.load().unwrap();
        assert!(keys.join_key(&old_join).is_none());
        assert_eq!(keys.retired.len(), 1, "the retired escrow key stays");
        assert_eq!(
            store
                .prune(Duration::ZERO, Duration::ZERO)
                .unwrap()
                .removed
                .len(),
            1
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
