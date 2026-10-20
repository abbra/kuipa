//! `kuipa seal`: a user's own vaults (§7.6.9).  Runs as the user, with
//! their Kerberos ticket; nothing here needs root.
//!
//! The realm comes from the host's world-readable files (`realm.json`,
//! the pinned anchors, the CA); everything of the user's lives in their
//! data directory (`$KUIPA_USER_DIR`, else `$XDG_DATA_HOME/kuipa`, else
//! `~/.local/share/kuipa`, mode 0700):
//!
//! ```text
//! device.key            the device's ML-KEM key, under the passphrase (IPDK)
//! vaults/<name>.vault   the last signed descriptor of each vault (IPVD)
//! servers.json          the servers' signed advertisements, with when they
//!                       were fetched, for sealing offline
//! ```
//!
//! A re-authentication session (`kuipa seal unlock`) lives in the runtime
//! directory (`$KUIPA_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/kuipa`: tmpfs,
//! the user's own, gone at logout): `sessions/<vault id>` holds the
//! server's session token and the unwrapped device key until the session
//! ends or `kuipa seal lock`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use kuipa_enroll::join::{AuthType, Operation, Prepared};
use kuipa_enroll::keytab::Enctype;
use kuipa_enroll::realm::{Deployment, VerifiedRealm};
use kuipa_enroll::vault::{
    Descriptor, DeviceKey, DeviceType, Policy, SealedVaultFile, SessionToken, TicketSource, Unlock,
    VaultOp, VerifiedDescriptor,
};
use kuipa_gssapi::GssClientCred;
use native_ossl::digest::DigestAlg;
use native_ossl::kdf::Pbkdf2Builder;
use native_ossl::rand::Rand;
use native_ossl::util::SecretBuf;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tang_pqc::primitives;
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{ExchangeKeyPair, KemAlg, SignedAdvertisement, unix_seconds};

use crate::flows::{self, Outcome};
use crate::net::Endpoint;
use crate::paths::{self, Error, Paths, PublicState};

const DEVICE_KEY_MAGIC: [u8; 4] = *b"IPDK";
const SESSION_FILE_MAGIC: [u8; 4] = *b"IPSS";
/// KDF id 1: PBKDF2-HMAC-SHA-512.
const KDF_PBKDF2_SHA512: u8 = 1;
const PBKDF2_ITERATIONS: u64 = 600_000;

/// A user's kuipa data directory.
#[derive(Clone, Debug)]
pub struct UserPaths {
    dir: PathBuf,
}

impl UserPaths {
    /// `$KUIPA_USER_DIR`, `$XDG_DATA_HOME/kuipa`, or `~/.local/share/kuipa`.
    ///
    /// # Errors
    ///
    /// Without any of those variables or `$HOME`.
    pub fn from_env() -> Result<Self, Error> {
        if let Some(d) = std::env::var_os("KUIPA_USER_DIR") {
            return Ok(Self::new(d));
        }
        if let Some(d) = std::env::var_os("XDG_DATA_HOME") {
            return Ok(Self::new(PathBuf::from(d).join("kuipa")));
        }
        let home = std::env::var_os("HOME").ok_or("no $HOME for the kuipa data directory")?;
        Ok(Self::new(PathBuf::from(home).join(".local/share/kuipa")))
    }

    /// The directory `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The device key file.
    #[must_use]
    pub fn device_key(&self) -> PathBuf {
        self.dir.join("device.key")
    }

    fn vaults(&self) -> PathBuf {
        self.dir.join("vaults")
    }

    fn vault(&self, name: &str) -> Result<PathBuf, Error> {
        if name.is_empty()
            || name.starts_with('.')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(
                format!("{name:?} is not a vault name: letters, digits, '.', '_' and '-'").into(),
            );
        }
        Ok(self.vaults().join(format!("{name}.vault")))
    }

    fn servers(&self) -> PathBuf {
        self.dir.join("servers.json")
    }

    /// The runtime directory for sessions: `$KUIPA_RUNTIME_DIR`, else
    /// `$XDG_RUNTIME_DIR/kuipa`.
    fn runtime() -> Result<PathBuf, Error> {
        if let Some(d) = std::env::var_os("KUIPA_RUNTIME_DIR") {
            return Ok(PathBuf::from(d));
        }
        let d = std::env::var_os("XDG_RUNTIME_DIR")
            .ok_or("no $XDG_RUNTIME_DIR to keep a session in (it must not touch a disk)")?;
        Ok(PathBuf::from(d).join("kuipa"))
    }

    fn session(id: &kuipa_enroll::escrow::VaultId) -> Result<PathBuf, Error> {
        Ok(Self::runtime()?.join("sessions").join(id.to_string()))
    }

    /// Write `data` (0600) in the directory, kept at 0700.
    fn write(&self, path: &Path, data: &[u8]) -> Result<(), Error> {
        for dir in [&self.dir, &self.vaults()] {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        paths::write_file(path, data, 0o600)
    }
}

/// The key that derives the device key file's encryption key.
fn passphrase_key(passphrase: &[u8], salt: &[u8], iterations: u64) -> Result<SecretBuf, Error> {
    let md = DigestAlg::fetch(c"SHA2-512", None)?;
    let mut key = SecretBuf::with_len(32);
    Pbkdf2Builder::new(&md, passphrase, salt)
        .iterations(u32::try_from(iterations).map_err(|_| "PBKDF2 iterations out of range")?)
        .derive(key.as_mut_slice())?;
    Ok(key)
}

/// Write `key` to `path` under `passphrase`:
/// `IPDK kdf(1) iterations(u64) salt(16) GCM_{PBKDF2(passphrase, salt)}(private JWK)`.
fn write_device_key(
    user: &UserPaths,
    key: &ExchangeKeyPair,
    passphrase: &[u8],
) -> Result<(), Error> {
    let mut salt = [0u8; 16];
    Rand::fill(&mut salt)?;
    let sealing = passphrase_key(passphrase, &salt, PBKDF2_ITERATIONS)?;
    let sealed = primitives::seal(sealing.as_ref(), key.to_jwk()?.as_ref())?;
    let bytes = Writer::new(DEVICE_KEY_MAGIC)
        .u8(KDF_PBKDF2_SHA512)
        .u64(PBKDF2_ITERATIONS)
        .fixed(&salt)
        .bytes(&sealed)
        .finish();
    user.write(&user.device_key(), &bytes)
}

/// Read the device key under `passphrase`.
///
/// # Errors
///
/// No device key, a wrong passphrase, or a malformed file.
pub fn read_device_key(user: &UserPaths, passphrase: &[u8]) -> Result<ExchangeKeyPair, Error> {
    let bytes = fs::read(user.device_key())
        .map_err(|_| "this host has no device key: run `kuipa seal device add VAULT` first")?;
    let mut r = Reader::new(&bytes, DEVICE_KEY_MAGIC, "device key")?;
    if r.u8()? != KDF_PBKDF2_SHA512 {
        return Err("device key: unknown key derivation".into());
    }
    let iterations = r.u64()?;
    let salt: [u8; 16] = r.fixed()?;
    let sealed = r.bytes()?.to_vec();
    r.finish()?;
    let sealing = passphrase_key(passphrase, &salt, iterations)?;
    let jwk = primitives::open(sealing.as_ref(), &sealed).map_err(|_| "wrong passphrase")?;
    Ok(ExchangeKeyPair::from_jwk(jwk.as_ref())?)
}

/// One cached advertisement.
#[derive(Serialize, Deserialize)]
struct CachedAdvertisement {
    server: String,
    fetched: u64,
    advertisement: String,
}

/// A user's view of the host's realm and their own vaults.
pub struct Seal<'a> {
    host: &'a Paths,
    user: &'a UserPaths,
    ccache: Option<&'a str>,
}

impl<'a> Seal<'a> {
    /// Use the host's realm files under `host`, the user's directory, and
    /// the ticket in `ccache` (else the default ccache, `KRB5CCNAME`).
    #[must_use]
    pub fn new(host: &'a Paths, user: &'a UserPaths, ccache: Option<&'a str>) -> Self {
        Self { host, user, ccache }
    }

    fn public(&self) -> Result<PublicState, Error> {
        PublicState::load(self.host)
    }

    fn cred(&self) -> Result<GssClientCred, Error> {
        Ok(match self.ccache {
            Some(name) => GssClientCred::from_named_ccache(name)?,
            None => GssClientCred::ambient()?,
        })
    }

    /// Run `op` against the realm, authenticated by the user's ticket, and
    /// keep the descriptors it answers with.
    fn op(&self, op: &VaultOp) -> Result<Vec<VerifiedDescriptor>, Error> {
        Ok(self.op_with_session(op)?.0)
    }

    fn op_with_session(
        &self,
        op: &VaultOp,
    ) -> Result<(Vec<VerifiedDescriptor>, Option<SessionToken>), Error> {
        let public = self.public()?;
        let anchors = paths::read_anchors(self.host)?;
        let known = paths::read_epoch_from(&self.host.anchors())?;
        let trust = flows::ca_trust(self.host)?;
        let cred = self.cred()?;
        let extra = op.to_bytes();
        let (reply, _) = flows::exchange_with(
            &Deployment::servers(&public.servers),
            &trust,
            &public.realm,
            &anchors,
            known,
            Operation::Vault,
            |adv| {
                let p = Prepared::new(
                    adv,
                    Operation::Vault,
                    &public.fqdn,
                    AuthType::Kerberos,
                    &Enctype::DEFAULT,
                )?;
                let target = format!("ipa-ku@{}", adv.server());
                let (token, binding) = flows::gss_token(&cred, &target, &p.channel_binding()?)?;
                Ok(p.with_kerberos(binding).seal(&token, &[], &extra)?)
            },
            |pending, response, adv| Ok(pending.finish_vault(response, adv)?),
        )?;
        let mut verified = Vec::with_capacity(reply.descriptors.len());
        for d in reply.descriptors {
            let v = d.verify(&public.realm, &anchors, &tang_pqc::Policy::default())?;
            self.user
                .write(&self.user.vault(&v.vault().name)?, &d.to_bytes())?;
            verified.push(v);
        }
        Ok((verified, reply.session))
    }

    /// `kuipa seal unlock`: start a re-authentication session for this
    /// host's device in vault `name`: until it ends, files open without
    /// the passphrase or a ticket.
    ///
    /// # Errors
    ///
    /// A wrong passphrase, a policy without sessions, no runtime
    /// directory, or any other error.
    pub fn unlock(&self, name: &str, passphrase: &[u8]) -> Result<Value, Error> {
        let key = read_device_key(self.user, passphrase)?;
        let (vaults, session) = self.op_with_session(&VaultOp::Unlock {
            name: name.into(),
            device: key.public().kid().to_string(),
        })?;
        let session = session.ok_or("the server started no session")?;
        let path = UserPaths::session(session.vault())?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
            for d in [dir, dir.parent().unwrap_or(dir)] {
                fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
            }
        }
        let bytes = Writer::new(SESSION_FILE_MAGIC)
            .bytes(&session.to_bytes())
            .bytes(key.to_jwk()?.as_ref())
            .finish();
        paths::write_file(&path, &bytes, 0o600)?;
        Ok(json!({
            "vaults": vaults.iter().map(describe).collect::<Vec<_>>(),
            "session_until": session.not_after(),
        }))
    }

    /// `kuipa seal lock`: end vault `name`'s session on this host.
    ///
    /// # Errors
    ///
    /// No stored descriptor of the vault, or I/O errors.
    pub fn lock(&self, name: &str) -> Result<Value, Error> {
        let id = self
            .stored(name)?
            .ok_or_else(|| format!("no vault {name:?} known here"))?
            .vault()
            .id;
        paths::remove(&UserPaths::session(&id)?)?;
        Ok(json!({ "locked": name }))
    }

    /// The live session of vault `id`, if any; an ended one is removed.
    fn session_for(id: &kuipa_enroll::escrow::VaultId) -> Option<(SessionToken, ExchangeKeyPair)> {
        let path = UserPaths::session(id).ok()?;
        let bytes = fs::read(&path).ok()?;
        let parsed = (|| -> Result<_, Error> {
            let mut r = Reader::new(&bytes, SESSION_FILE_MAGIC, "session")?;
            let token = SessionToken::from_bytes(r.bytes()?)?;
            let key = ExchangeKeyPair::from_jwk(r.bytes()?)?;
            r.finish()?;
            Ok((token, key))
        })();
        match parsed {
            Ok((token, key)) if token.not_after() >= unix_seconds(flows::now()) => {
                Some((token, key))
            }
            _ => {
                let _ = paths::remove(&path);
                None
            }
        }
    }

    /// Whether `sealed` can open in a live session, without a passphrase.
    #[must_use]
    pub fn in_session(sealed: &[u8]) -> bool {
        SealedVaultFile::from_bytes(sealed)
            .ok()
            .and_then(|f| Self::session_for(f.vault()))
            .is_some()
    }

    /// The stored descriptor of vault `name`, verified.
    fn stored(&self, name: &str) -> Result<Option<VerifiedDescriptor>, Error> {
        let Ok(bytes) = fs::read(self.user.vault(name)?) else {
            return Ok(None);
        };
        let public = self.public()?;
        let anchors = paths::read_anchors(self.host)?;
        Ok(Some(Descriptor::from_bytes(&bytes)?.verify(
            &public.realm,
            &anchors,
            &tang_pqc::Policy::default(),
        )?))
    }

    /// Vault `name`'s descriptor, fresh enough to seal with: the stored
    /// one, else one fetched now.
    fn descriptor(&self, name: &str) -> Result<VerifiedDescriptor, Error> {
        let now = unix_seconds(flows::now());
        if let Some(d) = self.stored(name)?
            && d.fresh_at(now)
        {
            return Ok(d);
        }
        let fetched = self.op(&VaultOp::Show { name: name.into() }).map_err(|e| {
            format!("vault {name:?}: no descriptor recent enough to seal with, and fetching one failed: {e}")
        })?;
        fetched
            .into_iter()
            .next()
            .ok_or_else(|| format!("no vault {name:?}").into())
    }

    /// Fetch and verify every server's advertisement, and cache them.
    fn refresh_servers(&self) -> Result<Vec<VerifiedRealm>, Error> {
        let public = self.public()?;
        let anchors = paths::read_anchors(self.host)?;
        let known = paths::read_epoch_from(&self.host.anchors())?;
        let trust = flows::ca_trust(self.host)?;
        let mut pins = anchors.clone();
        pins.sort_unstable();
        pins.dedup();
        let now = unix_seconds(flows::now());
        let mut cache = Vec::new();
        let mut verified = Vec::new();
        for server in &public.servers {
            let Ok((endpoint, v, _)) =
                flows::verified(server, &trust, &public.realm, &anchors, known)
            else {
                continue;
            };
            if let Ok(adv) = endpoint.advertisement(&pins) {
                cache.push(CachedAdvertisement {
                    server: server.clone(),
                    fetched: now,
                    advertisement: adv.to_json(),
                });
            }
            verified.push(v);
        }
        if verified.is_empty() {
            return Err(Outcome::RetryLater("no server of the realm answered".into()).into());
        }
        self.user
            .write(&self.user.servers(), &serde_json::to_vec_pretty(&cache)?)?;
        Ok(verified)
    }

    /// The cached advertisements, verified as of when they were fetched,
    /// and no older than `max_age`.
    fn cached_servers(&self, max_age: u64) -> Result<Vec<VerifiedRealm>, Error> {
        let Ok(bytes) = fs::read(self.user.servers()) else {
            return Ok(Vec::new());
        };
        let cache: Vec<CachedAdvertisement> = serde_json::from_slice(&bytes)?;
        let public = self.public()?;
        let anchors = paths::read_anchors(self.host)?;
        let now = unix_seconds(flows::now());
        Ok(cache
            .iter()
            .filter(|c| now.saturating_sub(c.fetched) <= max_age)
            .filter_map(|c| {
                let adv = SignedAdvertisement::from_json(c.advertisement.as_bytes()).ok()?;
                let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(c.fetched);
                VerifiedRealm::verify(
                    &adv,
                    &public.realm,
                    &anchors,
                    &tang_pqc::Policy::default(),
                    at,
                )
                .ok()
            })
            .collect())
    }

    /// `kuipa seal create`.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn create(&self, name: &str, policy: Policy) -> Result<Value, Error> {
        self.user.vault(name)?;
        let v = self.op(&VaultOp::Create {
            name: name.into(),
            policy,
        })?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal policy`.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn set_policy(&self, name: &str, policy: Policy) -> Result<Value, Error> {
        let v = self.op(&VaultOp::SetPolicy {
            name: name.into(),
            policy,
        })?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal device add`: register this host's device key (made now
    /// under `passphrase` if there is none) in vault `name`.
    ///
    /// # Errors
    ///
    /// A wrong passphrase for an existing key, a refusal, or any other
    /// error.
    pub fn add_device(&self, name: &str, passphrase: &[u8]) -> Result<Value, Error> {
        let key = if self.user.device_key().exists() {
            read_device_key(self.user, passphrase)?
        } else {
            let key = ExchangeKeyPair::generate(KemAlg::MlKem768)?;
            write_device_key(self.user, &key, passphrase)?;
            key
        };
        let public = self.public()?;
        let v = self.op(&VaultOp::AddDevice {
            name: name.into(),
            label: public.fqdn,
            kind: DeviceType::File,
            alg: key.public().alg().id(),
            key: tang_pqc::b64::encode(key.public().as_bytes()),
        })?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal device remove`.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn remove_device(&self, name: &str, id: &str) -> Result<Value, Error> {
        let v = self.op(&VaultOp::RemoveDevice {
            name: name.into(),
            id: id.into(),
        })?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal revoke`.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn revoke(&self, name: &str) -> Result<Value, Error> {
        let v = self.op(&VaultOp::Revoke { name: name.into() })?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal show`.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn show(&self, name: &str) -> Result<Value, Error> {
        let v = self.op(&VaultOp::Show { name: name.into() })?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal list`.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn list(&self) -> Result<Value, Error> {
        let v = self.op(&VaultOp::List)?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal file`: seal `contents` to vault `name`, offline when the
    /// stored descriptor and advertisements are recent enough.
    ///
    /// # Errors
    ///
    /// A revoked vault, no device registered when the policy needs one, no
    /// server known, or any other error.
    pub fn seal(&self, name: &str, contents: &[u8]) -> Result<Vec<u8>, Error> {
        let descriptor = self.descriptor(name)?;
        // The realm's descriptor age bounds the advertisements too.
        let mut servers = self.cached_servers(descriptor.max_age())?;
        if servers.is_empty() {
            servers = self.refresh_servers()?;
        }
        let refs: Vec<_> = servers.iter().collect();
        Ok(SealedVaultFile::seal(&descriptor, &refs, contents)?.to_bytes())
    }

    /// `kuipa seal open`: open a sealed file with this host's device key
    /// (under `passphrase`, when the file has device shares) and the
    /// user's ticket, when one is available.
    ///
    /// # Errors
    ///
    /// No device key or a wrong passphrase, [`Outcome::RetryLater`] when no
    /// server would open it, or a malformed file.
    pub fn open(&self, sealed: &[u8], passphrase: Option<&[u8]>) -> Result<SecretBuf, Error> {
        let file = SealedVaultFile::from_bytes(sealed)?;
        let session = Self::session_for(file.vault());
        let unwrapped;
        let device = if let Some((_, key)) = &session {
            Some(key)
        } else if file.devices().is_empty() {
            None
        } else {
            let passphrase =
                passphrase.ok_or("the file needs this host's device key: give its passphrase")?;
            unwrapped = read_device_key(self.user, passphrase)?;
            Some(&unwrapped)
        };
        let trust = flows::ca_trust(self.host)?;
        // A ticket is sent whenever one is available: vaults that do not
        // ask for it ignore it.
        let cred = self.cred().ok();
        let mut make_token = |server: &str, cb: &[u8; 32]| {
            let cred = cred.as_ref()?;
            flows::gss_token(cred, &format!("ipa-ku@{server}"), cb)
                .ok()
                .map(|(t, _)| t)
        };
        let ticket: Option<TicketSource<'_>> = if cred.is_some() && session.is_none() {
            Some(&mut make_token)
        } else {
            None
        };
        file.open(
            Unlock {
                device: device.map(|k| k as &dyn DeviceKey),
                session: session.as_ref().map(|(t, _)| t),
                ticket,
            },
            |server, request| {
                tracing::debug!(
                    server = %server,
                    "vault unlock for {} in vault {}",
                    request.principal(),
                    request.vault()
                );
                Endpoint::new(server, &trust)
                    .ok()?
                    .post(
                        &format!("rec/{}", request.recovery().kid()),
                        request.to_bytes(),
                    )
                    .ok()
            },
        )
        .map_err(|e| match e {
            kuipa_enroll::Error::Refused => Outcome::RetryLater(
                "no server would open it: the vault's policy refused, or no server answered".into(),
            )
            .into(),
            e => e.into(),
        })
    }

    /// `kuipa seal reseal`: open each file and seal it again to the
    /// vault's current devices.
    ///
    /// # Errors
    ///
    /// As for [`open`](Self::open) and [`seal`](Self::seal).
    pub fn reseal(
        &self,
        name: &str,
        sealed: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let plain = self.open(sealed, passphrase)?;
        self.seal(name, plain.as_ref())
    }
}

/// The JSON form of a vault, for `--json` and the renderer.
#[must_use]
pub fn describe(v: &VerifiedDescriptor) -> Value {
    let vault = v.vault();
    json!({
        "name": vault.name,
        "id": vault.id.to_string(),
        "owner": vault.owner,
        "state": vault.state,
        "policy": vault.policy,
        "devices": vault.devices.iter().map(|d| json!({
            "id": d.id, "label": d.label, "type": d.kind, "level": d.level,
        })).collect::<Vec<_>>(),
        "unlocks": vault.unlocks,
        "signed_by": v.server(),
        "signed_at": v.iat(),
    })
}

fn describe_all(v: &[VerifiedDescriptor]) -> Value {
    json!({ "vaults": v.iter().map(describe).collect::<Vec<_>>() })
}
