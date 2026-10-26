//! `kuipa seal`: a user's own vaults (§7.6.9).  Runs as the user, with
//! their Kerberos ticket; nothing here needs root.
//!
//! The realm comes from the host's world-readable files (`realm.json`,
//! the pinned anchors, the CA); everything of the user's lives in their
//! data directory (`$KUIPA_USER_DIR`, else `$XDG_DATA_HOME/kuipa`, else
//! `~/.local/share/kuipa`, mode 0700):
//!
//! ```text
//! device.key            the device's ML-KEM key, under the passphrase or
//!                       a passkey's hmac-secret (IPDK)
//! vaults/<name>.vault   the last signed descriptor of each vault (IPVD)
//! servers.json          the servers' signed advertisements, with when they
//!                       were fetched, for sealing offline
//! passkeys.json         the user's IPA passkeys, as the realm last listed
//!                       them, for the passkey factor's allow list
//! ```
//!
//! `vaults/<name>.tlog` holds what `kuipa tlog watch` last verified of
//! each server's transparency log for that vault (DESIGN-tlog.md §7).
//!
//! A re-authentication session (`kuipa seal unlock`) lives in the runtime
//! directory (`$KUIPA_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/kuipa`: tmpfs,
//! the user's own, gone at logout): `sessions/<vault id>` holds the
//! server's session token and the unwrapped device key until the session
//! ends or `kuipa seal lock`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use kuipa_enroll::join::{AuthType, Operation, Prepared};
use kuipa_enroll::keytab::Enctype;
use kuipa_enroll::passkey::PasskeyInfo;
use kuipa_enroll::realm::{Deployment, VerifiedRealm};
use kuipa_enroll::vault::{
    Descriptor, DeviceKey, DeviceType, Policy, SealedVaultFile, SessionSealedFile, SessionToken,
    TicketSource, Unlock, VaultOp, VerifiedDescriptor,
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
use tang_pqc::{ExchangeKeyPair, KemAlg, SignedAdvertisement, Thumbprint, unix_seconds};

use crate::flows::{self, Outcome};
use crate::net::Endpoint;
use crate::passkey::{Authenticator, Fido2, pin_of};
use crate::paths::{self, Error, Paths, PublicState};

const DEVICE_KEY_MAGIC: [u8; 4] = *b"IPDK";
const SESSION_FILE_MAGIC: [u8; 4] = *b"IPSS";
/// KDF id 1: PBKDF2-HMAC-SHA-512.
const KDF_PBKDF2_SHA512: u8 = 1;
/// KDF id 2: a passkey's `hmac-secret` output, through HKDF (§7.6.2).
const KDF_FIDO2_HMAC_SECRET: u8 = 2;
const PBKDF2_ITERATIONS: u64 = 600_000;
/// How long the user's listed passkeys are used before asking again.
const PASSKEYS_MAX_AGE: u64 = 3600;

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

    /// The servers' advertisements kept between runs, when this user may
    /// not write the host's (`net::cache_advertisements_in`).
    #[must_use]
    pub fn advertisements(&self) -> PathBuf {
        self.dir.join("advertisements")
    }

    /// A lost host's device key, recovered here until `kuipa seal recover
    /// finish --retire-old` (`DESIGN-recovery.md` §2).
    #[must_use]
    pub fn recovered_key(&self) -> PathBuf {
        self.dir.join("recovered.key")
    }

    /// The recovered key under `secret`, if there is one.
    fn recovered(
        &self,
        secret: &[u8],
        auth: &dyn Authenticator,
    ) -> Result<Option<ExchangeKeyPair>, Error> {
        match fs::read(self.recovered_key()) {
            Ok(bytes) => Ok(Some(unprotect_any(&bytes, secret, auth)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// The device to open a file with device slots `ids`: the recovered
    /// key when the file has a slot for it, else this host's device.
    fn device_for(
        &self,
        ids: &[Thumbprint],
        secret: &[u8],
        auth: &dyn Authenticator,
    ) -> Result<HostDevice, Error> {
        if let Some(old) = self.recovered(secret, auth)?
            && ids.contains(old.public().kid())
        {
            return Ok(HostDevice::File(old));
        }
        self.device(secret, auth)
    }

    /// The passkey this host's device key is wrapped by, if it is.
    fn passkey_wrap(&self) -> Option<PasskeyWrap> {
        let bytes = fs::read(self.device_key()).ok()?;
        PasskeyWrap::of(&bytes)
    }

    /// Whether this host's device key is wrapped by a passkey: its
    /// secret is the security key's PIN, which may be empty.
    #[must_use]
    pub fn passkey_device(&self) -> bool {
        self.passkey_wrap().is_some()
    }

    /// `key` protected as this host's keys are: under the passkey that
    /// wraps the device key, else under the passphrase `secret`.
    fn protect(
        &self,
        key: &ExchangeKeyPair,
        secret: &[u8],
        auth: &dyn Authenticator,
    ) -> Result<Vec<u8>, Error> {
        match self.passkey_wrap() {
            Some(wrap) => protect_with_passkey(key, &wrap, pin_of(secret)?, auth),
            None => protect_key(key, secret),
        }
    }

    /// The user's passkeys as last listed.
    fn passkeys(&self) -> PathBuf {
        self.dir.join("passkeys.json")
    }

    fn vaults(&self) -> PathBuf {
        self.dir.join("vaults")
    }

    /// The stored descriptor of the vault `reference` names in `realm`.
    fn vault(&self, reference: &str, realm: &str) -> Result<PathBuf, Error> {
        Ok(self
            .vaults()
            .join(format!("{}.vault", local_name(reference, realm)?)))
    }

    fn servers(&self) -> PathBuf {
        self.dir.join("servers.json")
    }

    /// The token device's location, when this host's device is a token.
    #[must_use]
    pub fn token_device(&self) -> PathBuf {
        self.dir.join("device.pkcs11")
    }

    fn token(&self) -> Option<TokenConfig> {
        serde_json::from_slice(&fs::read(self.token_device()).ok()?).ok()
    }

    /// This host's device under `secret` (the file's passphrase, or the
    /// PIN of the token or of the security key whose passkey wraps it).
    fn device(&self, secret: &[u8], auth: &dyn Authenticator) -> Result<HostDevice, Error> {
        if let Some(t) = self.token() {
            return Ok(HostDevice::Token(crate::pkcs11::TokenKey::open(
                &t.module,
                &t.uri,
                secret,
                &Self::runtime().unwrap_or_else(|_| self.dir.clone()),
            )?));
        }
        let bytes = fs::read(self.device_key())
            .map_err(|_| "this host has no device key: run `kuipa seal device add VAULT` first")?;
        Ok(HostDevice::File(unprotect_any(&bytes, secret, auth)?))
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
    let md = DigestAlg::fetch(tang_pqc::primitives::SHA512, None)?;
    let mut key = SecretBuf::with_len(32);
    Pbkdf2Builder::new(&md, passphrase, salt)
        .iterations(u32::try_from(iterations).map_err(|_| "PBKDF2 iterations out of range")?)
        .derive(key.as_mut_slice())?;
    Ok(key)
}

/// `key` under `secret` (a passphrase or a recovery code):
/// `IPDK kdf(1) iterations(u64) salt(16) GCM_{PBKDF2(secret, salt)}(private JWK)`.
fn protect_key(key: &ExchangeKeyPair, secret: &[u8]) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; 16];
    Rand::fill(&mut salt)?;
    let sealing = passphrase_key(secret, &salt, PBKDF2_ITERATIONS)?;
    let sealed = primitives::seal(sealing.as_ref(), key.to_jwk()?.as_ref())?;
    Ok(Writer::new(DEVICE_KEY_MAGIC)
        .u8(KDF_PBKDF2_SHA512)
        .u64(PBKDF2_ITERATIONS)
        .fixed(&salt)
        .bytes(&sealed)
        .finish())
}

/// Write `key` to the device key file under `passphrase`.
fn write_device_key(
    user: &UserPaths,
    key: &ExchangeKeyPair,
    passphrase: &[u8],
) -> Result<(), Error> {
    user.write(&user.device_key(), &protect_key(key, passphrase)?)
}

/// Read the device key under `passphrase`.
///
/// # Errors
///
/// No device key, a wrong passphrase, or a malformed file.
pub fn read_device_key(user: &UserPaths, passphrase: &[u8]) -> Result<ExchangeKeyPair, Error> {
    let bytes = fs::read(user.device_key())
        .map_err(|_| "this host has no device key: run `kuipa seal device add VAULT` first")?;
    unprotect_key(&bytes, passphrase)
}

/// The key `protect_key` protected under `secret`.
fn unprotect_key(bytes: &[u8], secret: &[u8]) -> Result<ExchangeKeyPair, Error> {
    let mut r = Reader::new(bytes, DEVICE_KEY_MAGIC, "device key")?;
    if r.u8()? != KDF_PBKDF2_SHA512 {
        return Err("device key: unknown key derivation".into());
    }
    let iterations = r.u64()?;
    let salt: [u8; 16] = r.fixed()?;
    let sealed = r.bytes()?.to_vec();
    r.finish()?;
    let sealing = passphrase_key(secret, &salt, iterations)?;
    let jwk = primitives::open(sealing.as_ref(), &sealed).map_err(|_| "wrong passphrase")?;
    Ok(ExchangeKeyPair::from_jwk(jwk.as_ref())?)
}

/// The passkey a key file is wrapped by: its relying party, credential,
/// and whether the user was verified when it was wrapped (`hmac-secret`
/// answers differently with and without).
struct PasskeyWrap {
    rp_id: String,
    credential_id: Vec<u8>,
    uv: bool,
}

impl PasskeyWrap {
    /// The wrap of a key file, if a passkey wraps it.
    fn of(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes, DEVICE_KEY_MAGIC, "device key").ok()?;
        if r.u8().ok()? != KDF_FIDO2_HMAC_SECRET {
            return None;
        }
        Some(Self {
            rp_id: r.str().ok()?.to_owned(),
            credential_id: r.bytes().ok()?.to_vec(),
            uv: r.u8().ok()? != 0,
        })
    }

    /// The key that encrypts the file: `HKDF(hmac-secret(salt), "passkey
    /// device key", salt ‖ credential id)`, the passkey's answer for
    /// `salt`, which only it gives.
    fn sealing_key(
        &self,
        salt: &[u8; 32],
        pin: Option<&str>,
        auth: &dyn Authenticator,
    ) -> Result<SecretBuf, Error> {
        // The challenge is checked by nobody: only the hmac-secret counts.
        let mut cdh = [0u8; 32];
        Rand::fill(&mut cdh)?;
        // A PIN verifies the user, which changes the answer: give it only
        // when the key was wrapped with one.
        let answer = auth.assert(
            &kuipa_fido2::AssertionRequest {
                rp_id: &self.rp_id,
                client_data_hash: &cdh,
                allow: std::slice::from_ref(&self.credential_id),
                user_verification: self.uv,
                hmac_salt: Some(salt),
            },
            pin.filter(|_| self.uv),
        )?;
        let secret = answer
            .hmac_secret
            .ok_or("the security key gave no hmac-secret")?;
        Ok(kuipa_enroll::vault::DOMAIN.derive_key(
            primitives::SHA256,
            &[secret.as_ref()],
            "passkey device key",
            &[salt, &self.credential_id],
        )?)
    }
}

/// `key` wrapped by the passkey `wrap` (one touch):
/// `IPDK kdf(2) rp_id credential_id uv(u8) salt(32) GCM_k(private JWK)`.
fn protect_with_passkey(
    key: &ExchangeKeyPair,
    wrap: &PasskeyWrap,
    pin: Option<&str>,
    auth: &dyn Authenticator,
) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; 32];
    Rand::fill(&mut salt)?;
    let sealing = wrap.sealing_key(&salt, pin, auth)?;
    let sealed = primitives::seal(sealing.as_ref(), key.to_jwk()?.as_ref())?;
    Ok(Writer::new(DEVICE_KEY_MAGIC)
        .u8(KDF_FIDO2_HMAC_SECRET)
        .str(&wrap.rp_id)
        .bytes(&wrap.credential_id)
        .u8(u8::from(wrap.uv))
        .fixed(&salt)
        .bytes(&sealed)
        .finish())
}

/// The key in a key file under `secret`: a passphrase, or for a
/// passkey-wrapped one the security key's PIN (one touch).
fn unprotect_any(
    bytes: &[u8],
    secret: &[u8],
    auth: &dyn Authenticator,
) -> Result<ExchangeKeyPair, Error> {
    let Some(wrap) = PasskeyWrap::of(bytes) else {
        return unprotect_key(bytes, secret);
    };
    let mut r = Reader::new(bytes, DEVICE_KEY_MAGIC, "device key")?;
    r.u8()?;
    r.str()?;
    r.bytes()?;
    r.u8()?;
    let salt: [u8; 32] = r.fixed()?;
    let sealed = r.bytes()?.to_vec();
    r.finish()?;
    let sealing = wrap.sealing_key(&salt, pin_of(secret)?, auth)?;
    let jwk = primitives::open(sealing.as_ref(), &sealed).map_err(
        |_| "the security key does not open this device key (another key, or another PIN setting)",
    )?;
    Ok(ExchangeKeyPair::from_jwk(jwk.as_ref())?)
}

/// The base32 alphabet of RFC 4648.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A new recovery code: 128 random bits as 26 base32 characters, in
/// groups of four for writing down (`DESIGN-recovery.md` §2).
fn new_recovery_code() -> Result<String, Error> {
    let mut bits = [0u8; 16];
    Rand::fill(&mut bits)?;
    let n = u128::from_be_bytes(bits);
    // 26 characters carry 130 bits: the first holds the top 3.
    let chars: Vec<u8> = (0..26)
        .rev()
        .map(|i| BASE32[usize::try_from((n >> (5 * i)) & 31).unwrap_or(0)])
        .collect();
    Ok(chars
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-"))
}

/// The secret a recovery code stands for: its 26 characters, upper case,
/// without the dashes and spaces it was written down with.
fn recovery_secret(code: &str) -> Result<SecretBuf, Error> {
    let bare: Vec<u8> = code
        .bytes()
        .filter(|b| !b"- \t".contains(b))
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if bare.len() != 26 || !bare.iter().all(|b| BASE32.contains(b)) {
        return Err("a recovery code is 26 letters and digits 2-7".into());
    }
    Ok(SecretBuf::new(bare))
}

/// A live session on this host: the server's token, the unwrapped device
/// key (a file device's; a token's never leaves the token), and for an
/// offline session the vault's released epoch keys.
struct LiveSession {
    token: SessionToken,
    key: Option<ExchangeKeyPair>,
    epochs: Vec<(u64, ExchangeKeyPair)>,
}

/// Makes a vault operation, encoded, for the exchange whose channel
/// binding it is given.
type MakeOp<'a> = &'a mut dyn FnMut(&[u8; 32]) -> Result<Vec<u8>, Error>;

/// The user's passkeys as the realm last listed them, and when.
#[derive(Serialize, Deserialize)]
struct CachedPasskeys {
    fetched: u64,
    info: PasskeyInfo,
}

/// Where this host's token device is: its PKCS#11 module and key URI.
#[derive(Serialize, Deserialize)]
struct TokenConfig {
    module: PathBuf,
    uri: String,
}

/// This host's device key: a passphrase-protected file, or a token.
enum HostDevice {
    File(ExchangeKeyPair),
    Token(crate::pkcs11::TokenKey),
}

impl HostDevice {
    fn public(&self) -> &tang_pqc::ExchangeKey {
        match self {
            Self::File(k) => k.public(),
            Self::Token(t) => t.public(),
        }
    }

    fn as_device(&self) -> &dyn DeviceKey {
        match self {
            Self::File(k) => k,
            Self::Token(t) => t,
        }
    }
}

/// The file name, without extension, of what the user keeps of the vault
/// `reference` names: `NAME` for their own vault, `NAME@OWNER` (the
/// owner's principal, `/` written `+`) for `OWNER/NAME`, one shared with
/// them.
fn local_name(reference: &str, realm: &str) -> Result<String, Error> {
    let (owner, name) = kuipa_enroll::vault::split_ref(reference);
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
    let Some(owner) = owner else {
        return Ok(name.to_owned());
    };
    let owner = if owner.contains('@') {
        owner.replace('/', "+")
    } else {
        format!("{}@{realm}", owner.replace('/', "+"))
    };
    if owner.starts_with(['.', '@'])
        || !owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@+".contains(&b))
    {
        return Err(format!("{owner:?} is not a vault owner").into());
    }
    Ok(format!("{name}@{owner}"))
}

/// The reference `me` uses for `vault`: its name if `me` owns it (or is
/// not known), else `OWNER/NAME`.
fn reference_for(vault: &kuipa_enroll::vault::Vault, me: Option<&str>) -> String {
    if me.is_none_or(|me| me == vault.owner) {
        vault.name.clone()
    } else {
        format!("{}/{}", vault.owner, vault.name)
    }
}

/// The vault a sealed file (either format) belongs to.
fn vault_of(sealed: &[u8]) -> Option<kuipa_enroll::escrow::VaultId> {
    if sealed.starts_with(b"IPUS") {
        SessionSealedFile::from_bytes(sealed)
            .ok()
            .map(|f| *f.vault())
    } else {
        SealedVaultFile::from_bytes(sealed).ok().map(|f| *f.vault())
    }
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
    credential: Credential<'a>,
    authenticator: &'a dyn Authenticator,
    passkey_pin: Option<SecretBuf>,
}

/// Whose ticket a vault operation carries.
#[derive(Clone, Copy)]
enum Credential<'a> {
    /// The user's: the ticket in this ccache, else the default one.
    Ccache(Option<&'a str>),
    /// A keytab's principal: this keytab's, else the host's.
    Keytab(Option<&'a Path>),
}

/// What `op_with_session` answers: the descriptors, verified, and the rest
/// of the server's reply (its own descriptors moved out).
struct OpAnswer {
    vaults: Vec<VerifiedDescriptor>,
    reply: kuipa_enroll::vault::Reply,
}

impl<'a> Seal<'a> {
    /// Use the host's realm files under `host`, the user's directory, and
    /// the ticket in `ccache` (else the default ccache, `KRB5CCNAME`).
    #[must_use]
    pub fn new(host: &'a Paths, user: &'a UserPaths, ccache: Option<&'a str>) -> Self {
        Self {
            host,
            user,
            credential: Credential::Ccache(ccache),
            authenticator: &Fido2,
            passkey_pin: None,
        }
    }

    /// Ask `authenticator` for passkey assertions instead of the security
    /// keys attached to the host.
    #[must_use]
    pub fn with_authenticator(mut self, authenticator: &'a dyn Authenticator) -> Self {
        self.authenticator = authenticator;
        self
    }

    /// Verify the user to the security key with `pin` for the passkey
    /// factor (empty for none).  Without it, a host whose device key a
    /// passkey wraps uses the device's PIN.
    #[must_use]
    pub fn with_passkey_pin(mut self, pin: SecretBuf) -> Self {
        self.passkey_pin = Some(pin);
        self
    }

    /// As the principal of `keytab` (a service's or a user's), or without
    /// one as the host itself, with a ticket from that keytab and the kuipa
    /// directory `user` (`kuipa escrow`, run as root).
    #[must_use]
    pub fn for_keytab(host: &'a Paths, user: &'a UserPaths, keytab: Option<&'a Path>) -> Self {
        Self {
            host,
            user,
            credential: Credential::Keytab(keytab),
            authenticator: &Fido2,
            passkey_pin: None,
        }
    }

    fn public(&self) -> Result<PublicState, Error> {
        PublicState::load(self.host)
    }

    fn cred(&self) -> Result<GssClientCred, Error> {
        Ok(match self.credential {
            Credential::Ccache(Some(name)) => GssClientCred::from_named_ccache(name)?,
            Credential::Ccache(None) => GssClientCred::ambient()?,
            Credential::Keytab(keytab) => flows::keytab_cred(self.host, keytab)?,
        })
    }

    /// Run `op` against the realm, authenticated by the user's ticket, and
    /// keep the descriptors it answers with.
    fn op(&self, op: &VaultOp) -> Result<Vec<VerifiedDescriptor>, Error> {
        Ok(self.op_with_session(op)?.vaults)
    }

    fn op_with_session(&self, op: &VaultOp) -> Result<OpAnswer, Error> {
        let extra = op.to_bytes();
        self.op_bound(&mut |_| Ok(extra.clone()))
    }

    /// As [`op_with_session`](Self::op_with_session), the operation made
    /// for each exchange from its channel binding (`make(cb)`, encoded),
    /// for an operation that carries something bound to the exchange.
    fn op_bound(&self, make: MakeOp<'_>) -> Result<OpAnswer, Error> {
        let public = self.public()?;
        // This host's pins, windows and freezes included (§1.4, §2): a
        // vault descriptor is fetched through a verified advertisement,
        // and a frozen pin must not fall back to a signature here.
        let (anchors, heads, retired, frozen) = paths::pinned_windows(&self.host.anchors())?;
        let known = paths::read_epoch_from(&self.host.anchors())?;
        let trust = flows::ca_trust(self.host)?;
        let cred = self.cred()?;
        let me = cred.principal_name();
        let (reply, _) = flows::exchange_with(
            &Deployment::servers(&public.servers),
            &trust,
            flows::Pins {
                realm: &public.realm,
                anchors: &anchors,
                heads: &heads,
                retired: &retired,
                frozen: &frozen,
            },
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
                let cb = p.channel_binding()?;
                let extra = make(&cb)?;
                let (token, binding) = flows::gss_token(&cred, &target, &cb)?;
                Ok(p.with_kerberos(binding).seal(&token, &[], &extra)?)
            },
            |pending, response, adv| Ok(pending.finish_vault(response, adv)?),
        )?;
        let mut reply = reply;
        let mut verified = Vec::with_capacity(reply.descriptors.len());
        for d in std::mem::take(&mut reply.descriptors) {
            let v = d.verify(&public.realm, &anchors, &tang_pqc::Policy::from_system()?)?;
            let reference = reference_for(v.vault(), me.as_deref());
            self.user
                .write(&self.user.vault(&reference, &public.realm)?, &d.to_bytes())?;
            verified.push(v);
        }
        Ok(OpAnswer {
            vaults: verified,
            reply,
        })
    }

    /// `kuipa seal unlock`: start a re-authentication session for this
    /// host's device in vault `name`: until it ends, files open without
    /// the passphrase or a ticket.
    ///
    /// # Errors
    ///
    /// A wrong passphrase, a policy without sessions, no runtime
    /// directory, or any other error.
    pub fn unlock(&self, name: &str, passphrase: &[u8], offline: bool) -> Result<Value, Error> {
        let key = self.user.device(passphrase, self.authenticator)?;
        // A session stands in for the passkey: starting one takes it, over
        // this exchange's challenge.
        let info = if self.vault_needs_passkey(name) {
            Some(self.passkey_info()?)
        } else {
            None
        };
        let pin = self.factor_pin(Some(passphrase))?;
        let device = key.public().kid().to_string();
        let OpAnswer { vaults, reply } = self.op_bound(&mut |cb| {
            let passkey = match &info {
                Some(info) => Some(tang_pqc::b64::encode(&self.passkey_assertion(
                    info,
                    &kuipa_enroll::vault::session_passkey_challenge(cb)?,
                    pin,
                )?)),
                None => None,
            };
            Ok(VaultOp::Unlock {
                name: name.into(),
                device: device.clone(),
                offline,
                passkey,
            }
            .to_bytes())
        })?;
        let (session, released) = (reply.session, reply.released);
        let session = session.ok_or("the server started no session")?;
        let epochs = match (offline, released) {
            (false, _) => Vec::new(),
            (true, Some(r)) => r.open(key.as_device(), session.vault())?,
            (true, None) => return Err("the server released no session keys".into()),
        };
        let path = UserPaths::session(session.vault())?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
            for d in [dir, dir.parent().unwrap_or(dir)] {
                fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut w = Writer::new(SESSION_FILE_MAGIC);
        let cached = match &key {
            HostDevice::File(k) => k.to_jwk()?,
            HostDevice::Token(_) => SecretBuf::with_len(0),
        };
        w.bytes(&session.to_bytes())
            .bytes(cached.as_ref())
            .u64(u64::try_from(epochs.len())?);
        for (epoch, k) in &epochs {
            w.u64(*epoch).bytes(k.to_jwk()?.as_ref());
        }
        let bytes = SecretBuf::new(w.finish());
        paths::write_file(&path, bytes.as_ref(), 0o600)?;
        Ok(json!({
            "vaults": vaults.iter().map(describe).collect::<Vec<_>>(),
            "session_until": session.not_after(),
            "offline": offline,
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

    /// The user's IPA passkeys, as the realm lists them (cached for an
    /// hour), else as it last listed them.
    fn passkey_info(&self) -> Result<PasskeyInfo, Error> {
        let now = unix_seconds(flows::now());
        let cached: Option<CachedPasskeys> = fs::read(self.user.passkeys())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        if let Some(c) = &cached
            && now.saturating_sub(c.fetched) <= PASSKEYS_MAX_AGE
        {
            return Ok(c.info.clone());
        }
        let listed = self.op_with_session(&VaultOp::Passkeys).and_then(|a| {
            a.reply
                .passkeys
                .ok_or_else(|| "the server listed no passkeys".into())
        });
        match (listed, cached) {
            (Ok(info), _) => {
                let fresh = CachedPasskeys {
                    fetched: now,
                    info: info.clone(),
                };
                self.user
                    .write(&self.user.passkeys(), &serde_json::to_vec_pretty(&fresh)?)?;
                Ok(info)
            }
            (Err(_), Some(c)) => Ok(c.info),
            (Err(e), None) => Err(format!("your passkeys could not be listed: {e}").into()),
        }
    }

    /// The PIN for the passkey factor: the one given, else for a host
    /// whose device key a passkey wraps the device's (`device_secret`).
    fn factor_pin<'s>(&'s self, device_secret: Option<&'s [u8]>) -> Result<Option<&'s str>, Error> {
        match (&self.passkey_pin, device_secret) {
            (Some(pin), _) => pin_of(pin.as_ref()),
            (None, Some(secret)) if self.user.passkey_device() => pin_of(secret),
            _ => Ok(None),
        }
    }

    /// An assertion (encoded) from one of the user's IPA passkeys over
    /// `challenge`.
    fn passkey_assertion(
        &self,
        info: &PasskeyInfo,
        challenge: &[u8; 32],
        pin: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        if info.credentials.is_empty() {
            return Err(
                "you have no IPA passkeys: register one (`ipa user-add-passkey --register`)".into(),
            );
        }
        let allow = info.credential_ids()?;
        let a = self.authenticator.assert(
            &kuipa_fido2::AssertionRequest {
                rp_id: &info.rp_id,
                client_data_hash: challenge,
                allow: &allow,
                user_verification: info.user_verification,
                hmac_salt: None,
            },
            pin,
        )?;
        Ok(kuipa_enroll::passkey::Assertion {
            credential_id: a.credential_id,
            authenticator_data: a.authenticator_data,
            signature: a.signature,
        }
        .to_bytes())
    }

    /// The stored descriptor of the vault `id`, verified.
    fn stored_by_id(&self, id: &kuipa_enroll::escrow::VaultId) -> Option<VerifiedDescriptor> {
        let public = self.public().ok()?;
        let anchors = paths::read_anchors(self.host).ok()?;
        let policy = tang_pqc::Policy::from_system().ok()?;
        fs::read_dir(self.user.vaults())
            .ok()?
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "vault"))
            .filter_map(|e| fs::read(e.path()).ok())
            .filter_map(|b| {
                Descriptor::from_bytes(&b)
                    .ok()?
                    .verify(&public.realm, &anchors, &policy)
                    .ok()
            })
            .find(|d| d.vault().id == *id)
    }

    /// Whether opening `sealed` takes a passkey assertion: its vault's
    /// policy has the passkey factor, and no session stands in for it.
    /// A vault not described here yet is listed first, with a ticket.
    #[must_use]
    pub fn needs_passkey(&self, sealed: &[u8]) -> bool {
        if sealed.starts_with(b"IPUS") {
            return false;
        }
        let Some(id) = vault_of(sealed) else {
            return false;
        };
        if Self::session_for(&id).is_some() {
            return false;
        }
        let stored = self.stored_by_id(&id).or_else(|| {
            self.op(&VaultOp::List).ok()?;
            self.stored_by_id(&id)
        });
        stored.is_some_and(|d| d.vault().policy.factors.passkey)
    }

    /// Whether vault `name`'s policy has the passkey factor, as its
    /// stored descriptor (else a fresh one) says.
    #[must_use]
    pub fn vault_needs_passkey(&self, name: &str) -> bool {
        let stored = self.stored(name).ok().flatten().or_else(|| {
            self.op(&VaultOp::Show { name: name.into() })
                .ok()?
                .into_iter()
                .next()
        });
        stored.is_some_and(|d| d.vault().policy.factors.passkey)
    }

    /// Whether the passkey factor would verify the user: the realm
    /// requires it, or its setting is not known here yet.
    #[must_use]
    pub fn passkey_verifies_user(&self) -> bool {
        fs::read(self.user.passkeys())
            .ok()
            .and_then(|b| serde_json::from_slice::<CachedPasskeys>(&b).ok())
            .is_none_or(|c| c.info.user_verification)
    }

    /// The live session of vault `id`, if any; an ended one is removed.
    fn session_for(id: &kuipa_enroll::escrow::VaultId) -> Option<LiveSession> {
        let path = UserPaths::session(id).ok()?;
        let bytes = SecretBuf::new(fs::read(&path).ok()?);
        let parsed = (|| -> Result<_, Error> {
            let mut r = Reader::new(bytes.as_ref(), SESSION_FILE_MAGIC, "session")?;
            let token = SessionToken::from_bytes(r.bytes()?)?;
            let key = match r.bytes()? {
                [] => None,
                jwk => Some(ExchangeKeyPair::from_jwk(jwk)?),
            };
            let mut epochs = Vec::new();
            for _ in 0..r.u64()? {
                let epoch = r.u64()?;
                epochs.push((epoch, ExchangeKeyPair::from_jwk(r.bytes()?)?));
            }
            r.finish()?;
            Ok(LiveSession { token, key, epochs })
        })();
        match parsed {
            Ok(live) if live.token.not_after() >= unix_seconds(flows::now()) => Some(live),
            _ => {
                let _ = paths::remove(&path);
                None
            }
        }
    }

    /// Whether opening `sealed` needs the device key's passphrase or the
    /// token's PIN: the file has device shares, and no session holds the
    /// key unwrapped.
    #[must_use]
    pub fn needs_secret(sealed: &[u8]) -> bool {
        let has_devices = if sealed.starts_with(b"IPUS") {
            true
        } else {
            SealedVaultFile::from_bytes(sealed).is_ok_and(|f| !f.devices().is_empty())
        };
        has_devices
            && vault_of(sealed)
                .and_then(|v| Self::session_for(&v))
                .is_none_or(|l| l.key.is_none())
    }

    /// Whether `sealed` can open in a live session, without a passphrase.
    #[must_use]
    pub fn in_session(sealed: &[u8]) -> bool {
        let Some(live) = vault_of(sealed).and_then(|v| Self::session_for(&v)) else {
            return false;
        };
        if sealed.starts_with(b"IPUS") {
            SessionSealedFile::from_bytes(sealed)
                .is_ok_and(|f| live.epochs.iter().any(|(e, _)| *e == f.epoch()))
        } else {
            true
        }
    }

    /// `kuipa seal file --session`: seal `contents` to vault `name`'s
    /// current epoch key, for opening in offline sessions.
    ///
    /// # Errors
    ///
    /// A vault without offline sessions, or as for [`seal`](Self::seal).
    pub fn seal_session(&self, name: &str, contents: &[u8]) -> Result<Vec<u8>, Error> {
        let descriptor = self.descriptor(name)?;
        Ok(SessionSealedFile::seal(&descriptor, contents)?.to_bytes())
    }

    /// `kuipa tlog watch`: check every server's transparency log for
    /// vault `name` (DESIGN-tlog.md §7).  Each server's answer must come
    /// from its advertised key and prove its entries, and its head must
    /// extend the one the last watch verified; then every entry since is
    /// listed, and flagged when the descriptor this host stored does not
    /// account for it — a device it does not list added or acting, a
    /// device it lists removed, a policy or revocation it does not show.
    /// The first watch of a server only sets the baseline: its history is
    /// listed, not flagged.  With the host's trusted witnesses
    /// (`kuipa tlog witnesses`), a head needs `required` of their
    /// cosignatures: one with fewer is reported unwitnessed and not
    /// recorded.  `ok` is false for any flag, a server whose log does not
    /// extend what was seen, an unwitnessed head, or a server that could
    /// not be checked: a watch that did not look is not a clean one.
    ///
    /// # Errors
    ///
    /// No stored descriptor (`kuipa seal show` fetches one), an unreadable
    /// watch state, or any other error outside one server's answer.
    pub fn watch(&self, name: &str) -> Result<Value, Error> {
        let stored = self.stored(name)?.ok_or_else(|| {
            format!("no descriptor of vault {name:?} here: run `kuipa seal show {name}` first")
        })?;
        let vault = stored.vault();
        let expected = Expected {
            subject: vault.id.as_bytes().to_vec(),
            devices: vault.devices.iter().map(|d| d.id.clone()).collect(),
            policy: serde_json::to_vec(&vault.policy)?,
            sharing: vault.sharing_bytes(),
            revoked: vault.state == kuipa_enroll::vault::State::Revoked,
        };
        let public = self.public()?;
        let state_path = self
            .user
            .vaults()
            .join(format!("{}.tlog", local_name(name, &self.public()?.realm)?));
        let mut state: BTreeMap<String, Watched> = match fs::read(&state_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("{}: {e}", state_path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        let trusted = crate::witness::Trusted::load(self.host)?;
        let witnesses = trusted.keys()?;
        let policy = tang_pqc::Policy::from_system()?;
        let (mut events, mut forked, mut unreachable, mut baseline, mut unwitnessed) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut relogged = Vec::new();
        for server in &public.servers {
            let mut before = state.get(server).cloned();
            let mut answer = self.watch_server(&public, server, name, before.as_ref());
            // A server whose key moved to another category (a crypto
            // policy change) keeps a new log: read it from its start, and
            // flag everything in it, as for a log already watched.
            let mut moved = false;
            if let Err(WatchError::NewLog(old)) = &answer {
                relogged.push(json!({ "server": server, "old_log": old }));
                (before, moved) = (None, true);
                answer = self.watch_server(&public, server, name, None);
            }
            let (entries, signed) = match answer {
                Ok(Some(found)) => found,
                Ok(None) => continue,
                Err(WatchError::Fork(why)) => {
                    forked.push(json!({ "server": server, "error": why }));
                    continue;
                }
                Err(WatchError::Other(e)) => {
                    unreachable.push(json!({ "server": server, "error": e.to_string() }));
                    continue;
                }
                Err(WatchError::NewLog(_)) => unreachable!("a fresh read has no log before it"),
            };
            let flag = before.is_some() || moved;
            if !flag {
                baseline.push(server.clone());
            }
            for e in &entries {
                events.push(describe_event(server, e, &expected, flag));
            }
            // A head too few trusted witnesses cosigned may be a view
            // shown to this reader alone: its entries are listed, but the
            // watch does not advance past it, so the next one sees them
            // again under a cosigned head.
            let cosigners = signed.witnesses(&witnesses, &policy).len();
            if cosigners < trusted.required {
                unwitnessed.push(json!({
                    "server": server,
                    "cosigners": cosigners,
                    "required": trusted.required,
                }));
                continue;
            }
            let head = signed.head;
            state.insert(
                server.clone(),
                Watched {
                    log: head.log.to_string(),
                    size: head.size,
                    root: tang_pqc::b64::encode(&head.root),
                },
            );
        }
        self.user
            .write(&state_path, serde_json::to_vec_pretty(&state)?.as_slice())?;
        let flagged = events
            .iter()
            .filter(|e| e["unexpected"] == Value::Bool(true))
            .count();
        Ok(json!({
            "ok": flagged == 0 && forked.is_empty() && unreachable.is_empty()
                && unwitnessed.is_empty(),
            "vault": name,
            "events": events,
            "unexpected": flagged,
            "forked": forked,
            "unreachable": unreachable,
            "unwitnessed": unwitnessed,
            "baseline": baseline,
            "relogged": relogged,
        }))
    }

    /// One server's part of [`watch`](Self::watch): its entries for vault
    /// `name` past what `before` saw, and its head; none for an empty log.
    fn watch_server(
        &self,
        public: &PublicState,
        server: &str,
        name: &str,
        before: Option<&Watched>,
    ) -> Result<
        Option<(
            Vec<kuipa_enroll::tlog::Entry>,
            kuipa_enroll::tlog::SignedHead,
        )>,
        WatchError,
    > {
        use kuipa_enroll::tlog::{LogId, MAX_ANSWER, Query};

        let (anchors, heads, retired, frozen) = paths::pinned_windows(&self.host.anchors())?;
        let known = paths::read_epoch_from(&self.host.anchors())?;
        let trust = flows::ca_trust(self.host)?;
        let cred = self.cred()?;
        let policy = tang_pqc::Policy::from_system()?;
        let deployment = Deployment::servers(&[server.to_owned()]);
        let mut from = before.map_or(0, |w| w.size);
        let mut entries = Vec::new();
        let mut last = None;
        loop {
            let extra = Query {
                vault: name.into(),
                from,
            }
            .to_bytes();
            let (answer, _) = flows::exchange_with(
                &deployment,
                &trust,
                flows::Pins {
                    realm: &public.realm,
                    anchors: &anchors,
                    heads: &heads,
                    retired: &retired,
                    frozen: &frozen,
                },
                known,
                Operation::Tlog,
                |adv| {
                    let p = Prepared::new(
                        adv,
                        Operation::Tlog,
                        &public.fqdn,
                        AuthType::Kerberos,
                        &Enctype::DEFAULT,
                    )?;
                    let target = format!("ipa-ku@{}", adv.server());
                    let (token, binding) = flows::gss_token(&cred, &target, &p.channel_binding()?)?;
                    Ok(p.with_kerberos(binding).seal(&token, &[], &extra)?)
                },
                |pending, response, adv| Ok(pending.finish_tlog(response, adv, &policy)?),
            )?;
            let full = answer.entries.len() == MAX_ANSWER;
            if let Some(e) = answer.entries.last() {
                from = e.index + 1;
            }
            entries.extend(answer.entries);
            last = answer.head.or(last);
            if !full {
                break;
            }
        }
        let Some(signed) = last else {
            return match before {
                Some(_) => Err(WatchError::Fork("the log is empty now".into())),
                None => Ok(None),
            };
        };
        let head = signed.head;
        // The head verified against the server's key, which also fixed
        // the log's hash.
        if head.log != LogId::of(&public.realm, server, head.log.alg())? {
            return Err(WatchError::Fork(
                "the answer is from another server's log".into(),
            ));
        }
        if let Some(w) = before
            && w.log != head.log.to_string()
        {
            return Err(WatchError::NewLog(w.log.clone()));
        }
        if let Some(w) = before {
            let old_root = kuipa_enroll::merkle::Hash::from_slice(&tang_pqc::b64::decode(&w.root)?)
                .map_err(|_| "a malformed root in the watch state")?;
            let extends = match head.size.cmp(&w.size) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => head.root == old_root,
                std::cmp::Ordering::Greater => {
                    let endpoint = Endpoint::new(server, &trust)?;
                    let proof = endpoint.tlog_consistency(&head.log, w.size, head.size)?;
                    kuipa_enroll::merkle::verify_consistency(
                        w.size, &old_root, head.size, &head.root, &proof,
                    )?
                }
            };
            if !extends {
                return Err(WatchError::Fork(format!(
                    "its head of {} leaves does not extend the {} seen before",
                    head.size, w.size
                )));
            }
        }
        Ok(Some((entries, signed)))
    }

    /// The stored descriptor of vault `name`, verified.
    fn stored(&self, name: &str) -> Result<Option<VerifiedDescriptor>, Error> {
        let public = self.public()?;
        let Ok(bytes) = fs::read(self.user.vault(name, &public.realm)?) else {
            return Ok(None);
        };
        let anchors = paths::read_anchors(self.host)?;
        Ok(Some(Descriptor::from_bytes(&bytes)?.verify(
            &public.realm,
            &anchors,
            &tang_pqc::Policy::from_system()?,
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
        // The whole window travels and a frozen pin is enforced (§1.4,
        // §2): these advertisements are what sealing trusts.
        let (anchors, heads, retired, frozen) = paths::pinned_windows(&self.host.anchors())?;
        let known = paths::read_epoch_from(&self.host.anchors())?;
        let trust = flows::ca_trust(self.host)?;
        let now = unix_seconds(flows::now());
        let mut cache = Vec::new();
        let mut verified = Vec::new();
        for server in &public.servers {
            let Ok((_, v, _)) = flows::verified(
                server,
                &trust,
                flows::Pins {
                    realm: &public.realm,
                    anchors: &anchors,
                    heads: &heads,
                    retired: &retired,
                    frozen: &frozen,
                },
                known,
            ) else {
                continue;
            };
            // What was just verified is what sealing keeps: no second fetch.
            cache.push(CachedAdvertisement {
                server: server.clone(),
                fetched: now,
                advertisement: v.signed().to_json(),
            });
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
                    &tang_pqc::Policy::from_system().ok()?,
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
        if name.contains('/') {
            return Err(format!("{name:?}: a vault is created as one's own, by its name").into());
        }
        local_name(name, "")?;
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
        let (key, kind) = if self.user.token().is_some() {
            (
                self.user.device(passphrase, self.authenticator)?,
                DeviceType::Pkcs11,
            )
        } else if self.user.device_key().exists() {
            let kind = if self.user.passkey_device() {
                DeviceType::Passkey
            } else {
                DeviceType::File
            };
            (self.user.device(passphrase, self.authenticator)?, kind)
        } else {
            let key = ExchangeKeyPair::generate(KemAlg::MlKem768)?;
            write_device_key(self.user, &key, passphrase)?;
            (HostDevice::File(key), DeviceType::File)
        };
        self.register_device(name, &key, kind)
    }

    /// `kuipa seal device add --passkey`: make this host's device key
    /// now, wrapped by the `hmac-secret` output of a new credential on the
    /// security key (two touches: the credential, then the wrap), and
    /// register it in vault `name`.  `pin` (empty for none) verifies the
    /// user, and must then be given at every use.  The credential is the
    /// device's own, under the relying party `kuipa:<realm>`, not one of
    /// the user's IPA passkeys.  No attestation is verified yet, so the
    /// device registers at level `any`.
    ///
    /// # Errors
    ///
    /// A device key already here, no security key, a key without
    /// `hmac-secret`, a refusal, or any other error.
    pub fn add_passkey_device(&self, name: &str, pin: &[u8]) -> Result<Value, Error> {
        if self.user.device_key().exists() || self.user.token().is_some() {
            return Err("this host already has a device key: one device per host".into());
        }
        let public = self.public()?;
        let me = self
            .cred()?
            .principal_name()
            .ok_or("cannot tell whose ticket this is")?;
        let pin = pin_of(pin)?;
        let mut user_id = [0u8; 32];
        Rand::fill(&mut user_id)?;
        let rp_id = format!("kuipa:{}", public.realm.to_lowercase());
        let credential = self.authenticator.make_credential(
            &kuipa_fido2::CredentialRequest {
                rp_id: &rp_id,
                rp_name: "kuipa device key",
                user_id: &user_id,
                user_name: &me,
                algorithms: crate::passkey::DEVICE_ALGORITHMS,
                hmac_secret: true,
            },
            pin,
        )?;
        let wrap = PasskeyWrap {
            rp_id,
            credential_id: credential.id,
            uv: pin.is_some(),
        };
        let key = ExchangeKeyPair::generate(KemAlg::MlKem768)?;
        let wrapped = protect_with_passkey(&key, &wrap, pin, self.authenticator)?;
        self.user.write(&self.user.device_key(), &wrapped)?;
        self.register_device(name, &HostDevice::File(key), DeviceType::Passkey)
    }

    /// Register this host's device `key`, of type `kind`, in vault `name`,
    /// depositing it first where the realm keeps device keys for recovery.
    /// A refused registration retires that deposit again, so a rejected
    /// device leaves no orphaned escrow behind.
    fn register_device(
        &self,
        name: &str,
        key: &HostDevice,
        kind: DeviceType,
    ) -> Result<Value, Error> {
        let deposit = match key {
            HostDevice::File(k) => self.deposit_device_key(k)?,
            HostDevice::Token(_) => None,
        };
        let public = self.public()?;
        let registered = self.op(&VaultOp::AddDevice {
            name: name.into(),
            label: public.fqdn,
            kind,
            alg: key.public().alg().id(),
            key: tang_pqc::b64::encode(key.public().as_bytes()),
        });
        if let Some((vault, id)) = deposit.filter(|_| registered.is_err()) {
            self.retire_deposit(&vault, &id)
                .map_err(|e| format!("the refused device's deposit was not retired: {e}"))?;
        }
        Ok(describe_all(&registered?))
    }

    /// `kuipa seal device add --pkcs11 URI`: make the ML-KEM key at `uri`
    /// on a token (through PKCS#11 `module`) this host's device, and
    /// register it in vault `name`.  `pin` logs in to the token.
    ///
    /// # Errors
    ///
    /// The token or key cannot be reached, a refusal, or any other error.
    pub fn add_token_device(
        &self,
        name: &str,
        module: &Path,
        uri: &str,
        pin: &[u8],
    ) -> Result<Value, Error> {
        if self.user.device_key().exists() {
            return Err(
                "this host already has a passphrase device key: one device per host".into(),
            );
        }
        let config = TokenConfig {
            module: module.to_path_buf(),
            uri: uri.to_owned(),
        };
        // Reach the key before remembering where it is.
        crate::pkcs11::TokenKey::open(
            module,
            uri,
            pin,
            &UserPaths::runtime().unwrap_or_else(|_| self.user.dir.clone()),
        )?;
        self.user.write(
            &self.user.token_device(),
            &serde_json::to_vec_pretty(&config)?,
        )?;
        self.add_device(name, pin)
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

    /// `kuipa seal share`: add `who` (managers, members, depositors) to
    /// vault `name`.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn share(
        &self,
        name: &str,
        who: [kuipa_enroll::vault::Members; 3],
    ) -> Result<Value, Error> {
        let [managers, members, depositors] = who;
        let v = self.op(&VaultOp::Share {
            name: name.into(),
            managers,
            members,
            depositors,
        })?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal unshare`: remove `who` (managers, members, depositors)
    /// from vault `name`, with the devices they hold.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn unshare(
        &self,
        name: &str,
        who: [kuipa_enroll::vault::Members; 3],
    ) -> Result<Value, Error> {
        let [managers, members, depositors] = who;
        let v = self.op(&VaultOp::Unshare {
            name: name.into(),
            managers,
            members,
            depositors,
        })?;
        Ok(describe_all(&v))
    }

    /// `kuipa seal deposit put`: seal `contents` to vault `name` and leave
    /// it with the servers as a deposit of `kind` for `subject`, in place of
    /// any earlier one of the same kind and subject (`DESIGN-recovery.md`
    /// §3).  A depositor seals without being able to open.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn deposit(
        &self,
        name: &str,
        contents: &[u8],
        kind: kuipa_enroll::vault::DepositKind,
        subject: std::collections::BTreeMap<String, String>,
    ) -> Result<Value, Error> {
        // The server registers a deposit's bindings itself.
        let sealed = self.seal_file(name, contents)?;
        let answer = self.op_with_session(&VaultOp::Deposit {
            name: name.into(),
            kind,
            subject,
            sealed: tang_pqc::b64::encode(&sealed.to_bytes()),
        })?;
        Ok(describe_deposits(name, &answer.reply.deposits))
    }

    /// `kuipa seal deposit list`: vault `name`'s deposits (a depositor's
    /// own, for a depositor).
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn deposits(&self, name: &str) -> Result<Value, Error> {
        let answer = self.op_with_session(&VaultOp::Deposits { name: name.into() })?;
        Ok(describe_deposits(name, &answer.reply.deposits))
    }

    /// `kuipa seal deposit fetch`: deposit `id`'s sealed file, to open as
    /// any other file of the vault.
    ///
    /// # Errors
    ///
    /// A depositor, no such deposit, a refusal.
    pub fn deposit_file(&self, name: &str, id: &str) -> Result<Vec<u8>, Error> {
        let answer = self.op_with_session(&VaultOp::FetchDeposit {
            name: name.into(),
            id: id.into(),
        })?;
        let deposit = answer
            .reply
            .deposits
            .first()
            .ok_or("the server sent no deposit")?;
        Ok(tang_pqc::b64::decode(&deposit.sealed)?)
    }

    /// `kuipa seal deposit retire`: remove deposit `id`, a depositor's own
    /// or, for a manager, any.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn retire_deposit(&self, name: &str, id: &str) -> Result<Value, Error> {
        self.op_with_session(&VaultOp::RetireDeposit {
            name: name.into(),
            id: id.into(),
        })?;
        Ok(json!({ "vault": name, "retired_deposit": id }))
    }

    /// `kuipa seal request`: ask the approvers of vault `name` to approve
    /// the release of `sealed`, for `reason`.
    ///
    /// # Errors
    ///
    /// A file of another kind, a vault without approvals, a refusal.
    pub fn request(&self, name: &str, sealed: &[u8], reason: &str) -> Result<Value, Error> {
        let file = SealedVaultFile::from_bytes(sealed)?;
        let bindings = file
            .bindings()?
            .iter()
            .map(kuipa_enroll::vault::binding_hex)
            .collect();
        let requests = self
            .op_with_session(&VaultOp::Request {
                name: name.into(),
                bindings,
                reason: reason.into(),
            })?
            .reply
            .requests;
        Ok(describe_requests(name, &requests))
    }

    /// `kuipa seal pending`: the open release requests of vault `name`, or
    /// of every vault the user approves for or has a part in.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn pending(&self, name: Option<&str>) -> Result<Value, Error> {
        let requests = self
            .op_with_session(&VaultOp::Pending {
                name: name.map(str::to_owned),
            })?
            .reply
            .requests;
        Ok(describe_requests(name.unwrap_or(""), &requests))
    }

    /// `kuipa seal approve` (or with `deny`, `kuipa seal deny`): approve or
    /// deny release request `id` of vault `name`.
    ///
    /// # Errors
    ///
    /// A refusal or any other error.
    pub fn decide(&self, name: &str, id: &str, deny: bool) -> Result<Value, Error> {
        let op = if deny {
            VaultOp::Deny {
                name: name.into(),
                id: id.into(),
            }
        } else {
            VaultOp::Approve {
                name: name.into(),
                id: id.into(),
            }
        };
        Ok(describe_requests(
            name,
            &self.op_with_session(&op)?.reply.requests,
        ))
    }

    /// `kuipa seal recovery-code`: escrow this host's device key under a
    /// new recovery code, which only the answer shows (`DESIGN-recovery.md`
    /// §2).  The device must be registered in one of the user's vaults.
    ///
    /// # Errors
    ///
    /// A token device (its key never leaves the token), a wrong
    /// passphrase, a refusal.
    pub fn recovery_code(&self, passphrase: &[u8]) -> Result<Value, Error> {
        if self.user.token().is_some() {
            return Err("a token's key never leaves the token: it has no recovery code".into());
        }
        let HostDevice::File(key) = self.user.device(passphrase, self.authenticator)? else {
            return Err("a token's key never leaves the token: it has no recovery code".into());
        };
        let code = new_recovery_code()?;
        let blob = protect_key(&key, recovery_secret(&code)?.as_ref())?;
        let device = key.public().kid().to_string();
        self.op_with_session(&VaultOp::EscrowCode {
            device: device.clone(),
            blob: tang_pqc::b64::encode(&blob),
        })?;
        Ok(json!({ "device": device, "recovery_code": code }))
    }

    /// `kuipa seal recover code`: fetch the user's escrowed device keys,
    /// open the one `code` protects, and keep it on this host as the
    /// recovered key, under `passphrase` (this host's device passphrase,
    /// if it has a device key).
    ///
    /// # Errors
    ///
    /// No escrow the code opens, a wrong passphrase for this host's device,
    /// a recovered key already here, a refusal.
    pub fn recover_code(&self, code: &str, passphrase: &[u8]) -> Result<Value, Error> {
        if self.user.recovered_key().exists() {
            return Err(
                "a recovered key is already here: `kuipa seal recover finish` first".into(),
            );
        }
        if self.user.device_key().exists() {
            // One passphrase (or passkey) for both keys of this host.
            self.user.device(passphrase, self.authenticator)?;
        }
        let secret = recovery_secret(code)?;
        let escrows = self.op_with_session(&VaultOp::RecoverCode)?.reply.escrows;
        let key = escrows
            .iter()
            .find_map(|e| {
                let blob = tang_pqc::b64::decode(&e.blob).ok()?;
                unprotect_key(&blob, secret.as_ref()).ok()
            })
            .ok_or("the code opens none of your escrowed device keys")?;
        self.user.write(
            &self.user.recovered_key(),
            &self.user.protect(&key, passphrase, self.authenticator)?,
        )?;
        Ok(json!({ "recovered": key.public().kid().to_string() }))
    }

    /// `kuipa seal recover finish`: register this host's device (made now
    /// under `passphrase` if there is none) in every vault where the
    /// recovered device is the user's, and reseal `sealed` to it.  With
    /// `retire_old`, also remove the recovered device from those vaults and
    /// forget it here: files not resealed then no longer open.  Answers the
    /// resealed files, in order.
    ///
    /// # Errors
    ///
    /// Nothing recovered here, a file of a vault the recovered device is
    /// not in, a wrong passphrase, a refusal.
    pub fn recover_finish(
        &self,
        passphrase: &[u8],
        sealed: &[Vec<u8>],
        retire_old: bool,
    ) -> Result<(Value, Vec<Vec<u8>>), Error> {
        let old = self
            .user
            .recovered(passphrase, self.authenticator)?
            .ok_or("nothing recovered here: run `kuipa seal recover code` first")?;
        let old_id = old.public().kid().to_string();
        let me = self
            .cred()?
            .principal_name()
            .ok_or("cannot tell whose ticket this is")?;
        let held: Vec<(String, kuipa_enroll::escrow::VaultId)> = self
            .op(&VaultOp::List)?
            .iter()
            .filter_map(|d| {
                let v = d.vault();
                v.devices
                    .iter()
                    .any(|x| x.id == old_id && v.holder(x) == me)
                    .then(|| (reference_for(v, Some(&me)), v.id))
            })
            .collect();
        if !self.user.device_key().exists() && self.user.token().is_none() {
            write_device_key(
                self.user,
                &ExchangeKeyPair::generate(KemAlg::MlKem768)?,
                passphrase,
            )?;
        }
        let new_id = self
            .user
            .device(passphrase, self.authenticator)?
            .public()
            .kid()
            .to_string();
        for (name, _) in &held {
            let current = self.op(&VaultOp::Show { name: name.clone() })?;
            if !current
                .iter()
                .any(|d| d.vault().devices.iter().any(|x| x.id == new_id))
            {
                self.add_device(name, passphrase)?;
            }
        }
        let mut resealed = Vec::with_capacity(sealed.len());
        for file in sealed {
            let id = vault_of(file).ok_or("not a sealed vault file")?;
            let (name, _) = held.iter().find(|(_, v)| *v == id).ok_or_else(|| {
                format!("a file of vault {id}, where the recovered device is not")
            })?;
            resealed.push(self.reseal(name, file, Some(passphrase))?);
        }
        if retire_old {
            for (name, _) in &held {
                self.remove_device(name, &old_id)?;
            }
            paths::remove(&self.user.recovered_key())?;
        }
        Ok((
            json!({
                "vaults": held.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
                "device": new_id,
                "resealed": resealed.len(),
                "retired": if retire_old { Some(old_id) } else { None },
            }),
            resealed,
        ))
    }

    /// The realm's device-key recovery settings, if it has any.
    fn recovery(&self) -> Result<Option<kuipa_enroll::vault::RecoverySettings>, Error> {
        Ok(self
            .op_with_session(&VaultOp::RecoverySettings)?
            .reply
            .recovery)
    }

    /// Where the realm keeps device keys for recovery, deposit `key` there
    /// (`DESIGN-recovery.md` §4), unless the user already has.  Answers
    /// the id of the deposit this call made, if it made one.  A failure
    /// stops the registration only where the realm requires the deposit.
    fn deposit_device_key(&self, key: &ExchangeKeyPair) -> Result<Option<(String, String)>, Error> {
        let Some(settings) = self.recovery()? else {
            return Ok(None);
        };
        match self.deposit_device_key_to(&settings.device_vault, key) {
            Err(e) if !settings.required => {
                tracing::warn!("the device key was not deposited for recovery: {e}");
                Ok(None)
            }
            done => done.map(|id| id.map(|id| (settings.device_vault.clone(), id))),
        }
    }

    fn deposit_device_key_to(
        &self,
        vault: &str,
        key: &ExchangeKeyPair,
    ) -> Result<Option<String>, Error> {
        let id = key.public().kid().to_string();
        let mine = self
            .op_with_session(&VaultOp::Deposits { name: vault.into() })?
            .reply
            .deposits;
        if mine.iter().any(|d| {
            d.kind == kuipa_enroll::vault::DepositKind::Device
                && d.subject.get("device") == Some(&id)
        }) {
            return Ok(None);
        }
        let subject = std::collections::BTreeMap::from([("device".to_owned(), id)]);
        let answer = self.deposit(
            vault,
            key.to_jwk()?.as_ref(),
            kuipa_enroll::vault::DepositKind::Device,
            subject,
        )?;
        Ok(answer["deposits"]
            .as_array()
            .and_then(|d| d.first())
            .and_then(|d| d["id"].as_str())
            .map(str::to_owned))
    }

    /// `kuipa seal recover helpdesk`: this host's device, which the
    /// helpdesk delivers a lost device's key to.
    ///
    /// # Errors
    ///
    /// No device key here, or a wrong passphrase.
    pub fn recover_helpdesk(&self, passphrase: &[u8]) -> Result<Value, Error> {
        let key = self.user.device(passphrase, self.authenticator)?;
        Ok(json!({ "helpdesk_device": key.public().kid().to_string() }))
    }

    /// `kuipa seal recover deliver`: as the helpdesk, open deposit `id` of
    /// the realm's device vault (with this host's device under `passphrase`
    /// and, for a vault with approvals, the approved request `release`) and
    /// deliver the key it holds to `user`'s device `device`, encrypted to
    /// that device's registered public key.
    ///
    /// # Errors
    ///
    /// No device recovery in the realm, not a device deposit, a refusal
    /// (not the helpdesk, no such device of the user's), or any other
    /// error.
    pub fn deliver(
        &self,
        id: &str,
        to: (&str, &str),
        passphrase: Option<&[u8]>,
        release: Option<&str>,
    ) -> Result<Value, Error> {
        let (user, device) = to;
        let settings = self.recovery()?.ok_or("the realm has no device recovery")?;
        let sealed = self.deposit_file(&settings.device_vault, id)?;
        let jwk = self.open_with(&sealed, passphrase, release)?;
        let old = ExchangeKeyPair::from_jwk(jwk.as_ref())?;
        let found = self
            .op_with_session(&VaultOp::DeviceKey {
                user: user.into(),
                device: device.into(),
            })?
            .reply
            .devices;
        let new = found
            .first()
            .ok_or("the server named no such device")?
            .public()?;
        if new.kid().to_string() != device {
            return Err("the server named another device".into());
        }
        let blob = kuipa_enroll::vault::seal_delivery(&new, &old)?;
        self.op_with_session(&VaultOp::Deliver {
            user: user.into(),
            device: device.into(),
            blob: tang_pqc::b64::encode(&blob),
        })?;
        Ok(json!({
            "delivered": old.public().kid().to_string(),
            "user": user,
            "to_device": device,
        }))
    }

    /// `kuipa seal recover fetch`: the key the helpdesk delivered to this
    /// host's device, kept here as the recovered key, under `passphrase`.
    ///
    /// # Errors
    ///
    /// No delivery for this device, a wrong passphrase, a recovered key
    /// already here, a refusal.
    pub fn recover_fetch(&self, passphrase: &[u8]) -> Result<Value, Error> {
        if self.user.recovered_key().exists() {
            return Err(
                "a recovered key is already here: `kuipa seal recover finish` first".into(),
            );
        }
        let device = self.user.device(passphrase, self.authenticator)?;
        let mine = device.public().kid().to_string();
        let escrows = self.op_with_session(&VaultOp::RecoverCode)?.reply.escrows;
        let key = escrows
            .iter()
            .filter(|e| e.kind == "delivery" && e.device == mine)
            .find_map(|e| {
                let blob = tang_pqc::b64::decode(&e.blob).ok()?;
                kuipa_enroll::vault::open_delivery(&blob, device.as_device()).ok()
            })
            .ok_or("nothing was delivered to this host's device")?;
        self.user.write(
            &self.user.recovered_key(),
            &self.user.protect(&key, passphrase, self.authenticator)?,
        )?;
        Ok(json!({ "recovered": key.public().kid().to_string() }))
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
        let sealed = self.seal_file(name, contents)?;
        if self.descriptor(name)?.vault().policy.sealing == kuipa_enroll::vault::Sealing::Registered
        {
            // Until registered, no server opens it.
            self.register(name, &sealed.bindings()?, &[])?;
        }
        Ok(sealed.to_bytes())
    }

    /// Seal `contents` to vault `name`, without registering it.
    fn seal_file(&self, name: &str, contents: &[u8]) -> Result<SealedVaultFile, Error> {
        let descriptor = self.descriptor(name)?;
        // The realm's descriptor age bounds the advertisements too.
        let mut servers = self.cached_servers(descriptor.max_age())?;
        if servers.is_empty() {
            servers = self.refresh_servers()?;
        }
        let refs: Vec<_> = servers.iter().collect();
        Ok(SealedVaultFile::seal(&descriptor, &refs, contents)?)
    }

    /// Register `add` and retire `retire` on vault `name` (registered
    /// sealing).
    fn register(
        &self,
        name: &str,
        add: &[kuipa_enroll::escrow::BindingHash],
        retire: &[kuipa_enroll::escrow::BindingHash],
    ) -> Result<(), Error> {
        let hex = |v: &[kuipa_enroll::escrow::BindingHash]| {
            v.iter().map(kuipa_enroll::vault::binding_hex).collect()
        };
        self.op(&VaultOp::Register {
            name: name.into(),
            add: hex(add),
            retire: hex(retire),
        })?;
        Ok(())
    }

    /// `kuipa seal retire`: with registered sealing, make `sealed` (and
    /// every copy of it) unopenable.
    ///
    /// # Errors
    ///
    /// A file of another kind, a vault without registered sealing, or a
    /// refusal.
    pub fn retire(&self, name: &str, sealed: &[u8]) -> Result<(), Error> {
        let file = SealedVaultFile::from_bytes(sealed)?;
        self.register(name, &[], &file.bindings()?)
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
        self.open_with(sealed, passphrase, None)
    }

    /// `kuipa seal open --request ID`: as [`open`](Self::open), naming the
    /// approved release request `release` for a vault with approvals.
    ///
    /// # Errors
    ///
    /// As for [`open`](Self::open), and a malformed request id.
    pub fn open_with(
        &self,
        sealed: &[u8],
        passphrase: Option<&[u8]>,
        release: Option<&str>,
    ) -> Result<SecretBuf, Error> {
        let release = release
            .map(kuipa_enroll::vault::ReleaseRequest::id_bytes)
            .transpose()?;
        if sealed.starts_with(b"IPUS") {
            return self.open_offline(sealed, passphrase);
        }
        let file = SealedVaultFile::from_bytes(sealed)?;
        let session = Self::session_for(file.vault());
        let unwrapped;
        let device: Option<&dyn DeviceKey> =
            if let Some(k) = session.as_ref().and_then(|l| l.key.as_ref()) {
                Some(k)
            } else if file.devices().is_empty() && session.is_none() {
                None
            } else {
                let passphrase = passphrase
                    .ok_or("the file needs this host's device key: give its passphrase or PIN")?;
                unwrapped =
                    self.user
                        .device_for(&file.devices(), passphrase, self.authenticator)?;
                Some(unwrapped.as_device())
            };
        let trust = flows::ca_trust(self.host)?;
        // A passkey only when the vault asks for one: each takes a touch.
        let passkey_info = if session.is_none() && self.needs_passkey(sealed) {
            Some(self.passkey_info()?)
        } else {
            None
        };
        let pin = self.factor_pin(passphrase)?;
        let failure: std::cell::RefCell<Option<Error>> = std::cell::RefCell::new(None);
        let mut make_assertion = |_: &str, challenge: &[u8; 32]| {
            if failure.borrow().is_some() {
                return None;
            }
            let info = passkey_info.as_ref()?;
            self.passkey_assertion(info, challenge, pin)
                .map_err(|e| *failure.borrow_mut() = Some(e))
                .ok()
        };
        let passkey: Option<kuipa_enroll::vault::PasskeySource<'_>> = if passkey_info.is_some() {
            Some(&mut make_assertion)
        } else {
            None
        };
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
                device,
                session: session.as_ref().map(|l| &l.token),
                ticket,
                release,
                passkey,
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
        .map_err(|e| match (e, failure.take()) {
            // The passkey failed before any server could answer.
            (kuipa_enroll::Error::Refused, Some(passkey)) => passkey,
            (kuipa_enroll::Error::Refused, None) => Outcome::RetryLater(
                "no server would open it: the vault's policy refused, or no server answered".into(),
            )
            .into(),
            (e, _) => e.into(),
        })
    }

    /// Open a file sealed for offline sessions, here, without a server.
    fn open_offline(&self, sealed: &[u8], passphrase: Option<&[u8]>) -> Result<SecretBuf, Error> {
        let file = SessionSealedFile::from_bytes(sealed)?;
        let live = Self::session_for(file.vault()).ok_or(
            "this file opens in an offline session: run `kuipa seal unlock VAULT --offline`",
        )?;
        let (_, epoch_key) = live
            .epochs
            .iter()
            .find(|(e, _)| *e == file.epoch())
            .ok_or("the session was started before this file's epoch: unlock again")?;
        let fetched;
        let device = if let Some(k) = &live.key {
            k as &dyn DeviceKey
        } else {
            let secret = passphrase.ok_or("the file needs this host's token: give its PIN")?;
            fetched = self.user.device(secret, self.authenticator)?;
            fetched.as_device()
        };
        Ok(file.open(epoch_key, device)?)
    }

    /// `kuipa seal reseal`: open each file and seal it again to the
    /// vault's current devices, every member's.
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
        // The devices registered now, not those of the stored descriptor:
        // a reseal is what gives a new device or member the file.
        self.op(&VaultOp::Show { name: name.into() })?;
        let again = self.seal(name, plain.as_ref())?;
        if self
            .stored(name)?
            .is_some_and(|d| d.vault().policy.sealing == kuipa_enroll::vault::Sealing::Registered)
        {
            // The old copy, wherever it is, stops opening.
            self.retire(name, sealed)?;
        }
        Ok(again)
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
        "managers": vault.managers.entries(),
        "members": vault.members.entries(),
        "depositors": vault.depositors.entries(),
        "devices": vault.devices.iter().map(|d| json!({
            "id": d.id, "label": d.label, "type": d.kind, "level": d.level,
            "holder": vault.holder(d),
        })).collect::<Vec<_>>(),
        "unlocks": vault.unlocks,
        "signed_by": v.server(),
        "signed_at": v.iat(),
    })
}

/// The JSON form of deposits, for `--json` and the renderer.
fn describe_deposits(vault: &str, deposits: &[kuipa_enroll::vault::Deposit]) -> Value {
    json!({
        "vault": vault,
        "deposits": deposits.iter().map(|d| json!({
            "id": d.id,
            "depositor": d.depositor,
            "kind": d.kind,
            "subject": d.subject,
            "added": d.added,
        })).collect::<Vec<_>>(),
    })
}

/// The JSON form of release requests, for `--json` and the renderer.
fn describe_requests(vault: &str, requests: &[kuipa_enroll::vault::ReleaseRequest]) -> Value {
    json!({
        "vault": vault,
        "requests": requests.iter().map(|r| json!({
            "id": r.id,
            "vault": r.vault.to_string(),
            "requester": r.requester,
            "reason": r.reason,
            "bindings": r.bindings,
            "created": r.created,
            "not_after": r.not_after,
            "approvals": r.approvals.iter().map(|a| a.approver.clone()).collect::<Vec<_>>(),
            "denied_by": r.denied.as_ref().map(|d| d.approver.clone()),
            "uses": r.uses,
        })).collect::<Vec<_>>(),
    })
}

fn describe_all(v: &[VerifiedDescriptor]) -> Value {
    json!({ "vaults": v.iter().map(describe).collect::<Vec<_>>() })
}

/// What `kuipa tlog watch` last verified of one server's log.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Watched {
    /// The log's id (hex).
    log: String,
    /// Its size then: entries below it were seen.
    size: u64,
    /// Its root then (base64url).
    root: String,
}

/// Why one server's part of a watch failed.
enum WatchError {
    /// The server's log does not extend what was seen.
    Fork(String),
    /// The server keeps another log than the one seen (named): its key
    /// moved to another category, which changes the log's hash and id.
    NewLog(String),
    /// Anything else: the server is unreachable, refuses, or errs.
    Other(Error),
}

impl<E: Into<Error>> From<E> for WatchError {
    fn from(e: E) -> Self {
        Self::Other(e.into())
    }
}

/// What the stored descriptor accounts for.
struct Expected {
    /// The vault's id: every entry's opening must name it.
    subject: Vec<u8>,
    devices: BTreeSet<String>,
    /// The policy's JSON, digested with each log's hash to compare.
    policy: Vec<u8>,
    /// Who shares the vault, digested the same way.
    sharing: Vec<u8>,
    revoked: bool,
}

/// One entry as `kuipa tlog watch` reports it; `flag` decides whether an
/// unaccounted entry counts as unexpected (not on a baseline watch).
fn describe_event(
    server: &str,
    e: &kuipa_enroll::tlog::Entry,
    expected: &Expected,
    flag: bool,
) -> Value {
    use kuipa_enroll::tlog::{VaultAction as A, VaultEvent};

    // The answer's check made sure an opening opens its leaf; that it is
    // about this vault is this watch's to check.  A server that will not
    // open an entry, or opens it to another vault's event, hides what it
    // did: flagged, whatever the watch's state.
    let refused = |why: &str| {
        json!({
            "server": server, "index": e.index, "time": e.leaf.time,
            "action": format!("kind {}", e.leaf.kind.0),
            "unexpected": true, "why": why,
        })
    };
    let Some(opening) = &e.opening else {
        return refused("the server would not open this entry");
    };
    if opening.subject != expected.subject {
        return refused("the server opened this entry to another vault's event");
    }
    let Ok(event) = VaultEvent::from_bytes(&opening.event) else {
        return json!({
            "server": server, "index": e.index, "time": opening.time,
            "action": format!("kind {}", e.leaf.kind.0), "unexpected": false,
        });
    };
    let device = event.device.as_deref();
    let listed = device.is_some_and(|d| expected.devices.contains(d));
    let unlisted = device.is_some() && !listed;
    let (action, why) = match event.action {
        A::Create => ("create", None),
        A::SetPolicy => (
            "set-policy",
            primitives::digest(event.digest.alg().openssl_name(), &[&expected.policy])
                .is_ok_and(|d| d != *event.digest)
                .then_some("a policy the stored descriptor does not show"),
        ),
        A::Share | A::Unshare => (
            if event.action == A::Share {
                "share"
            } else {
                "unshare"
            },
            primitives::digest(event.digest.alg().openssl_name(), &[&expected.sharing])
                .is_ok_and(|d| d != *event.digest)
                .then_some("managers or members the stored descriptor does not show"),
        ),
        A::EscrowCode => ("escrow-code", unlisted.then_some("an unlisted device")),
        A::RecoverCode => (
            "recover-code",
            Some("the device's escrowed key was fetched for recovery"),
        ),
        A::Deposit => ("deposit", None),
        A::RetireDeposit => ("retire-deposit", None),
        A::Deliver => (
            "deliver",
            Some("a recovered key was delivered to the device"),
        ),
        A::Request => ("request", None),
        A::Approve => ("approve", None),
        A::Deny => ("deny", None),
        A::Revoke => (
            "revoke",
            (!expected.revoked).then_some("the stored descriptor shows the vault enabled"),
        ),
        A::AddDevice => (
            "add-device",
            (!listed).then_some("a device the stored descriptor does not list"),
        ),
        A::RemoveDevice => (
            "remove-device",
            listed.then_some("a device the stored descriptor still lists"),
        ),
        A::Session => ("session", unlisted.then_some("an unlisted device")),
        A::OfflineSession => ("offline-session", unlisted.then_some("an unlisted device")),
        A::Release => ("release", unlisted.then_some("an unlisted device")),
    };
    json!({
        "server": server,
        "index": e.index,
        "time": opening.time,
        "action": action,
        "device": device,
        "unexpected": flag && why.is_some(),
        "why": why,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-leaf lookup answer's entry for `opening`, its leaf made from
    /// it, as a server answers.
    fn entry(
        opening: Option<kuipa_enroll::tlog::Opening>,
        made_from: &kuipa_enroll::tlog::Opening,
    ) -> kuipa_enroll::tlog::Entry {
        kuipa_enroll::tlog::Entry {
            index: 0,
            leaf: made_from
                .leaf(kuipa_enroll::merkle::TreeHash::Sha256)
                .expect("a leaf"),
            path: Vec::new(),
            opening,
        }
    }

    #[test]
    fn the_watch_reads_openings_and_flags_what_the_server_will_not_open() {
        use kuipa_enroll::tlog::{Kind, Opening, VaultAction, VaultEvent};

        let expected = Expected {
            subject: b"vault-1".to_vec(),
            devices: BTreeSet::from(["dev-1".to_owned()]),
            policy: Vec::new(),
            sharing: Vec::new(),
            revoked: false,
        };
        let event = |device: &str| {
            VaultEvent {
                action: VaultAction::Release,
                device: Some(device.into()),
                digest: kuipa_enroll::merkle::Hash::zero(kuipa_enroll::merkle::TreeHash::Sha256),
            }
            .to_bytes()
        };
        let mine = Opening::new(
            Kind::ESCROW_RELEASE,
            1_800_000_123,
            b"vault-1",
            event("dev-1"),
        )
        .unwrap();

        // The event and its exact time come from the opening.
        let listed = describe_event("ipa1", &entry(Some(mine.clone()), &mine), &expected, true);
        assert_eq!(listed["action"], "release", "{listed}");
        assert_eq!(listed["time"], 1_800_000_123, "{listed}");
        assert_eq!(listed["unexpected"], false, "{listed}");
        let other_device = Opening::new(
            Kind::ESCROW_RELEASE,
            1_800_000_200,
            b"vault-1",
            event("dev-2"),
        )
        .unwrap();
        let flagged = describe_event(
            "ipa1",
            &entry(Some(other_device.clone()), &other_device),
            &expected,
            true,
        );
        assert_eq!(flagged["unexpected"], true, "{flagged}");

        // An entry the server will not open, or opens to another vault's
        // event, is flagged even on a baseline watch.
        let unopened = describe_event("ipa1", &entry(None, &mine), &expected, false);
        assert_eq!(unopened["unexpected"], true, "{unopened}");
        let theirs = Opening::new(
            Kind::ESCROW_RELEASE,
            1_800_000_123,
            b"vault-2",
            event("dev-1"),
        )
        .unwrap();
        let elsewhere = describe_event(
            "ipa1",
            &entry(Some(theirs.clone()), &theirs),
            &expected,
            false,
        );
        assert_eq!(elsewhere["unexpected"], true, "{elsewhere}");
    }

    #[test]
    fn recovery_codes_are_128_bits_written_in_groups() {
        let code = new_recovery_code().unwrap();
        // 26 characters in groups of four: 7 groups, the last of two.
        assert_eq!(code.len(), 26 + 6, "{code}");
        assert_eq!(code.split('-').count(), 7);
        // The top character carries 3 bits only.
        assert!(b"ABCDEFGH".contains(&code.as_bytes()[0]), "{code}");
        assert_ne!(code, new_recovery_code().unwrap());
        // Written down any way, it is the same secret.
        let secret = recovery_secret(&code).unwrap();
        let sloppy = code.to_lowercase().replace('-', " ");
        assert_eq!(recovery_secret(&sloppy).unwrap().as_ref(), secret.as_ref());
        // Too short, too long, or a character outside the alphabet.
        let mut outside = code.clone();
        outside.replace_range(0..1, "1");
        for bad in [String::new(), "ABCD".into(), format!("{code}A"), outside] {
            assert!(recovery_secret(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_key_under_a_code_opens_only_with_it() {
        let key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let code = new_recovery_code().unwrap();
        let blob = protect_key(&key, recovery_secret(&code).unwrap().as_ref()).unwrap();
        let back = unprotect_key(&blob, recovery_secret(&code).unwrap().as_ref()).unwrap();
        assert_eq!(back.public().kid(), key.public().kid());
        let other = recovery_secret(&new_recovery_code().unwrap()).unwrap();
        assert!(unprotect_key(&blob, other.as_ref()).is_err());
    }
}
