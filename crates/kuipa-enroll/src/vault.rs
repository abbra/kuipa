//! User vaults (§7.6): policies, devices, the signed vault descriptor, the
//! operations that manage a vault, and files sealed to one.
//!
//! ```text
//! A, B ←$ 32 bytes                                server share, device share
//! DEK  = HKDF(A ‖ B, "vault dek", IPCV(P, V))     (B empty without factors.device)
//! for each server i:  (B_i, K_i, t_i) = tang-pqc provision to ek_i, committed to IPCV(P, V)
//!                     W_i = GCM_{K_i}(A)
//! for each device j:  (c_j, s_j) = ML-KEM.Encaps(dpk_j)
//!                     L_j = HKDF(s_j, "device", IPCV(P, V) ‖ id_j ‖ H(c_j));  U_j = GCM_{L_j}(B)
//! IPUF = P ‖ V ‖ [(server_i, B_i, ek_i, t_i, W_i)] ‖ [(id_j, c_j, U_j)] ‖ GCM_DEK(file)
//! ```
//!
//! An unlock is the unified recovery request ([`EscrowRequest`]) naming the
//! vault, with the device to answer to and, when the policy asks for it,
//! the owner's GSS-API token bound to the request.  With a device, the
//! server's answer is encrypted to that device's key ([`VaultAnswer`]).

use std::fmt;
use std::str::FromStr;

use native_ossl::rand::Rand;
use native_ossl::util::SecretBuf;
use serde::{Deserialize, Serialize};
use tang_pqc::primitives::{self, Domain};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{
    Binding, BindingContext, ExchangeKey, ExchangeKeyPair, KemAlg, Policy as CryptoPolicy,
    RecoveryResponse, SigningKey, Thumbprint, VerifyingKey, b64,
};

use crate::delegation::{Delegation, VerifiedDelegation};
use crate::error::{Error, Result};
use crate::escrow::{self, EscrowRequest, VaultId, commitment_data};
use crate::keytab::Principal;
use crate::realm::VerifiedRealm;

/// Domain of vault derivations: the data key, device shares, answers.
pub const DOMAIN: Domain = Domain::new("ipa-ku-enroll/v1 vault");

/// ML-DSA context of descriptor signatures.
pub const DESCRIPTOR_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 vault descriptor";

/// ML-DSA context of session token signatures.
pub const SESSION_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 vault session";

const DESCRIPTOR_MAGIC: [u8; 4] = *b"IPVD";
const REPLY_MAGIC: [u8; 4] = *b"IPVR";
const FILE_MAGIC: [u8; 4] = *b"IPUF";
const ANSWER_MAGIC: [u8; 4] = *b"IPVA";
const SESSION_MAGIC: [u8; 4] = *b"IPST";

const HASH: &std::ffi::CStr = c"SHA2-256";

/// What an attestation proved about a device key (§7.6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// Nothing is attested.
    Any,
    /// The key that wraps the device key is hardware-bound.
    HardwareWrapped,
    /// The device key itself is non-extractable hardware.
    HardwareBound,
}

/// Where a device key lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceType {
    /// An encrypted key file (PBES2).
    File,
    /// A key file wrapped by a passkey's PRF output.
    Passkey,
    /// A non-extractable ML-KEM key on a PKCS#11 token.
    Pkcs11,
    /// A key file wrapped by an AES key on a PKCS#11 token.
    Pkcs11Wrapped,
}

impl DeviceType {
    /// The highest level a device of this type can be granted.
    #[must_use]
    pub const fn highest(self) -> Level {
        match self {
            Self::File => Level::Any,
            Self::Passkey | Self::Pkcs11Wrapped => Level::HardwareWrapped,
            Self::Pkcs11 => Level::HardwareBound,
        }
    }
}

/// Which delegated tickets satisfy `factors.ticket` (§7.6.5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TicketDelegation {
    /// Any ticket naming the owner.
    #[default]
    Allow,
    /// Only tickets the owner obtained with their own credentials.
    Refuse,
    /// Delegated tickets whose every transited service is listed.
    Via(Vec<String>),
}

impl TicketDelegation {
    /// Does a ticket that passed through `transited` qualify?  `None`
    /// (the delegation is unknown) qualifies only for [`Self::Allow`].
    #[must_use]
    pub fn accepts(&self, transited: Option<&[String]>) -> bool {
        match (self, transited) {
            (Self::Allow, _) => true,
            (_, None) => false,
            (Self::Refuse, Some(t)) => t.is_empty(),
            (Self::Via(allowed), Some(t)) => t.iter().all(|s| allowed.contains(s)),
        }
    }
}

/// The factors an unlock needs besides the server's share.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Factors {
    /// A registered device of at least this level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<Level>,
    /// The owner's Kerberos ticket.
    #[serde(default)]
    pub ticket: bool,
    /// A passkey assertion from one of the owner's IPA passkeys.
    #[serde(default)]
    pub passkey: bool,
}

/// How bindings of the vault's files are authorised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Sealing {
    /// Commitment only: sealing needs no server.
    #[default]
    Offline,
    /// Each seal's bindings are registered, so a reseal retires a copy.
    Registered,
}

/// Session kinds the vault allows (§7.6.6).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sessions {
    /// The longest re-authentication session, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reauth: Option<u64>,
    /// The longest offline session, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline: Option<u64>,
}

/// A vault's policy (§7.6.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// The factors an unlock needs.
    pub factors: Factors,
    /// Which delegated tickets satisfy `factors.ticket`.
    #[serde(default)]
    pub ticket_delegation: TicketDelegation,
    /// No unlock after this time (Unix seconds); the server fills it in
    /// from the realm limits when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<u64>,
    /// Releases over the vault's life.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unlocks: Option<u64>,
    /// Sessions.
    #[serde(default)]
    pub sessions: Sessions,
    /// Sealing mode.
    #[serde(default)]
    pub sealing: Sealing,
}

impl Policy {
    fn refuse(why: impl Into<String>) -> Error {
        Error::Policy(why.into())
    }

    /// Check what any policy must satisfy, and what this build supports.
    ///
    /// # Errors
    ///
    /// [`Error::Policy`].
    pub fn validate(&self) -> Result<()> {
        let f = &self.factors;
        if f.device.is_none() && !f.ticket && !f.passkey {
            return Err(Self::refuse(
                "a vault needs a factor besides the server: device, ticket or passkey",
            ));
        }
        if f.passkey {
            return Err(Self::refuse("the passkey factor is not supported yet"));
        }
        if self.max_unlocks == Some(0) {
            return Err(Self::refuse("a vault that never unlocks"));
        }
        if self.sessions.reauth.is_some() && f.device.is_none() {
            return Err(Self::refuse(
                "re-authentication sessions need the device factor: a session token alone would open the vault",
            ));
        }
        if self.sessions.offline.is_some() {
            return Err(Self::refuse("offline sessions are not supported yet"));
        }
        if self.sealing == Sealing::Registered {
            return Err(Self::refuse("registered sealing is not supported yet"));
        }
        if let TicketDelegation::Via(list) = &self.ticket_delegation
            && list.is_empty()
        {
            return Err(Self::refuse("ticket delegation via an empty list"));
        }
        Ok(())
    }
}

/// What a realm lets its users choose (§7.6.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// The longest a vault may live, in seconds.
    pub max_lifetime: u64,
    /// The largest `max_unlocks`; `None` for no cap.
    #[serde(default)]
    pub max_unlocks: Option<u64>,
    /// Vaults per user.
    pub max_vaults: usize,
    /// Devices per vault.
    pub max_devices: usize,
    /// The longest re-authentication session, in seconds.
    pub max_reauth: u64,
    /// Whether offline sessions are allowed at all.
    #[serde(default)]
    pub offline_sessions: bool,
    /// Whether a vault may do without the device factor.
    pub without_device: bool,
    /// How old a descriptor may be when a client seals with it, in seconds.
    pub descriptor_age: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_lifetime: 400 * 86_400,
            max_unlocks: None,
            max_vaults: 16,
            max_devices: 8,
            max_reauth: 12 * 3600,
            offline_sessions: false,
            without_device: true,
            descriptor_age: 30 * 86_400,
        }
    }
}

impl Limits {
    /// Check `policy` (made valid) against these limits at `now`, filling
    /// in `not_after` when absent.
    ///
    /// # Errors
    ///
    /// [`Error::Policy`].
    pub fn apply(&self, policy: &mut Policy, now: u64) -> Result<()> {
        policy.validate()?;
        let latest = now.saturating_add(self.max_lifetime);
        let not_after = *policy.not_after.get_or_insert(latest);
        if not_after <= now {
            return Err(Policy::refuse("the vault would already be expired"));
        }
        if not_after > latest {
            return Err(Policy::refuse(format!(
                "the realm allows vaults for at most {} days",
                self.max_lifetime / 86_400
            )));
        }
        if let (Some(asked), Some(cap)) = (policy.max_unlocks, self.max_unlocks)
            && asked > cap
        {
            return Err(Policy::refuse(format!(
                "the realm allows at most {cap} unlocks"
            )));
        }
        if policy.sessions.reauth.is_some_and(|t| t > self.max_reauth) {
            return Err(Policy::refuse("re-authentication session too long"));
        }
        if policy.sessions.offline.is_some() && !self.offline_sessions {
            return Err(Policy::refuse("the realm does not allow offline sessions"));
        }
        if policy.factors.device.is_none() && !self.without_device {
            return Err(Policy::refuse("the realm requires the device factor"));
        }
        Ok(())
    }
}

/// A device key registered in a vault.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Thumbprint of the public key.
    pub id: String,
    /// The owner's label.
    pub label: String,
    /// Where the key lives.
    #[serde(rename = "type")]
    pub kind: DeviceType,
    /// The level granted at registration.
    pub level: Level,
    /// KEM id of the public key.
    pub alg: u8,
    /// The public key, base64url.
    pub key: String,
    /// When it was registered.
    pub added: u64,
}

impl Device {
    /// A device for `key`, at level [`Level::Any`] until an attestation
    /// proves more.
    #[must_use]
    pub fn new(key: &ExchangeKey, label: &str, kind: DeviceType, added: u64) -> Self {
        Self {
            id: key.kid().to_string(),
            label: label.to_owned(),
            kind,
            level: Level::Any,
            alg: key.alg().id(),
            key: b64::encode(key.as_bytes()),
            added,
        }
    }

    /// The public key, checked against the id.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] or [`Error::Mismatch`].
    pub fn public(&self) -> Result<ExchangeKey> {
        let key = ExchangeKey::from_bytes(KemAlg::from_id(self.alg)?, &b64::decode(&self.key)?)?;
        if key.kid().to_string() != self.id {
            return Err(Error::Mismatch("device key id"));
        }
        Ok(key)
    }

    /// The id.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn thumbprint(&self) -> Result<Thumbprint> {
        Thumbprint::from_str(&self.id).map_err(|_| Error::Malformed("device id"))
    }
}

/// Whether a vault still answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Unlocks are answered under the policy.
    #[default]
    Enabled,
    /// Nothing is answered any more.
    Revoked,
}

/// A vault as the directory stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    /// The id.
    pub id: VaultId,
    /// The owner's principal.
    pub owner: String,
    /// The owner's label, unique per owner.
    pub name: String,
    /// The policy.
    pub policy: Policy,
    /// Registered devices.
    #[serde(default)]
    pub devices: Vec<Device>,
    /// Enabled or revoked.
    #[serde(default)]
    pub state: State,
    /// Releases so far, summed over the servers (§7.6.7); kept by the
    /// directory, not by the owner.
    #[serde(default)]
    pub unlocks: u64,
}

impl Vault {
    /// The registered device `id`, if any.
    #[must_use]
    pub fn device(&self, id: &Thumbprint) -> Option<&Device> {
        let id = id.to_string();
        self.devices.iter().find(|d| d.id == id)
    }
}

/// What the descriptor signature covers.
#[derive(Serialize, Deserialize)]
struct DescriptorBody {
    realm: String,
    vault: Vault,
    iat: u64,
    /// The realm's `descriptor_age` limit: how long a client may seal with
    /// this descriptor.
    max_age: u64,
}

/// A vault as a server describes it, signed under its delegation, so a
/// client can seal offline with it and re-check it later (§7.6.3).
#[derive(Clone, PartialEq, Eq)]
pub struct Descriptor {
    body: Box<[u8]>,
    delegation: Box<[u8]>,
    signer_key: Box<[u8]>,
    signature: Box<[u8]>,
}

impl fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Descriptor").finish_non_exhaustive()
    }
}

impl Descriptor {
    /// Sign `vault` of `realm` as of `iat`.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn sign(
        signing: &SigningKey,
        delegation: &Delegation,
        realm: &str,
        vault: &Vault,
        iat: u64,
        max_age: u64,
    ) -> Result<Self> {
        let body = serde_json::to_vec(&DescriptorBody {
            realm: realm.to_owned(),
            vault: vault.clone(),
            iat,
            max_age,
        })
        .map_err(|_| Error::Malformed("vault descriptor"))?;
        let mut d = Self {
            body: body.into(),
            delegation: delegation.to_json().into_bytes().into(),
            signer_key: signing.public().to_jwk_json().into_bytes().into(),
            signature: Box::default(),
        };
        d.signature = signing
            .sign_with_context(&d.signed_part(), DESCRIPTOR_CONTEXT)?
            .into();
        Ok(d)
    }

    fn signed_part(&self) -> Vec<u8> {
        Writer::new(DESCRIPTOR_MAGIC)
            .bytes(&self.body)
            .bytes(&self.delegation)
            .bytes(&self.signer_key)
            .finish()
    }

    /// Verify the signature and the delegation as of the descriptor's own
    /// `iat`, against `anchors` for `realm`.
    ///
    /// # Errors
    ///
    /// [`Error::UntrustedAnchor`], [`Error::Expired`], [`Error::WrongRealm`],
    /// [`Error::Mismatch`] or a crypto error.
    pub fn verify(
        &self,
        realm: &str,
        anchors: &[Thumbprint],
        policy: &CryptoPolicy,
    ) -> Result<VerifiedDescriptor> {
        let body: DescriptorBody =
            serde_json::from_slice(&self.body).map_err(|_| Error::Malformed("vault descriptor"))?;
        let delegation =
            Delegation::from_json(&self.delegation)?.verify_at(anchors, policy, body.iat)?;
        if delegation.realm != realm || body.realm != realm {
            return Err(Error::WrongRealm);
        }
        let key = VerifyingKey::from_jwk_json(&self.signer_key)?;
        if key.thumbprint() != &delegation.key {
            return Err(Error::Mismatch("descriptor signer"));
        }
        key.verify_with_context(&self.signed_part(), DESCRIPTOR_CONTEXT, &self.signature)?;
        let owner: Principal = body.vault.owner.parse()?;
        if owner.realm() != realm {
            return Err(Error::WrongRealm);
        }
        Ok(VerifiedDescriptor {
            vault: body.vault,
            owner,
            iat: body.iat,
            max_age: body.max_age,
            delegation,
        })
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(DESCRIPTOR_MAGIC);
        w.bytes(&self.body)
            .bytes(&self.delegation)
            .bytes(&self.signer_key)
            .bytes(&self.signature);
        w.finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, DESCRIPTOR_MAGIC, "vault descriptor")?;
        let d = Self {
            body: r.bytes()?.into(),
            delegation: r.bytes()?.into(),
            signer_key: r.bytes()?.into(),
            signature: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(d)
    }
}

/// A descriptor whose signature chain verified.
#[derive(Debug)]
pub struct VerifiedDescriptor {
    vault: Vault,
    owner: Principal,
    iat: u64,
    max_age: u64,
    delegation: VerifiedDelegation,
}

impl VerifiedDescriptor {
    /// The vault.
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Its owner.
    #[must_use]
    pub fn owner(&self) -> &Principal {
        &self.owner
    }

    /// When the server signed it.
    #[must_use]
    pub fn iat(&self) -> u64 {
        self.iat
    }

    /// The server that signed it.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.delegation.server
    }

    /// How long after `iat` a client may seal with it: the realm's
    /// `descriptor_age`.
    #[must_use]
    pub fn max_age(&self) -> u64 {
        self.max_age
    }

    /// Whether a client may still seal with it at `now`: at most the
    /// realm's `descriptor_age` after it was signed.
    #[must_use]
    pub fn fresh_at(&self, now: u64) -> bool {
        now.saturating_sub(self.iat) <= self.max_age
    }
}

/// What an owner asks of their vaults, sent as the operation data of a
/// `POST /ipa/ku/vault/{kid}` exchange authenticated by their ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum VaultOp {
    /// Create a vault.
    Create {
        /// Its label.
        name: String,
        /// Its policy; the server fills in `not_after` and checks limits.
        policy: Policy,
    },
    /// Replace a vault's policy.
    SetPolicy {
        /// The vault.
        name: String,
        /// The new policy.
        policy: Policy,
    },
    /// Register a device.
    AddDevice {
        /// The vault.
        name: String,
        /// The device's label.
        label: String,
        /// Where its key lives.
        #[serde(rename = "type")]
        kind: DeviceType,
        /// KEM id.
        alg: u8,
        /// The public key, base64url.
        key: String,
    },
    /// Remove a device.
    RemoveDevice {
        /// The vault.
        name: String,
        /// The device's id.
        id: String,
    },
    /// Revoke a vault: nothing is answered for it any more.
    Revoke {
        /// The vault.
        name: String,
    },
    /// Describe one vault.
    Show {
        /// The vault.
        name: String,
    },
    /// Describe every vault of the owner.
    List,
    /// Start a re-authentication session for one of the vault's devices.
    Unlock {
        /// The vault.
        name: String,
        /// The device's id.
        device: String,
    },
}

impl VaultOp {
    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|_| Error::Malformed("vault operation"))
    }
}

/// What a vault operation answers with: descriptors, and for
/// [`VaultOp::Unlock`] a session token.
#[derive(Clone, Debug, Default)]
pub struct Reply {
    /// The vaults the operation concerned.
    pub descriptors: Vec<Descriptor>,
    /// A new session.
    pub session: Option<SessionToken>,
}

impl Reply {
    /// Encode: `IPVR n(u64) [descriptor] session` (session empty without
    /// one).
    ///
    /// # Panics
    ///
    /// Never for fewer than 2⁶⁴ descriptors.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(REPLY_MAGIC);
        w.u64(u64::try_from(self.descriptors.len()).expect("few descriptors"));
        for d in &self.descriptors {
            w.bytes(&d.to_bytes());
        }
        w.bytes(
            &self
                .session
                .as_ref()
                .map(SessionToken::to_bytes)
                .unwrap_or_default(),
        );
        w.finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, REPLY_MAGIC, "vault reply")?;
        let n = r.u64()?;
        let mut descriptors = Vec::new();
        for _ in 0..n {
            descriptors.push(Descriptor::from_bytes(r.bytes()?)?);
        }
        let session = match r.bytes()? {
            [] => None,
            b => Some(SessionToken::from_bytes(b)?),
        };
        r.finish()?;
        Ok(Self {
            descriptors,
            session,
        })
    }
}

/// A re-authentication session (§7.6.6): for `device` of `owner`'s vault,
/// until `not_after`, signed by a server under its delegation so any
/// server can check it.  It stands in for the ticket and passkey factors;
/// the answer is still encrypted to the device.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken {
    vault: VaultId,
    owner: String,
    device: Thumbprint,
    not_after: u64,
    delegation: Box<[u8]>,
    signer_key: Box<[u8]>,
    signature: Box<[u8]>,
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionToken")
            .field("vault", &self.vault)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl SessionToken {
    /// Sign a session.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn sign(
        signing: &SigningKey,
        delegation: &Delegation,
        vault: VaultId,
        owner: &str,
        device: Thumbprint,
        not_after: u64,
    ) -> Result<Self> {
        let mut t = Self {
            vault,
            owner: owner.to_owned(),
            device,
            not_after,
            delegation: delegation.to_json().into_bytes().into(),
            signer_key: signing.public().to_jwk_json().into_bytes().into(),
            signature: Box::default(),
        };
        t.signature = signing
            .sign_with_context(&t.signed_part(), SESSION_CONTEXT)?
            .into();
        Ok(t)
    }

    fn signed_part(&self) -> Vec<u8> {
        Writer::new(SESSION_MAGIC)
            .fixed(self.vault.as_bytes())
            .str(&self.owner)
            .fixed(self.device.as_bytes())
            .u64(self.not_after)
            .bytes(&self.delegation)
            .bytes(&self.signer_key)
            .finish()
    }

    /// Check the signature and its delegation against `anchors` of
    /// `realm`, and that the session is for `vault`, `owner` and `device`
    /// and lasts past `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Expired`], [`Error::Mismatch`], [`Error::UntrustedAnchor`],
    /// [`Error::WrongRealm`] or a crypto error.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        realm: &str,
        anchors: &[Thumbprint],
        policy: &CryptoPolicy,
        vault: &VaultId,
        owner: &str,
        device: &Thumbprint,
        now: u64,
    ) -> Result<()> {
        if &self.vault != vault || self.owner != owner || &self.device != device {
            return Err(Error::Mismatch("session"));
        }
        if now > self.not_after {
            return Err(Error::Expired);
        }
        let delegation =
            Delegation::from_json(&self.delegation)?.verify_at(anchors, policy, now)?;
        if delegation.realm != realm {
            return Err(Error::WrongRealm);
        }
        let key = VerifyingKey::from_jwk_json(&self.signer_key)?;
        if key.thumbprint() != &delegation.key {
            return Err(Error::Mismatch("session signer"));
        }
        key.verify_with_context(&self.signed_part(), SESSION_CONTEXT, &self.signature)?;
        Ok(())
    }

    /// The vault.
    #[must_use]
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// When the session ends.
    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(SESSION_MAGIC);
        w.bytes(&self.signed_part()).bytes(&self.signature);
        w.finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut outer = Reader::new(bytes, SESSION_MAGIC, "vault session")?;
        let signed = outer.bytes()?;
        let signature = outer.bytes()?.into();
        outer.finish()?;
        let mut r = Reader::new(signed, SESSION_MAGIC, "vault session")?;
        let t = Self {
            vault: VaultId::from_bytes(r.fixed()?),
            owner: r.str()?.to_owned(),
            device: Thumbprint::from_bytes(r.fixed()?),
            not_after: r.u64()?,
            delegation: r.bytes()?.into(),
            signer_key: r.bytes()?.into(),
            signature,
        };
        r.finish()?;
        Ok(t)
    }
}

/// A device key that can decapsulate: an [`ExchangeKeyPair`] in memory, or
/// a key held by a token.
pub trait DeviceKey {
    /// The thumbprint of its public key.
    fn id(&self) -> Thumbprint;
    /// Decapsulate `ciphertext`.
    ///
    /// # Errors
    ///
    /// A crypto or token error.
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<SecretBuf>;
}

impl DeviceKey for ExchangeKeyPair {
    fn id(&self) -> Thumbprint {
        *self.public().kid()
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Result<SecretBuf> {
        Ok(ExchangeKeyPair::decapsulate(self, ciphertext)?)
    }
}

/// The server's share, encrypted to a registered device: `IPVA(ct, sealed)`
/// with `k = HKDF(Decaps(ct), "answer", H(request))`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultAnswer {
    ciphertext: Box<[u8]>,
    sealed: Box<[u8]>,
}

fn answer_key(secret: &[u8], request: &EscrowRequest) -> Result<SecretBuf> {
    Ok(DOMAIN.derive_key(
        HASH,
        &[secret],
        "answer",
        &[&primitives::digest(HASH, &[&request.to_bytes()])?],
    )?)
}

impl VaultAnswer {
    /// Encrypt `response` to `device` for `request`.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn seal(
        device: &ExchangeKey,
        request: &EscrowRequest,
        response: &RecoveryResponse,
    ) -> Result<Self> {
        let (ciphertext, secret) = device.encapsulate()?;
        let key = answer_key(secret.as_ref(), request)?;
        Ok(Self {
            sealed: primitives::seal(key.as_ref(), &response.to_bytes())?.into(),
            ciphertext: ciphertext.into(),
        })
    }

    /// Open with the device the request named.
    ///
    /// # Errors
    ///
    /// [`Error::BadResponse`].
    pub fn open(
        &self,
        device: &dyn DeviceKey,
        request: &EscrowRequest,
    ) -> Result<RecoveryResponse> {
        let secret = device.decapsulate(&self.ciphertext)?;
        let key = answer_key(secret.as_ref(), request)?;
        let plain = primitives::open(key.as_ref(), &self.sealed).map_err(|_| Error::BadResponse)?;
        Ok(RecoveryResponse::from_bytes(plain.as_ref())?)
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(ANSWER_MAGIC)
            .bytes(&self.ciphertext)
            .bytes(&self.sealed)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, ANSWER_MAGIC, "vault answer")?;
        let a = Self {
            ciphertext: r.bytes()?.into(),
            sealed: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(a)
    }
}

/// What the server answers a recovery request with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recovered {
    /// Under the tang-pqc transport key only (machine vaults, and vaults
    /// answered without a device).
    Plain(RecoveryResponse),
    /// Encrypted to the device the request named.
    Device(VaultAnswer),
}

impl Recovered {
    /// The plain response, for a machine vault.
    #[must_use]
    pub fn into_plain(self) -> Option<RecoveryResponse> {
        match self {
            Self::Plain(r) => Some(r),
            Self::Device(_) => None,
        }
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Plain(r) => r.to_bytes(),
            Self::Device(a) => a.to_bytes(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ServerSlot {
    server: String,
    binding: Binding,
    escrow_key: ExchangeKey,
    commitment: [u8; 32],
    wrapped: Box<[u8]>,
}

#[derive(Clone, PartialEq, Eq)]
struct DeviceSlot {
    id: Thumbprint,
    ciphertext: Box<[u8]>,
    wrapped: Box<[u8]>,
}

/// A file sealed to a user vault.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedVaultFile {
    principal: Principal,
    vault: VaultId,
    servers: Vec<ServerSlot>,
    devices: Vec<DeviceSlot>,
    ciphertext: Box<[u8]>,
}

impl fmt::Debug for SealedVaultFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedVaultFile")
            .field("principal", &self.principal)
            .field("vault", &self.vault)
            .field("servers", &self.servers())
            .finish_non_exhaustive()
    }
}

fn device_key(secret: &[u8], committed: &[u8], id: &Thumbprint, ct: &[u8]) -> Result<SecretBuf> {
    Ok(DOMAIN.derive_key(
        HASH,
        &[secret],
        "device",
        &[committed, id.as_bytes(), &primitives::digest(HASH, &[ct])?],
    )?)
}

fn data_key(a: &[u8], b: &[u8], committed: &[u8]) -> Result<SecretBuf> {
    Ok(DOMAIN.derive_key(HASH, &[a, b], "dek", &[committed])?)
}

/// Makes the owner's GSS-API token for `ipa-ku@<server>` with the given
/// channel binding, or gives up on that server.
pub type TicketSource<'a> = &'a mut dyn FnMut(&str, &[u8; 32]) -> Option<Vec<u8>>;

/// What an unlock needs from its caller.
pub struct Unlock<'a> {
    /// The device to answer to, and whose share to open.
    pub device: Option<&'a dyn DeviceKey>,
    /// A re-authentication session, in place of the ticket.
    pub session: Option<&'a SessionToken>,
    /// A GSS-API token for `ipa-ku@<server>` bound to the request's
    /// [`EscrowRequest::ticket_binding`], when the vault needs a ticket.
    pub ticket: Option<TicketSource<'a>>,
}

impl SealedVaultFile {
    /// Seal `contents` to the vault `descriptor` describes, through the
    /// escrow keys of `servers`.  Works offline.
    ///
    /// # Errors
    ///
    /// [`Error::Policy`] for a revoked vault, [`Error::Missing`] without
    /// servers or, when the policy needs a device, without registered
    /// devices; [`Error::WrongRealm`] or a crypto error.
    pub fn seal(
        descriptor: &VerifiedDescriptor,
        servers: &[&VerifiedRealm],
        contents: &[u8],
    ) -> Result<Self> {
        let vault = descriptor.vault();
        if vault.state != State::Enabled {
            return Err(Error::Policy("the vault is revoked".into()));
        }
        if servers.is_empty() {
            return Err(Error::Missing("escrow servers"));
        }
        let principal = descriptor.owner().clone();
        let committed = commitment_data(&principal, &vault.id);
        let ctx = BindingContext::new(escrow::DOMAIN, &committed);
        let mut a = SecretBuf::with_len(32);
        Rand::fill_private(a.as_mut_slice())?;
        let mut slots = Vec::with_capacity(servers.len());
        for realm in servers {
            if realm.info().realm != principal.realm() {
                return Err(Error::WrongRealm);
            }
            let escrow_key = realm.escrow_key()?.clone();
            let (binding, key, commitment) = realm.advertisement().provision_committed(
                &ctx,
                Some(escrow_key.kid()),
                &committed,
            )?;
            slots.push(ServerSlot {
                server: realm.server().into(),
                wrapped: primitives::seal(key.as_ref(), a.as_ref())?.into(),
                binding,
                escrow_key,
                commitment,
            });
        }
        let mut devices = Vec::new();
        let mut b = SecretBuf::with_len(0);
        if vault.policy.factors.device.is_some() {
            if vault.devices.is_empty() {
                return Err(Error::Missing("registered devices"));
            }
            b = SecretBuf::with_len(32);
            Rand::fill_private(b.as_mut_slice())?;
            for d in &vault.devices {
                let public = d.public()?;
                let (ct, secret) = public.encapsulate()?;
                let key = device_key(secret.as_ref(), &committed, public.kid(), &ct)?;
                devices.push(DeviceSlot {
                    id: *public.kid(),
                    wrapped: primitives::seal(key.as_ref(), b.as_ref())?.into(),
                    ciphertext: ct.into(),
                });
            }
        }
        let dek = data_key(a.as_ref(), b.as_ref(), &committed)?;
        Ok(Self {
            principal,
            vault: vault.id,
            servers: slots,
            devices,
            ciphertext: primitives::seal(dek.as_ref(), contents)?.into(),
        })
    }

    /// The owner.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The vault.
    #[must_use]
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// The servers that can release the server share, in order.
    #[must_use]
    pub fn servers(&self) -> Vec<&str> {
        self.servers.iter().map(|s| s.server.as_str()).collect()
    }

    /// The devices that hold a device share.
    #[must_use]
    pub fn devices(&self) -> Vec<Thumbprint> {
        self.devices.iter().map(|d| d.id).collect()
    }

    /// Open, trying each server in turn.  `recover(server, request)` sends
    /// the request and returns the server's answer bytes, or `None`.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when the file has device shares and `unlock`
    /// names no device that holds one, [`Error::Refused`] if no server
    /// answered, [`Error::BadResponse`] or a crypto error.
    pub fn open(
        &self,
        mut unlock: Unlock<'_>,
        mut recover: impl FnMut(&str, &EscrowRequest) -> Option<Vec<u8>>,
    ) -> Result<SecretBuf> {
        let committed = commitment_data(&self.principal, &self.vault);
        let b = if self.devices.is_empty() {
            SecretBuf::with_len(0)
        } else {
            let device = unlock.device.ok_or(Error::Missing(
                "a device registered when the file was sealed",
            ))?;
            let slot = self
                .devices
                .iter()
                .find(|s| s.id == device.id())
                .ok_or(Error::Missing(
                    "a device registered when the file was sealed",
                ))?;
            let secret = device.decapsulate(&slot.ciphertext)?;
            let key = device_key(secret.as_ref(), &committed, &slot.id, &slot.ciphertext)?;
            primitives::open(key.as_ref(), &slot.wrapped).map_err(|_| Error::BadResponse)?
        };
        for slot in &self.servers {
            let (recovery, pending) = slot.binding.recovery_request(&slot.escrow_key)?;
            let mut request = EscrowRequest::for_vault(
                self.principal.clone(),
                self.vault,
                slot.commitment,
                recovery,
                unlock.device.map(DeviceKey::id),
            );
            if let Some(session) = unlock.session {
                request = request.with_session(session.to_bytes());
            }
            if let Some(ticket) = unlock.ticket.as_mut() {
                let Some(token) = ticket(&slot.server, &request.ticket_binding()?) else {
                    continue;
                };
                request = request.with_ticket(token);
            }
            let Some(answer) = recover(&slot.server, &request) else {
                continue;
            };
            let response = match unlock.device {
                Some(device) => {
                    VaultAnswer::from_bytes(&answer).and_then(|a| a.open(device, &request))
                }
                None => RecoveryResponse::from_bytes(&answer).map_err(Error::from),
            };
            let Ok(response) = response else { continue };
            let Ok(key) = pending.finish(&response) else {
                continue;
            };
            let a =
                primitives::open(key.as_ref(), &slot.wrapped).map_err(|_| Error::BadResponse)?;
            let dek = data_key(a.as_ref(), b.as_ref(), &committed)?;
            return primitives::open(dek.as_ref(), &self.ciphertext)
                .map_err(|_| Error::BadResponse);
        }
        Err(Error::Refused)
    }

    /// Encode.
    ///
    /// # Panics
    ///
    /// Never for files sealed by this crate (at most 255 servers and
    /// devices).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(FILE_MAGIC);
        w.str(&self.principal.to_string())
            .fixed(self.vault.as_bytes())
            .u8(u8::try_from(self.servers.len()).expect("at most 255 servers"));
        for s in &self.servers {
            w.str(&s.server)
                .bytes(&s.binding.to_bytes())
                .bytes(s.escrow_key.as_bytes())
                .fixed(&s.commitment)
                .bytes(&s.wrapped);
        }
        w.u8(u8::try_from(self.devices.len()).expect("at most 255 devices"));
        for d in &self.devices {
            w.fixed(d.id.as_bytes())
                .bytes(&d.ciphertext)
                .bytes(&d.wrapped);
        }
        w.bytes(&self.ciphertext).finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, FILE_MAGIC, "sealed vault file")?;
        let principal: Principal = r.str()?.parse()?;
        let vault = VaultId::from_bytes(r.fixed()?);
        let ctx = BindingContext::new(escrow::DOMAIN, &commitment_data(&principal, &vault));
        let servers = (0..r.u8()?)
            .map(|_| {
                let server = r.str()?.to_owned();
                let binding = Binding::from_bytes_with(&ctx, r.bytes()?)?;
                let escrow_key = ExchangeKey::from_bytes(binding.alg(), r.bytes()?)?;
                if escrow_key.kid() != binding.kid() {
                    return Err(Error::Mismatch("escrow key"));
                }
                Ok(ServerSlot {
                    server,
                    binding,
                    escrow_key,
                    commitment: r.fixed()?,
                    wrapped: r.bytes()?.into(),
                })
            })
            .collect::<Result<_>>()?;
        let devices = (0..r.u8()?)
            .map(|_| {
                Ok(DeviceSlot {
                    id: Thumbprint::from_bytes(r.fixed()?),
                    ciphertext: r.bytes()?.into(),
                    wrapped: r.bytes()?.into(),
                })
            })
            .collect::<Result<_>>()?;
        let ciphertext = r.bytes()?.into();
        r.finish()?;
        Ok(Self {
            principal,
            vault,
            servers,
            devices,
            ciphertext,
        })
    }
}
