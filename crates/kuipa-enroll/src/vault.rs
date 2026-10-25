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
use crate::escrow::{self, BindingHash, EscrowRequest, VaultId, commitment_data};
use crate::keytab::Principal;
use crate::realm::VerifiedRealm;
use crate::tlog::Receipt;

/// Domain of vault derivations: the data key, device shares, answers.
pub const DOMAIN: Domain = Domain::new("ipa-ku-enroll/v1 vault");

/// ML-DSA context of descriptor signatures.
pub const DESCRIPTOR_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 vault descriptor";

/// ML-DSA context of session token signatures.
pub const SESSION_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 vault session";

const DESCRIPTOR_MAGIC: [u8; 4] = *b"IPVD";
const REPLY_MAGIC: [u8; 4] = *b"IPVR";
/// Version 2 adds the receipts of the events an operation logged, 3 the
/// release requests, 4 device escrows, 5 deposits, 6 devices and the
/// realm's recovery settings.
const REPLY_VERSION: u8 = 6;
const FILE_MAGIC: [u8; 4] = *b"IPUF";
const ANSWER_MAGIC: [u8; 4] = *b"IPVA";
const SESSION_MAGIC: [u8; 4] = *b"IPST";
const SESSION_FILE_MAGIC: [u8; 4] = *b"IPUS";
const EPOCH_KEYS_MAGIC: [u8; 4] = *b"IPEK";
const DELIVERY_MAGIC: [u8; 4] = *b"IPDD";

/// How long an offline-session epoch lasts unless the policy says.
pub const DEFAULT_EPOCH: u64 = 30 * 86_400;

/// The hash of a derivation from one KEM's shared secret: that KEM's
/// suite hash (SHA-256 for ML-KEM-768, SHA-384 for ML-KEM-1024), named by
/// the ciphertext's length, as every KEM-bound hash is (DESIGN.md §4.1.1).
///
/// # Errors
///
/// [`Error::Malformed`] for a ciphertext of no ML-KEM set.
fn suite(ct: &[u8]) -> Result<&'static std::ffi::CStr> {
    tang_pqc::KemAlg::ALL
        .into_iter()
        .find(|a| a.ciphertext_len() == ct.len())
        .map(tang_pqc::KemAlg::hash)
        .ok_or(Error::Malformed("KEM ciphertext"))
}

/// The hash of a derivation over several KEMs' shares: the strongest
/// suite hash among them.
fn strongest(algs: impl IntoIterator<Item = tang_pqc::KemAlg>) -> &'static std::ffi::CStr {
    let strongest = algs
        .into_iter()
        .max_by_key(|a| primitives::digest_len(a.hash()))
        .unwrap_or(tang_pqc::KemAlg::MlKem768);
    strongest.hash()
}

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
    /// Any ticket naming the opener.
    #[default]
    Allow,
    /// Only tickets the opener obtained with their own credentials.
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
    /// The opener's Kerberos ticket: the owner's, or in a shared vault a
    /// manager's or member's.
    #[serde(default)]
    pub ticket: bool,
    /// A passkey assertion from one of the owner's IPA passkeys.
    #[serde(default)]
    pub passkey: bool,
}

impl Factors {
    /// Whether these factors include all of `least`'s: its device factor at
    /// its level or above, its ticket, its passkey.
    #[must_use]
    pub fn meets(&self, least: &Self) -> bool {
        least
            .device
            .is_none_or(|l| self.device.is_some_and(|d| d >= l))
            && (self.ticket || !least.ticket)
            && (self.passkey || !least.passkey)
    }
}

/// As `kuipa seal create --require` takes them: `device=any,ticket`.
impl fmt::Display for Factors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(level) = self.device {
            parts.push(format!(
                "device={}",
                serde_json::to_value(level)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            ));
        }
        if self.ticket {
            parts.push("ticket".to_owned());
        }
        if self.passkey {
            parts.push("passkey".to_owned());
        }
        if parts.is_empty() {
            parts.push("none".to_owned());
        }
        f.write_str(&parts.join(","))
    }
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
    /// How long one session key lasts before the next epoch's replaces it
    /// for new files, in seconds (default [`DEFAULT_EPOCH`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
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
    /// Approvals a release needs (`DESIGN-approvals.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvals: Option<Approvals>,
}

/// How long a release request waits for approvals and is then usable,
/// unless the policy says.
pub const DEFAULT_APPROVAL_WINDOW: u64 = 86_400;

/// The longest approval window a policy may set.
pub const MAX_APPROVAL_WINDOW: u64 = 7 * 86_400;

/// The longest reason a release request may give, in bytes.
pub const MAX_REASON: usize = 512;

/// A vault's approvals (`DESIGN-approvals.md` §1): `m` people of `from`,
/// other than the requester, approve a release before a server answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approvals {
    /// Approvals needed.
    pub m: u32,
    /// Who may approve, named as a shared vault's members are.
    pub from: Members,
    /// How long a request may wait for approvals and then be used, in
    /// seconds (default [`DEFAULT_APPROVAL_WINDOW`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<u64>,
    /// Releases one approved request covers (default 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uses: Option<u64>,
}

impl Approvals {
    /// The approval window, in seconds.
    #[must_use]
    pub fn window(&self) -> u64 {
        self.window.unwrap_or(DEFAULT_APPROVAL_WINDOW)
    }

    /// The releases a request covers.
    #[must_use]
    pub fn uses(&self) -> u64 {
        self.uses.unwrap_or(1)
    }

    fn validate(&self) -> Result<()> {
        if self.m == 0 {
            return Err(Policy::refuse("approvals of none"));
        }
        if self.from.is_empty() {
            return Err(Policy::refuse("approvals from no one"));
        }
        let only_users = self.from.groups.is_empty()
            && self.from.hosts.is_empty()
            && self.from.services.is_empty();
        if only_users && self.from.users.len() < usize::try_from(self.m).unwrap_or(usize::MAX) {
            return Err(Policy::refuse(format!(
                "{} approvals from {} users",
                self.m,
                self.from.users.len()
            )));
        }
        if !(1..=MAX_APPROVAL_WINDOW).contains(&self.window()) {
            return Err(Policy::refuse(
                "an approval window of no length or over 7 days",
            ));
        }
        if self.uses() == 0 {
            return Err(Policy::refuse("approved requests that cover no release"));
        }
        Ok(())
    }
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
        if self.sessions.offline.is_some() && f.device.is_none() {
            return Err(Self::refuse(
                "offline sessions need the device factor: the released key is encrypted to a device",
            ));
        }
        if self.sessions.epoch == Some(0) {
            return Err(Self::refuse("an epoch of no length"));
        }
        if let TicketDelegation::Via(list) = &self.ticket_delegation
            && list.is_empty()
        {
            return Err(Self::refuse("ticket delegation via an empty list"));
        }
        if let Some(approvals) = &self.approvals {
            approvals.validate()?;
            if self.sessions.offline.is_some() {
                return Err(Self::refuse(
                    "offline sessions open files without a server, hence without approvals",
                ));
            }
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
    /// Devices per vault and holder: each member of a shared vault
    /// registers up to this many.
    pub max_devices: usize,
    /// Entries in a vault's managers and members together (§7.6.12);
    /// 0 keeps every vault to its owner.
    #[serde(default = "default_max_members")]
    pub max_members: usize,
    /// Deposits per depositor and vault (`DESIGN-recovery.md` §3).
    #[serde(default = "default_max_deposits")]
    pub max_deposits: usize,
    /// The longest re-authentication session, in seconds.
    pub max_reauth: u64,
    /// Whether offline sessions are allowed at all.
    #[serde(default)]
    pub offline_sessions: bool,
    /// Whether a vault may do without the device factor.
    pub without_device: bool,
    /// How old a descriptor may be when a client seals with it, in seconds.
    pub descriptor_age: u64,
    /// The factors a policy needs at least: it must meet one of these
    /// sets ([`Factors::meets`]).  Empty: any non-empty combination.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<Factors>,
    /// Limits for the members of groups, in place of these where they
    /// say otherwise ([`Limits::for_groups`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupLimits>,
}

/// Limits for the members of one user group or host group: each field
/// set here replaces the realm's, the others are the realm's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupLimits {
    /// The group, by name.
    pub group: String,
    /// Of the groups a vault's owner is in, the one with the lowest
    /// priority applies (ties go to the group named first in byte order),
    /// as FreeIPA's password policies are chosen.
    pub priority: u32,
    /// What this group's members get instead of the realm's limits.
    #[serde(flatten)]
    pub set: LimitOverrides,
}

/// The fields of [`Limits`] a group can replace; `None` keeps the realm's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitOverrides {
    /// [`Limits::max_lifetime`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lifetime: Option<u64>,
    /// [`Limits::max_unlocks`]; `null` lifts the realm's cap.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub max_unlocks: Option<Option<u64>>,
    /// [`Limits::max_vaults`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_vaults: Option<usize>,
    /// [`Limits::max_devices`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_devices: Option<usize>,
    /// [`Limits::max_members`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_members: Option<usize>,
    /// [`Limits::max_deposits`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_deposits: Option<usize>,
    /// [`Limits::max_reauth`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_reauth: Option<u64>,
    /// [`Limits::offline_sessions`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_sessions: Option<bool>,
    /// [`Limits::without_device`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub without_device: Option<bool>,
    /// [`Limits::descriptor_age`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_age: Option<u64>,
    /// [`Limits::factors`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factors: Option<Vec<Factors>>,
}

/// A field that is present, `null` included: `Some` of what it holds.
fn present<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

const fn default_max_members() -> usize {
    64
}

const fn default_max_deposits() -> usize {
    32
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_lifetime: 400 * 86_400,
            max_unlocks: None,
            max_vaults: 16,
            max_devices: 8,
            max_members: default_max_members(),
            max_deposits: default_max_deposits(),
            max_reauth: 12 * 3600,
            offline_sessions: false,
            without_device: true,
            descriptor_age: 30 * 86_400,
            factors: Vec::new(),
            groups: Vec::new(),
        }
    }
}

impl Limits {
    /// The limits for a vault whose owner is a member of `groups`: those
    /// of the matching group with the lowest priority over the realm's,
    /// or the realm's.  The result names no groups.
    #[must_use]
    pub fn for_groups(&self, groups: &[String]) -> Self {
        let mut out = Self {
            groups: Vec::new(),
            ..self.clone()
        };
        let Some(chosen) = self
            .groups
            .iter()
            .filter(|g| groups.contains(&g.group))
            .min_by(|a, b| (a.priority, &a.group).cmp(&(b.priority, &b.group)))
        else {
            return out;
        };
        let o = chosen.set.clone();
        out.max_lifetime = o.max_lifetime.unwrap_or(out.max_lifetime);
        out.max_unlocks = o.max_unlocks.unwrap_or(out.max_unlocks);
        out.max_vaults = o.max_vaults.unwrap_or(out.max_vaults);
        out.max_devices = o.max_devices.unwrap_or(out.max_devices);
        out.max_members = o.max_members.unwrap_or(out.max_members);
        out.max_deposits = o.max_deposits.unwrap_or(out.max_deposits);
        out.max_reauth = o.max_reauth.unwrap_or(out.max_reauth);
        out.offline_sessions = o.offline_sessions.unwrap_or(out.offline_sessions);
        out.without_device = o.without_device.unwrap_or(out.without_device);
        out.descriptor_age = o.descriptor_age.unwrap_or(out.descriptor_age);
        out.factors = o.factors.unwrap_or(out.factors);
        out
    }

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
        if !self.factors.is_empty() && !self.factors.iter().any(|f| policy.factors.meets(f)) {
            let sets: Vec<String> = self.factors.iter().map(Factors::to_string).collect();
            return Err(Policy::refuse(format!(
                "the realm requires the factors of one of: {}",
                sets.join("; ")
            )));
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
    /// The principal who registered it, and who alone opens with it;
    /// absent on devices registered before shared vaults, which are the
    /// owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
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
            holder: None,
        }
    }

    /// The same device, held by `holder`.
    #[must_use]
    pub fn held_by(mut self, holder: &str) -> Self {
        self.holder = Some(holder.to_owned());
        self
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
    /// Who manages the vault besides its owner: its policy, members and
    /// state (§7.6.12).
    #[serde(default, skip_serializing_if = "Members::is_empty")]
    pub managers: Members,
    /// Who opens and seals with it besides its owner and managers.
    #[serde(default, skip_serializing_if = "Members::is_empty")]
    pub members: Members,
    /// Who seals to it and deposits, without opening.
    #[serde(default, skip_serializing_if = "Members::is_empty")]
    pub depositors: Members,
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
    /// Offline-session keys, one per epoch, oldest first (§7.6.6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub session_keys: Vec<SessionKey>,
    /// With `sealing = registered`: the `H(ct)` (hex) of every binding of
    /// a file sealed and not yet retired; left out of descriptors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<String>,
}

/// Who shares a vault: users, user and host groups (by the directory's
/// `memberOf`), hosts and services, as the signing policy names signers.
pub type Members = crate::sign::Signers;

/// What a principal may do with a vault (§7.6.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Seal to it and deposit, but never open (`DESIGN-recovery.md` §3).
    Depositor,
    /// Open and seal, and register and remove its own devices.
    Member,
    /// Also change the policy, the managers and members, and revoke.
    Manager,
    /// The vault's owner: a manager, and the `P` its files are sealed to.
    Owner,
}

/// Split a vault reference, `NAME` (the caller's own) or `OWNER/NAME`
/// (one shared with the caller), at its last `/`.
#[must_use]
pub fn split_ref(reference: &str) -> (Option<&str>, &str) {
    match reference.rsplit_once('/') {
        Some((owner, name)) => (Some(owner), name),
        None => (None, reference),
    }
}

/// The most bindings a vault keeps registered.
pub const MAX_BINDINGS: usize = 4096;

/// A binding hash as the vault stores it.
#[must_use]
pub fn binding_hex(hash: &BindingHash) -> String {
    use std::fmt::Write as _;
    hash.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// One server's way into a session key: the key's private JWK sealed to
/// the server's escrow key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeySlot {
    /// The server.
    pub server: String,
    /// Its escrow key's id.
    pub kid: String,
    /// The encapsulation to it, base64url.
    pub ct: String,
    /// The sealed private JWK, base64url.
    pub wrapped: String,
}

/// A vault's offline-session key for one epoch: the public half for
/// sealing, the private half sealed to each server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    /// The epoch's number, from 1.
    pub epoch: u64,
    /// When the epoch began.
    pub started: u64,
    /// KEM id.
    pub alg: u8,
    /// The public key, base64url.
    pub key: String,
    /// The private key's slots; left out of descriptors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slots: Vec<SessionKeySlot>,
}

fn session_slot_key(
    secret: &[u8],
    vault: &VaultId,
    epoch: u64,
    server: &str,
    ct: &[u8],
) -> Result<SecretBuf> {
    let hash = suite(ct)?;
    Ok(DOMAIN.derive_key(
        hash,
        &[secret],
        "session key",
        &[
            vault.as_bytes(),
            &epoch.to_be_bytes(),
            server.as_bytes(),
            &primitives::digest(hash, &[ct])?,
        ],
    )?)
}

impl SessionKey {
    /// A new epoch's key for `vault`, sealed to each `(server, escrow key)`.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn generate(
        vault: &VaultId,
        epoch: u64,
        started: u64,
        servers: &[(String, ExchangeKey)],
    ) -> Result<Self> {
        let pair = ExchangeKeyPair::generate(KemAlg::MlKem768)?;
        let mut key = Self {
            epoch,
            started,
            alg: pair.public().alg().id(),
            key: b64::encode(pair.public().as_bytes()),
            slots: Vec::new(),
        };
        key.add_slots(vault, &pair, servers)?;
        Ok(key)
    }

    /// Seal the private key to each server in `servers` it has no slot for
    /// yet.  Returns whether a slot was added.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn add_slots(
        &mut self,
        vault: &VaultId,
        pair: &ExchangeKeyPair,
        servers: &[(String, ExchangeKey)],
    ) -> Result<bool> {
        let jwk = pair.to_jwk()?;
        let mut added = false;
        for (server, ek) in servers {
            let kid = ek.kid().to_string();
            if self.slots.iter().any(|s| s.kid == kid) {
                continue;
            }
            let (ct, secret) = ek.encapsulate()?;
            let k = session_slot_key(secret.as_ref(), vault, self.epoch, server, &ct)?;
            self.slots.push(SessionKeySlot {
                server: server.clone(),
                kid,
                ct: b64::encode(&ct),
                wrapped: b64::encode(&primitives::seal(k.as_ref(), jwk.as_ref())?),
            });
            added = true;
        }
        Ok(added)
    }

    /// Open the private key with one of `escrow` (a server's own keys).
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] when no slot is for any of them, or a crypto
    /// error.
    pub fn open(&self, vault: &VaultId, escrow: &[ExchangeKeyPair]) -> Result<ExchangeKeyPair> {
        for slot in &self.slots {
            let Some(own) = escrow
                .iter()
                .find(|k| k.public().kid().to_string() == slot.kid)
            else {
                continue;
            };
            let ct = b64::decode(&slot.ct)?;
            let secret = own.decapsulate(&ct)?;
            let k = session_slot_key(secret.as_ref(), vault, self.epoch, &slot.server, &ct)?;
            let jwk = primitives::open(k.as_ref(), &b64::decode(&slot.wrapped)?)
                .map_err(|_| Error::Malformed("session key slot"))?;
            return Ok(ExchangeKeyPair::from_jwk(jwk.as_ref())?);
        }
        Err(Error::Missing("a session key slot for this server"))
    }

    /// The public key.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn public(&self) -> Result<ExchangeKey> {
        Ok(ExchangeKey::from_bytes(
            KemAlg::from_id(self.alg)?,
            &b64::decode(&self.key)?,
        )?)
    }
}

/// Session keys released by an offline unlock, encrypted to the device:
/// `IPEK(ct, GCM_k([epoch, private JWK]…))`, `k` from the device's
/// decapsulation of `ct`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasedKeys {
    ciphertext: Box<[u8]>,
    sealed: Box<[u8]>,
}

fn released_key(secret: &[u8], vault: &VaultId, ct: &[u8]) -> Result<SecretBuf> {
    let hash = suite(ct)?;
    Ok(DOMAIN.derive_key(
        hash,
        &[secret],
        "released keys",
        &[vault.as_bytes(), &primitives::digest(hash, &[ct])?],
    )?)
}

impl ReleasedKeys {
    /// Encrypt `keys` (epoch, key) of `vault` to `device`.
    ///
    /// # Errors
    ///
    /// A crypto error.
    ///
    /// # Panics
    ///
    /// Never for fewer than 2⁶⁴ keys.
    pub fn seal(
        device: &ExchangeKey,
        vault: &VaultId,
        keys: &[(u64, ExchangeKeyPair)],
    ) -> Result<Self> {
        let mut plain = Writer::new(EPOCH_KEYS_MAGIC);
        plain.u64(u64::try_from(keys.len()).expect("few epochs"));
        for (epoch, key) in keys {
            plain.u64(*epoch).bytes(key.to_jwk()?.as_ref());
        }
        let plain = SecretBuf::new(plain.finish());
        let (ct, secret) = device.encapsulate()?;
        let k = released_key(secret.as_ref(), vault, &ct)?;
        Ok(Self {
            sealed: primitives::seal(k.as_ref(), plain.as_ref())?.into(),
            ciphertext: ct.into(),
        })
    }

    /// Open with the device.
    ///
    /// # Errors
    ///
    /// [`Error::BadResponse`] or [`Error::Malformed`].
    pub fn open(
        &self,
        device: &dyn DeviceKey,
        vault: &VaultId,
    ) -> Result<Vec<(u64, ExchangeKeyPair)>> {
        let secret = device.decapsulate(&self.ciphertext)?;
        let k = released_key(secret.as_ref(), vault, &self.ciphertext)?;
        let plain = primitives::open(k.as_ref(), &self.sealed).map_err(|_| Error::BadResponse)?;
        let mut r = Reader::new(plain.as_ref(), EPOCH_KEYS_MAGIC, "released keys")?;
        let n = r.u64()?;
        let mut keys = Vec::new();
        for _ in 0..n {
            let epoch = r.u64()?;
            keys.push((epoch, ExchangeKeyPair::from_jwk(r.bytes()?)?));
        }
        r.finish()?;
        Ok(keys)
    }

    /// Encode: `ct sealed`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(EPOCH_KEYS_MAGIC)
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
        let mut r = Reader::new(bytes, EPOCH_KEYS_MAGIC, "released keys")?;
        let k = Self {
            ciphertext: r.bytes()?.into(),
            sealed: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(k)
    }
}

/// A file sealed for offline sessions (§7.6.6): the server share sealed to
/// the vault's epoch key instead of through the servers' escrow keys.
///
/// ```text
/// IPUS = P ‖ V ‖ epoch ‖ c_e ‖ GCM_{HKDF(Decaps(dk_e, c_e))}(A) ‖ [(id_j, c_j, U_j)] ‖ GCM_DEK(file)
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SessionSealedFile {
    principal: Principal,
    vault: VaultId,
    epoch: u64,
    ciphertext_e: Box<[u8]>,
    wrapped_a: Box<[u8]>,
    devices: Vec<DeviceSlot>,
    ciphertext: Box<[u8]>,
}

impl fmt::Debug for SessionSealedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSealedFile")
            .field("vault", &self.vault)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

fn epoch_share_key(secret: &[u8], committed: &[u8], epoch: u64, ct: &[u8]) -> Result<SecretBuf> {
    let hash = suite(ct)?;
    Ok(DOMAIN.derive_key(
        hash,
        &[secret],
        "epoch share",
        &[
            committed,
            &epoch.to_be_bytes(),
            &primitives::digest(hash, &[ct])?,
        ],
    )?)
}

impl SessionSealedFile {
    /// Seal `contents` to the vault's current epoch key and its devices.
    ///
    /// # Errors
    ///
    /// [`Error::Policy`] for a revoked vault or one without offline
    /// sessions, [`Error::Missing`] without devices, or a crypto error.
    pub fn seal(descriptor: &VerifiedDescriptor, contents: &[u8]) -> Result<Self> {
        let vault = descriptor.vault();
        if vault.state != State::Enabled {
            return Err(Error::Policy("the vault is revoked".into()));
        }
        let current = vault
            .session_keys
            .last()
            .filter(|_| vault.policy.sessions.offline.is_some())
            .ok_or_else(|| Error::Policy("the vault has no offline sessions".into()))?;
        let principal = descriptor.owner().clone();
        let committed = commitment_data(&principal, &vault.id);
        let mut a = SecretBuf::with_len(32);
        Rand::fill_private(a.as_mut_slice())?;
        let (ct_e, secret_e) = current.public()?.encapsulate()?;
        let k_e = epoch_share_key(secret_e.as_ref(), &committed, current.epoch, &ct_e)?;
        let (devices, b) = device_slots(vault, &committed)?;
        let dek = data_key(suite(&ct_e)?, a.as_ref(), b.as_ref(), &committed)?;
        Ok(Self {
            wrapped_a: primitives::seal(k_e.as_ref(), a.as_ref())?.into(),
            ciphertext_e: ct_e.into(),
            principal,
            vault: vault.id,
            epoch: current.epoch,
            devices,
            ciphertext: primitives::seal(dek.as_ref(), contents)?.into(),
        })
    }

    /// The vault.
    #[must_use]
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// The epoch whose key opens the server share.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Open with the epoch's key (from an offline unlock) and the device.
    ///
    /// # Errors
    ///
    /// [`Error::BadResponse`] for the wrong keys, or a crypto error.
    pub fn open(&self, epoch_key: &ExchangeKeyPair, device: &dyn DeviceKey) -> Result<SecretBuf> {
        let committed = commitment_data(&self.principal, &self.vault);
        let secret_e = epoch_key.decapsulate(&self.ciphertext_e)?;
        let k_e = epoch_share_key(
            secret_e.as_ref(),
            &committed,
            self.epoch,
            &self.ciphertext_e,
        )?;
        let a = primitives::open(k_e.as_ref(), &self.wrapped_a).map_err(|_| Error::BadResponse)?;
        let b = open_device_share(&self.devices, device, &committed)?;
        let dek = data_key(
            suite(&self.ciphertext_e)?,
            a.as_ref(),
            b.as_ref(),
            &committed,
        )?;
        primitives::open(dek.as_ref(), &self.ciphertext).map_err(|_| Error::BadResponse)
    }

    /// Encode.
    ///
    /// # Panics
    ///
    /// Never for files sealed by this crate (at most 255 devices).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(SESSION_FILE_MAGIC);
        w.str(&self.principal.to_string())
            .fixed(self.vault.as_bytes())
            .u64(self.epoch)
            .bytes(&self.ciphertext_e)
            .bytes(&self.wrapped_a)
            .u8(u8::try_from(self.devices.len()).expect("at most 255 devices"));
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
        let mut r = Reader::new(bytes, SESSION_FILE_MAGIC, "session-sealed file")?;
        let principal = r.str()?.parse()?;
        let vault = VaultId::from_bytes(r.fixed()?);
        let epoch = r.u64()?;
        let ciphertext_e = r.bytes()?.into();
        let wrapped_a = r.bytes()?.into();
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
            epoch,
            ciphertext_e,
            wrapped_a,
            devices,
            ciphertext,
        })
    }
}

/// The device share `B` and a slot per registered device, or nothing
/// without the device factor.
fn device_slots(vault: &Vault, committed: &[u8]) -> Result<(Vec<DeviceSlot>, SecretBuf)> {
    if vault.policy.factors.device.is_none() {
        return Ok((Vec::new(), SecretBuf::with_len(0)));
    }
    if vault.devices.is_empty() {
        return Err(Error::Missing("registered devices"));
    }
    let mut b = SecretBuf::with_len(32);
    Rand::fill_private(b.as_mut_slice())?;
    let mut devices = Vec::new();
    for d in &vault.devices {
        let public = d.public()?;
        let (ct, secret) = public.encapsulate()?;
        let key = device_key(secret.as_ref(), committed, public.kid(), &ct)?;
        devices.push(DeviceSlot {
            id: *public.kid(),
            wrapped: primitives::seal(key.as_ref(), b.as_ref())?.into(),
            ciphertext: ct.into(),
        });
    }
    Ok((devices, b))
}

/// Open the device share with `device`, or nothing when there are no
/// device slots.
fn open_device_share(
    slots: &[DeviceSlot],
    device: &dyn DeviceKey,
    committed: &[u8],
) -> Result<SecretBuf> {
    if slots.is_empty() {
        return Ok(SecretBuf::with_len(0));
    }
    let slot = slots
        .iter()
        .find(|s| s.id == device.id())
        .ok_or(Error::Missing(
            "a device registered when the file was sealed",
        ))?;
    let secret = device.decapsulate(&slot.ciphertext)?;
    let key = device_key(secret.as_ref(), committed, &slot.id, &slot.ciphertext)?;
    primitives::open(key.as_ref(), &slot.wrapped).map_err(|_| Error::BadResponse)
}

impl Vault {
    /// What `principal`, a member of `groups`, may do with this vault, if
    /// anything.
    #[must_use]
    pub fn role(&self, principal: &Principal, groups: &[String]) -> Option<Role> {
        if principal.to_string() == self.owner {
            Some(Role::Owner)
        } else if self.managers.admits(principal, groups) {
            Some(Role::Manager)
        } else if self.members.admits(principal, groups) {
            Some(Role::Member)
        } else if self.depositors.admits(principal, groups) {
            Some(Role::Depositor)
        } else {
            None
        }
    }

    /// Whether `principal`, a member of `groups`, may open the vault's
    /// files: any role but depositor.
    #[must_use]
    pub fn opens(&self, principal: &Principal, groups: &[String]) -> bool {
        self.role(principal, groups)
            .is_some_and(|r| r >= Role::Member)
    }

    /// Whether anyone besides the owner shares it.
    #[must_use]
    pub fn is_shared(&self) -> bool {
        !self.managers.is_empty() || !self.members.is_empty() || !self.depositors.is_empty()
    }

    /// Who shares it, as the transparency log digests it after a share or
    /// an unshare.
    #[must_use]
    pub fn sharing_bytes(&self) -> Vec<u8> {
        // Depositors join the digest only when there are any, so the
        // digests logged before them stay what they were.
        if self.depositors.is_empty() {
            serde_json::to_vec(&(&self.managers, &self.members))
        } else {
            serde_json::to_vec(&(&self.managers, &self.members, &self.depositors))
        }
        .unwrap_or_default()
    }

    /// Who holds `device`: its holder, else the owner.
    #[must_use]
    pub fn holder<'a>(&'a self, device: &'a Device) -> &'a str {
        device.holder.as_deref().unwrap_or(&self.owner)
    }

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

/// One approval or denial of a release request: who, and when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// The approver.
    pub approver: String,
    /// When (Unix seconds).
    pub at: u64,
}

/// A request for the release of a file of a vault with approvals
/// (`DESIGN-approvals.md` §2), as the directory keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// The id: 16 random bytes, hex.
    pub id: String,
    /// The vault.
    pub vault: VaultId,
    /// Who asked, and alone may use it.
    pub requester: String,
    /// The binding hashes `H(ct)` (hex) of the file or files it is for.
    pub bindings: Vec<String>,
    /// Why, for the approvers.
    pub reason: String,
    /// When it was made.
    pub created: u64,
    /// No approval or release after this time.
    pub not_after: u64,
    /// The approvals so far, kept by the directory.
    #[serde(default)]
    pub approvals: Vec<Approval>,
    /// The denial that ended it, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied: Option<Approval>,
    /// Releases made with it so far, summed over the servers.
    #[serde(default)]
    pub uses: u64,
}

impl ReleaseRequest {
    /// Whether approvals and releases may still be made with it at `now`.
    #[must_use]
    pub fn is_open(&self, now: u64) -> bool {
        self.denied.is_none() && now <= self.not_after
    }

    /// What the transparency log digests for the request: everything but
    /// what the directory adds later.
    #[must_use]
    pub fn log_bytes(&self) -> Vec<u8> {
        let core = Self {
            approvals: Vec::new(),
            denied: None,
            uses: 0,
            ..self.clone()
        };
        serde_json::to_vec(&core).unwrap_or_default()
    }

    /// The id as the 16 bytes a recovery request carries.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an id that is not 32 hex digits.
    pub fn id_bytes(id: &str) -> Result<[u8; 16]> {
        let mut out = [0u8; 16];
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Malformed("release request id"));
        }
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&id[2 * i..2 * i + 2], 16)
                .map_err(|_| Error::Malformed("release request id"))?;
        }
        Ok(out)
    }
}

/// The largest deposit a server keeps, in bytes of its sealed file.
pub const MAX_DEPOSIT: usize = 16 * 1024;

/// What a deposit holds (`DESIGN-recovery.md` §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepositKind {
    /// A user's device key, for helpdesk recovery.
    Device,
    /// A LUKS volume's recovery key.
    Luks,
    /// Any small secret: a backup repository's password, say.
    File,
}

/// A file sealed to a vault that its servers keep for the members: its
/// depositor may be gone when anyone needs it (`DESIGN-recovery.md` §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    /// The id: 16 random bytes, hex.
    pub id: String,
    /// The vault.
    pub vault: VaultId,
    /// Who deposited it.
    pub depositor: String,
    /// What it holds.
    pub kind: DepositKind,
    /// What it is for, among the depositor's deposits of this kind: a
    /// device id, a volume's UUID, a name.
    pub subject: std::collections::BTreeMap<String, String>,
    /// When it was deposited.
    pub added: u64,
    /// The sealed file (`IPUF`), base64url; left out of listings.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sealed: String,
}

/// The realm's device-key recovery (`DESIGN-recovery.md` §4), on
/// `cn=recovery,cn=kuipa,cn=etc` (`ipaKURecovery`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySettings {
    /// The helpdesk vault device keys are deposited to, `OWNER/NAME`.
    pub device_vault: String,
    /// Whether an extractable device is registered only once its key is
    /// deposited there.
    #[serde(default)]
    pub required: bool,
}

/// A recovered device key on its way to its holder's new device
/// (`DESIGN-recovery.md` §4): `IPDD ct sealed`, the key's private JWK
/// sealed under a key from an ML-KEM encapsulation to the new device.
///
/// # Errors
///
/// A crypto error.
pub fn seal_delivery(to: &ExchangeKey, key: &ExchangeKeyPair) -> Result<Vec<u8>> {
    let (ct, secret) = to.encapsulate()?;
    let k = delivery_key(secret.as_ref(), to.kid(), &ct)?;
    let sealed = primitives::seal(k.as_ref(), key.to_jwk()?.as_ref())?;
    Ok(Writer::new(DELIVERY_MAGIC)
        .bytes(&ct)
        .bytes(&sealed)
        .finish())
}

/// The key a delivery holds, opened with the device it was sealed to.
///
/// # Errors
///
/// [`Error::Malformed`], or [`Error::BadResponse`] for another device's.
pub fn open_delivery(bytes: &[u8], device: &dyn DeviceKey) -> Result<ExchangeKeyPair> {
    let mut r = Reader::new(bytes, DELIVERY_MAGIC, "device delivery")?;
    let ct = r.bytes()?.to_vec();
    let sealed = r.bytes()?.to_vec();
    r.finish()?;
    let secret = device.decapsulate(&ct)?;
    let k = delivery_key(secret.as_ref(), &device.id(), &ct)?;
    let jwk = primitives::open(k.as_ref(), &sealed).map_err(|_| Error::BadResponse)?;
    ExchangeKeyPair::from_jwk(jwk.as_ref()).map_err(Into::into)
}

fn delivery_key(secret: &[u8], to: &Thumbprint, ct: &[u8]) -> Result<SecretBuf> {
    let hash = suite(ct)?;
    Ok(DOMAIN.derive_key(
        hash,
        &[secret],
        "device delivery",
        &[to.as_bytes(), &primitives::digest(hash, &[ct])?],
    )?)
}

/// The largest escrowed device key a server keeps, in bytes.
pub const MAX_ESCROW_BLOB: usize = 16 * 1024;

/// A device key kept for recovery (`DESIGN-recovery.md` §2), on its
/// holder's own entry: the private key under a key derived from a
/// recovery code only the holder has, in the `device.key` format.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEscrow {
    /// The device's id.
    pub device: String,
    /// How it is protected: `code`.
    pub kind: String,
    /// The protected key, base64url.
    pub blob: String,
    /// When it was escrowed.
    pub added: u64,
}

/// What a user asks of their vaults, sent as the operation data of a
/// `POST /ipa/ku/vault/{kid}` exchange authenticated by their ticket.
/// Every `name` is a vault reference: `NAME` for the caller's own vault,
/// `OWNER/NAME` for one shared with them ([`split_ref`]).
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
    /// Describe every vault of the caller, and those shared with them.
    List,
    /// With `sealing = registered`: register the bindings of a newly sealed
    /// file, and retire those of files it replaces or that are given up.
    Register {
        /// The vault.
        name: String,
        /// Binding hashes (hex) to register.
        add: Vec<String>,
        /// Binding hashes (hex) to retire.
        retire: Vec<String>,
    },
    /// Add managers or members (§7.6.12); managers only.
    Share {
        /// The vault.
        name: String,
        /// New managers.
        #[serde(default)]
        managers: Members,
        /// New members.
        #[serde(default)]
        members: Members,
        /// New depositors.
        #[serde(default)]
        depositors: Members,
    },
    /// Remove managers or members, and the devices they hold; managers
    /// only, but anyone may leave.
    Unshare {
        /// The vault.
        name: String,
        /// Managers to remove.
        #[serde(default)]
        managers: Members,
        /// Members to remove.
        #[serde(default)]
        members: Members,
        /// Depositors to remove.
        #[serde(default)]
        depositors: Members,
    },
    /// Ask for the release of the file whose bindings these are, from a
    /// vault with approvals (`DESIGN-approvals.md` §2).
    Request {
        /// The vault.
        name: String,
        /// The file's binding hashes (hex).
        bindings: Vec<String>,
        /// Why, for the approvers.
        reason: String,
    },
    /// The open release requests of the vault, or of every vault whose
    /// approvers or members include the caller.
    Pending {
        /// The vault, if just one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// Approve a release request.
    Approve {
        /// The vault.
        name: String,
        /// The request.
        id: String,
    },
    /// Deny a release request: it ends on every server.
    Deny {
        /// The vault.
        name: String,
        /// The request.
        id: String,
    },
    /// Keep `blob`, device `device`'s key under a recovery code, on the
    /// caller's entry, in place of any earlier one for that device.
    EscrowCode {
        /// The device's id; the caller must hold it in one of their vaults.
        device: String,
        /// The protected key, base64url.
        blob: String,
    },
    /// The caller's device keys kept under recovery codes.
    RecoverCode,
    /// Keep `sealed`, a file sealed to the vault, as a deposit, in place
    /// of the depositor's earlier one of the same kind and subject.
    Deposit {
        /// The vault.
        name: String,
        /// What it holds.
        kind: DepositKind,
        /// What it is for.
        subject: std::collections::BTreeMap<String, String>,
        /// The sealed file, base64url.
        sealed: String,
    },
    /// The vault's deposits, without their files: all of them for its
    /// members, their own for a depositor.
    Deposits {
        /// The vault.
        name: String,
    },
    /// One deposit, with its file; members only.
    FetchDeposit {
        /// The vault.
        name: String,
        /// The deposit.
        id: String,
    },
    /// Remove a deposit: a depositor's own, or any for a manager.
    RetireDeposit {
        /// The vault.
        name: String,
        /// The deposit.
        id: String,
    },
    /// The realm's recovery settings.
    RecoverySettings,
    /// The public key of `user`'s device `device`, to deliver to; members
    /// of the realm's device vault only.
    DeviceKey {
        /// Whose.
        user: String,
        /// The device's id.
        device: String,
    },
    /// Keep `blob`, a recovered key sealed to `user`'s device `device`
    /// (`IPDD`), on `user`'s entry until they fetch it; members of the
    /// realm's device vault only.
    Deliver {
        /// Whose.
        user: String,
        /// The device it is sealed to.
        device: String,
        /// The delivery, base64url.
        blob: String,
    },
    /// Start a session for one of the vault's devices: re-authentication,
    /// or with `offline`, the release of the vault's session keys.
    Unlock {
        /// The vault.
        name: String,
        /// The device's id.
        device: String,
        /// An offline session (§7.6.6).
        #[serde(default)]
        offline: bool,
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
/// [`VaultOp::Unlock`] a session token and, offline, the session keys.
#[derive(Clone, Debug, Default)]
pub struct Reply {
    /// The vaults the operation concerned.
    pub descriptors: Vec<Descriptor>,
    /// A new session.
    pub session: Option<SessionToken>,
    /// The vault's session keys, released to the device.
    pub released: Option<ReleasedKeys>,
    /// Receipts for the events the operation logged (`DESIGN-tlog.md`).
    pub receipts: Vec<Receipt>,
    /// Release requests the operation made, changed or listed.
    pub requests: Vec<ReleaseRequest>,
    /// Device keys the operation escrowed or returned.
    pub escrows: Vec<DeviceEscrow>,
    /// Deposits the operation made, listed or fetched.
    pub deposits: Vec<Deposit>,
    /// Devices the operation looked up.
    pub devices: Vec<Device>,
    /// The realm's recovery settings, when asked for.
    pub recovery: Option<RecoverySettings>,
}

impl Reply {
    /// Encode: `IPVR` version 6, `n(u64) [descriptor] session released
    /// m(u8) [receipt] requests escrows deposits devices recovery`
    /// (session and released empty without one, the rest JSON).
    ///
    /// # Panics
    ///
    /// Never for fewer than 2⁶⁴ descriptors.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_version(REPLY_MAGIC, REPLY_VERSION);
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
        )
        .bytes(
            &self
                .released
                .as_ref()
                .map(ReleasedKeys::to_bytes)
                .unwrap_or_default(),
        );
        w.u8(u8::try_from(self.receipts.len()).expect("few receipts"));
        for receipt in &self.receipts {
            w.bytes(&receipt.to_bytes());
        }
        w.bytes(&serde_json::to_vec(&self.requests).unwrap_or_default());
        w.bytes(&serde_json::to_vec(&self.escrows).unwrap_or_default());
        w.bytes(&serde_json::to_vec(&self.deposits).unwrap_or_default());
        w.bytes(&serde_json::to_vec(&self.devices).unwrap_or_default());
        w.bytes(&serde_json::to_vec(&self.recovery).unwrap_or_default());
        w.finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::with_version(bytes, REPLY_MAGIC, REPLY_VERSION, "vault reply")?;
        let n = r.u64()?;
        let mut descriptors = Vec::new();
        for _ in 0..n {
            descriptors.push(Descriptor::from_bytes(r.bytes()?)?);
        }
        let session = match r.bytes()? {
            [] => None,
            b => Some(SessionToken::from_bytes(b)?),
        };
        let released = match r.bytes()? {
            [] => None,
            b => Some(ReleasedKeys::from_bytes(b)?),
        };
        let receipts = (0..r.u8()?)
            .map(|_| Receipt::from_bytes(r.bytes()?))
            .collect::<Result<_>>()?;
        let requests =
            serde_json::from_slice(r.bytes()?).map_err(|_| Error::Malformed("release requests"))?;
        let escrows =
            serde_json::from_slice(r.bytes()?).map_err(|_| Error::Malformed("device escrows"))?;
        let deposits =
            serde_json::from_slice(r.bytes()?).map_err(|_| Error::Malformed("deposits"))?;
        let devices =
            serde_json::from_slice(r.bytes()?).map_err(|_| Error::Malformed("devices"))?;
        let recovery = serde_json::from_slice(r.bytes()?)
            .map_err(|_| Error::Malformed("recovery settings"))?;
        r.finish()?;
        Ok(Self {
            descriptors,
            session,
            released,
            receipts,
            requests,
            escrows,
            deposits,
            devices,
            recovery,
        })
    }
}

/// A re-authentication session (§7.6.6): for `device` of a vault and its
/// `holder` (the owner, or the member of a shared vault who registered it),
/// until `not_after`, signed by a server under its delegation so any
/// server can check it.  It stands in for the ticket and passkey factors;
/// the answer is still encrypted to the device.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken {
    vault: VaultId,
    holder: String,
    device: Thumbprint,
    not_after: u64,
    delegation: Box<[u8]>,
    signer_key: Box<[u8]>,
    signature: Box<[u8]>,
}

/// The vault, holder and device a session must be for.
#[derive(Clone, Copy)]
pub struct SessionFor<'a> {
    /// The vault the session opens.
    pub vault: &'a VaultId,
    /// The holder whose device presents the session.
    pub holder: &'a str,
    /// That device.
    pub device: &'a Thumbprint,
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
        holder: &str,
        device: Thumbprint,
        not_after: u64,
    ) -> Result<Self> {
        let mut t = Self {
            vault,
            holder: holder.to_owned(),
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
            .str(&self.holder)
            .fixed(self.device.as_bytes())
            .u64(self.not_after)
            .bytes(&self.delegation)
            .bytes(&self.signer_key)
            .finish()
    }

    /// Check the signature and its delegation against `anchors` of
    /// `realm`, and that the session is for `expected` and lasts past `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Expired`], [`Error::Mismatch`], [`Error::UntrustedAnchor`],
    /// [`Error::WrongRealm`] or a crypto error.
    pub fn check(
        &self,
        realm: &str,
        anchors: &[Thumbprint],
        policy: &CryptoPolicy,
        expected: SessionFor<'_>,
        now: u64,
    ) -> Result<()> {
        if &self.vault != expected.vault
            || self.holder != expected.holder
            || &self.device != expected.device
        {
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
            holder: r.str()?.to_owned(),
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

fn answer_key(secret: &[u8], ct: &[u8], request: &EscrowRequest) -> Result<SecretBuf> {
    let hash = suite(ct)?;
    Ok(DOMAIN.derive_key(
        hash,
        &[secret],
        "answer",
        &[&primitives::digest(hash, &[&request.to_bytes()])?],
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
        let key = answer_key(secret.as_ref(), &ciphertext, request)?;
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
        let key = answer_key(secret.as_ref(), &self.ciphertext, request)?;
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
    let hash = suite(ct)?;
    Ok(DOMAIN.derive_key(
        hash,
        &[secret],
        "device",
        &[committed, id.as_bytes(), &primitives::digest(hash, &[ct])?],
    )?)
}

fn data_key(hash: &std::ffi::CStr, a: &[u8], b: &[u8], committed: &[u8]) -> Result<SecretBuf> {
    Ok(DOMAIN.derive_key(hash, &[a, b], "dek", &[committed])?)
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
    /// The approved release request, for a vault with approvals.
    pub release: Option<[u8; 16]>,
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
        let (devices, b) = device_slots(vault, &committed)?;
        let hash = strongest(slots.iter().map(|s| s.escrow_key.alg()));
        let dek = data_key(hash, a.as_ref(), b.as_ref(), &committed)?;
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

    /// `H(ct)` of each server slot's binding: what registered sealing
    /// registers.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn bindings(&self) -> Result<Vec<BindingHash>> {
        self.servers
            .iter()
            .map(|s| BindingHash::from_slice(&s.binding.ciphertext_hash()?))
            .collect()
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
        let b = match unlock.device {
            Some(device) => open_device_share(&self.devices, device, &committed)?,
            None if self.devices.is_empty() => SecretBuf::with_len(0),
            None => {
                return Err(Error::Missing(
                    "a device registered when the file was sealed",
                ));
            }
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
            if let Some(id) = unlock.release {
                request = request.with_release(id);
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
            let hash = strongest(self.servers.iter().map(|s| s.escrow_key.alg()));
            let dek = data_key(hash, a.as_ref(), b.as_ref(), &committed)?;
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
                if !crate::realm::is_safe_name(&server) {
                    return Err(Error::Malformed("sealed slot server"));
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn factors(device: Option<Level>, ticket: bool) -> Factors {
        Factors {
            device,
            ticket,
            passkey: false,
        }
    }

    fn policy(f: Factors) -> Policy {
        Policy {
            factors: f,
            ..Policy::default()
        }
    }

    #[test]
    fn factor_sets_are_met_by_their_supersets() {
        let any = factors(Some(Level::Any), false);
        let bound = factors(Some(Level::HardwareBound), true);
        assert!(bound.meets(&any), "a stronger device and more factors");
        assert!(!any.meets(&bound));
        assert!(!factors(None, true).meets(&any), "no device at all");
        assert!(any.meets(&Factors::default()), "nothing asked");
        assert_eq!(bound.to_string(), "device=hardware-bound,ticket");
        assert_eq!(Factors::default().to_string(), "none");
    }

    #[test]
    fn a_policy_must_meet_one_of_the_realm_factor_sets() {
        let limits = Limits {
            factors: vec![
                factors(Some(Level::Any), false),
                Factors {
                    device: None,
                    ticket: true,
                    passkey: true,
                },
            ],
            ..Limits::default()
        };
        limits
            .apply(&mut policy(factors(Some(Level::Any), true)), NOW)
            .unwrap();
        let err = limits
            .apply(&mut policy(factors(None, true)), NOW)
            .unwrap_err()
            .to_string();
        assert!(err.contains("device=any; ticket,passkey"), "{err}");
    }

    #[test]
    fn a_delivery_opens_only_with_the_device_it_was_sealed_to() {
        let old = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let new = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let other = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let blob = seal_delivery(new.public(), &old).unwrap();
        assert!(blob.starts_with(b"IPDD"));
        let back = open_delivery(&blob, &new).unwrap();
        assert_eq!(back.public().kid(), old.public().kid());
        assert!(open_delivery(&blob, &other).is_err());
        let mut cut = blob.clone();
        cut.truncate(blob.len() - 1);
        assert!(open_delivery(&cut, &new).is_err());
    }

    #[test]
    fn the_owners_group_with_the_lowest_priority_sets_the_limits() {
        let limits: Limits = serde_json::from_value(serde_json::json!({
            "max_lifetime": 86_400, "max_unlocks": 10, "max_vaults": 2,
            "max_devices": 8, "max_reauth": 3600, "without_device": true,
            "descriptor_age": 86_400,
            "groups": [
                { "group": "ops", "priority": 20, "max_vaults": 50,
                  "max_unlocks": null, "offline_sessions": true },
                { "group": "contractors", "priority": 10, "max_vaults": 1,
                  "factors": [{ "device": "hardware-bound" }] },
                { "group": "auditors", "priority": 10, "max_vaults": 3 },
            ],
        }))
        .unwrap();
        let of = |groups: &[&str]| {
            limits.for_groups(&groups.iter().map(|&g| g.to_owned()).collect::<Vec<_>>())
        };
        // No group: the realm's, and the result names no groups.
        let plain = of(&["staff"]);
        assert_eq!((plain.max_vaults, plain.max_unlocks), (2, Some(10)));
        assert!(plain.groups.is_empty());
        // One group: its fields, the realm's for the rest; null lifts a cap.
        let ops = of(&["ops"]);
        assert_eq!((ops.max_vaults, ops.max_unlocks), (50, None));
        assert!(ops.offline_sessions);
        assert_eq!(ops.max_lifetime, 86_400);
        // Several: the lowest priority wins whole, ties by name.
        let both = of(&["ops", "contractors"]);
        assert_eq!(both.max_vaults, 1);
        assert!(!both.offline_sessions, "nothing merged from ops");
        assert_eq!(both.factors, [factors(Some(Level::HardwareBound), false)]);
        assert_eq!(of(&["contractors", "auditors"]).max_vaults, 3);
        // What a realm stores reads back the same.
        let again: Limits = serde_json::from_slice(&serde_json::to_vec(&limits).unwrap()).unwrap();
        assert_eq!(again, limits);
    }
}
