//! Anchor exchange between servers (§4.2).
//!
//! Every server has its own anchor and makes a claim for its signing key.
//! Each anchor vouches, with one signature over a Merkle tree, for its own
//! server's claim and every claim it trusts ([`crate::delegation`]).
//! Servers gossip anchor keys, claims and vouches with agirru; this module
//! holds the replicated state ([`AnchorState`]), decides which anchors a
//! server trusts ([`Trust`]), and defines the Kerberos-protected sync
//! message ([`PeerSync`]).
//!
//! Trust starts from two facts a server can check itself: its own anchor,
//! and a peer's own claim received, with its own anchor's proof, in a sync
//! request authenticated with that peer's `ipa-ku/<fqdn>` Kerberos key.  A
//! claim is then trusted when its own anchor vouches for it and so does an
//! anchor already trusted for a *different* server.  Each server vouches
//! for every claim it trusts, so trust reaches servers that never talk
//! directly.  Only servers in the membership (the IPA server list, plus
//! configured peers) are considered: removing a server from the topology
//! removes its claim from every vouch, and its anchor everywhere.
//!
//! The state grows with the number of servers, not its square: one anchor
//! key, a few small claims and one vouch (one signature and one 32-byte
//! leaf per vouched claim) per server.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, OnceLock};

use agirru_crdt::{Delta, Generation, GenerationClock, Merge};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{Policy, Thumbprint, VerifyingKey, b64, primitives};

use crate::delegation::{Claim, Delegation, SignedSuccession, SignedVouch, VOUCH_VALIDITY};
use crate::error::{Error, Result};
use crate::merkle::{Hash, TreeHash};

/// How long a claim may wait for a vouch before it is dropped (seconds).
const UNVOUCHED_GRACE: u64 = 3600;

/// The `kuipa` service principal of `server`, which authenticates its
/// syncs.
#[must_use]
pub fn peer_principal(server: &str, realm: &str) -> String {
    format!("ipa-ku/{server}@{realm}")
}

/// Whether the server's current claim `own` for its signing key `key` must
/// be reissued at `now`: missing, for another key, or past two thirds of
/// its lifetime.
#[must_use]
pub fn needs_renewal(own: Option<&Claim>, key: &Thumbprint, now: u64) -> bool {
    let Some(c) = own else {
        return true;
    };
    c.key != *key || now >= c.iat + (c.exp - c.iat) / 3 * 2
}

/// Whether the server's anchor must vouch again at `now` for `leaves`: no
/// vouch yet, past half its lifetime, a claim to drop (at once: a removed
/// server, or this server's own renewed claim), or claims to add once the
/// current vouch is `interval` seconds old, so additions are batched.
#[must_use]
pub fn needs_vouch(own: Option<&SignedVouch>, leaves: &[Hash], now: u64, interval: u64) -> bool {
    let Some(v) = own else {
        return true;
    };
    let vouch = v.vouch();
    if now >= vouch.iat + (vouch.exp - vouch.iat) / 2 {
        return true;
    }
    let mut wanted = leaves.to_vec();
    wanted.sort_unstable();
    wanted.dedup();
    let mut have = v.live().to_vec();
    have.sort_unstable();
    have.dedup();
    if have == wanted {
        return false;
    }
    let drops = have.iter().any(|l| wanted.binary_search(l).is_err());
    drops || now.saturating_sub(vouch.iat) >= interval
}

/// The `iat` for a new vouch by an anchor whose current vouch is `own`:
/// `now`, but always after the current one, so the new vouch replaces it
/// everywhere even when issued within the same second.
#[must_use]
pub fn next_vouch_iat(own: Option<&SignedVouch>, now: u64) -> u64 {
    own.map_or(now, |v| now.max(v.vouch().iat + 1))
}

/// Which delegation to advertise: `candidate` (the current claim with
/// every trusted anchor's proof), unless `current` is for the same key, has
/// proofs valid for another quarter of a vouch's lifetime, and has more of
/// them.  This keeps a renewed claim out of advertisements until the other
/// anchors vouch for it.
#[must_use]
pub fn prefer(current: Option<Delegation>, candidate: Delegation, now: u64) -> Delegation {
    let Some(current) = current else {
        return candidate;
    };
    let (Ok(cur), Ok(new)) = (current.claim(), candidate.claim()) else {
        return candidate;
    };
    if current.same_claim(&candidate)
        || cur.key != new.key
        || current.vouched_until() < now + VOUCH_VALIDITY / 4
        || candidate.proof_count() >= current.proof_count()
    {
        candidate
    } else {
        current
    }
}

/// One exchanged item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// An anchor's public key (JWK JSON), keyed by its thumbprint.
    Key(String),
    /// A claim, keyed by its leaf hash.
    Claim(Claim),
    /// An anchor's signed vouch, keyed by the anchor: the newest wins.
    Vouch(SignedVouch),
    /// A rotated anchor's succession, keyed by that (old) anchor: the
    /// newest wins.  It carries its own key.
    Succession(SignedSuccession),
}

impl Entry {
    fn id(&self) -> Result<String> {
        Ok(match self {
            Self::Key(jwk) => {
                format!(
                    "k {}",
                    VerifyingKey::from_jwk_json(jwk.as_bytes())?.thumbprint()
                )
            }
            // A local key, not a log leaf: any one hash names the claim.
            Self::Claim(c) => format!("c {}", b64::encode(&c.leaf(TreeHash::Sha384)?)),
            Self::Vouch(v) => format!("v {}", v.vouch().anchor),
            Self::Succession(s) => {
                // Also checks that it encodes, for `value`.
                s.to_bytes()?;
                format!("s {}", s.statement()?.old)
            }
        })
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Key(_) => 1,
            Self::Claim(_) => 2,
            Self::Vouch(_) => 3,
            Self::Succession(_) => 4,
        }
    }

    /// What orders replacements of one id: the signed `iat` of a vouch or
    /// succession, as [`AnchorState`]'s merge compares first; 0 for
    /// content-addressed entries.
    fn order(&self) -> u64 {
        match self {
            Self::Vouch(v) => v.vouch().iat,
            Self::Succession(s) => s.statement().map_or(0, |st| st.iat),
            Self::Key(_) | Self::Claim(_) => 0,
        }
    }

    fn value(&self) -> Vec<u8> {
        match self {
            Self::Key(jwk) => jwk.as_bytes().to_vec(),
            Self::Claim(c) => c.to_bytes(),
            Self::Vouch(v) => v.to_bytes(),
            // Only entries whose `id` succeeded are stored, and that encoded.
            Self::Succession(s) => s.to_bytes().unwrap_or_default(),
        }
    }

    fn decode(tag: u8, value: &[u8]) -> Result<Self> {
        Ok(match tag {
            1 => Self::Key(
                std::str::from_utf8(value)
                    .map_err(|_| Error::Malformed("anchor key"))?
                    .to_owned(),
            ),
            2 => Self::Claim(Claim::from_bytes(value)?),
            3 => Self::Vouch(SignedVouch::from_bytes(value)?),
            4 => Self::Succession(SignedSuccession::from_bytes(value)?),
            _ => return Err(Error::Malformed("exchange entry")),
        })
    }
}

/// A fixed-size name for an entry id in reconciliation summaries.
pub type EntryId = [u8; 16];

/// The [`EntryId`] of an entry id: a truncated domain-separated SHA-256.
///
/// # Errors
///
/// A cryptographic hash operation failed.
pub fn entry_id(id: &str) -> Result<EntryId> {
    let hash = primitives::sha256(&[b"ipa-ku/anchor-entry-id/v1\0", id.as_bytes()])?;
    let mut short = [0; 16];
    short.copy_from_slice(&hash[..16]);
    Ok(short)
}

/// One entry in a reconciliation summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryVersion {
    /// Hash of the entry's tag and encoding.
    pub hash: [u8; 32],
    /// [`Entry`]'s replacement order.
    pub order: u64,
}

impl EntryVersion {
    /// Whether this version should be sent to a holder of `other`: the
    /// holder lacks the id, or has different content that is not newer.
    /// Equal orders are sent; the receiver's merge breaks the tie.
    #[must_use]
    pub fn replaces(&self, other: Option<&Self>) -> bool {
        other.is_none_or(|o| o.hash != self.hash && o.order <= self.order)
    }
}

#[derive(Clone, Debug)]
struct Slot {
    entry: Entry,
    generation: Generation,
}

/// The replicated state: anchor keys, claims and vouches.
///
/// Keys and claims are content-addressed and never change; a vouch is
/// replaced by a newer one from the same anchor (its signed `iat` orders
/// them, ties broken by content).  Only the anchor can produce its vouch,
/// so this needs no causal tags.  Expired claims and vouches, claims no
/// vouch covers, and keys nothing refers to are dropped.
#[derive(Clone, Debug, Default)]
pub struct AnchorState {
    /// Mutate only through [`Self::slots_mut`], which detaches the digest.
    /// Shared by clones until one of them changes.
    slots: Arc<BTreeMap<String, Slot>>,
    /// The snapshot digest, shared by unmodified clones.
    digest: Arc<OnceLock<[u8; 32]>>,
    /// The reconciliation index, shared by unmodified clones.
    index: Arc<OnceLock<EntryIndex>>,
}

/// Each entry's summary version and id, by [`EntryId`].
#[derive(Debug)]
struct EntryIndex {
    summary: BTreeMap<EntryId, EntryVersion>,
    names: BTreeMap<EntryId, String>,
}

/// Most bucket bits a summary may use: 4,096 buckets.
pub const MAX_BUCKET_BITS: u32 = 12;

/// The bucket of `id` among `2^bits`: its leading bits.
#[must_use]
pub fn bucket_of(id: &EntryId, bits: u32) -> usize {
    if bits == 0 {
        0
    } else {
        usize::from(u16::from_be_bytes([id[0], id[1]]) >> (16 - bits))
    }
}

impl PartialEq for AnchorState {
    fn eq(&self, other: &Self) -> bool {
        self.slots.len() == other.slots.len()
            && self
                .slots
                .iter()
                .zip(other.slots.iter())
                .all(|((k, a), (l, b))| k == l && a.entry == b.entry)
    }
}

const STATE_MAGIC: [u8; 4] = *b"IPAS";
const STATE_DIGEST_DOMAIN: &[u8] = b"ipa-ku/anchor-state/v1\0";

/// The digest of an encoded [`AnchorState`], as [`AnchorState::digest`].
///
/// # Errors
///
/// A cryptographic hash operation failed.
pub fn state_digest(encoded: &[u8]) -> Result<[u8; 32]> {
    Ok(primitives::sha256(&[STATE_DIGEST_DOMAIN, encoded])?)
}

impl AnchorState {
    /// Mutable entries, copied if shared; detaches the cached digest and
    /// index.
    fn slots_mut(&mut self) -> &mut BTreeMap<String, Slot> {
        self.digest = Arc::default();
        self.index = Arc::default();
        Arc::make_mut(&mut self.slots)
    }

    fn index(&self) -> Result<&EntryIndex> {
        if let Some(index) = self.index.get() {
            return Ok(index);
        }
        let mut index = EntryIndex {
            summary: BTreeMap::new(),
            names: BTreeMap::new(),
        };
        for (id, slot) in self.slots.iter() {
            let hash = primitives::sha256(&[
                b"ipa-ku/anchor-entry/v1\0",
                &[slot.entry.tag()],
                &slot.entry.value(),
            ])?;
            let short = entry_id(id)?;
            index.summary.insert(
                short,
                EntryVersion {
                    hash,
                    order: slot.entry.order(),
                },
            );
            index.names.insert(short, id.clone());
        }
        Ok(self.index.get_or_init(|| index))
    }

    /// The digest of [`Self::to_bytes`], computed once per state version.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn digest(&self) -> Result<[u8; 32]> {
        if let Some(digest) = self.digest.get() {
            return Ok(*digest);
        }
        let digest = state_digest(&self.to_bytes())?;
        Ok(*self.digest.get_or_init(|| digest))
    }

    /// Hash and order each current entry, under its [`EntryId`], for
    /// bounded, snapshot-specific reconciliation; computed once per state
    /// version.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn entry_summary(&self) -> Result<&BTreeMap<EntryId, EntryVersion>> {
        Ok(&self.index()?.summary)
    }

    /// Each entry's [`EntryId`], [`EntryVersion`] and kind — its tag: keys
    /// 1, claims 2, vouches 3, successions 4, so ascending kind puts the
    /// keys others are checked against first.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn entry_versions(&self) -> Result<Vec<(EntryId, EntryVersion, u8)>> {
        let index = self.index()?;
        self.slots
            .iter()
            .map(|(name, slot)| {
                let id = entry_id(name)?;
                let version = index
                    .summary
                    .get(&id)
                    .copied()
                    .ok_or(Error::Malformed("entry index"))?;
                Ok((id, version, slot.entry.tag()))
            })
            .collect()
    }

    /// One 16-byte hash per bucket of `2^bits` (`bits` at most
    /// [`MAX_BUCKET_BITS`]) over the summary entries in it.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn bucket_hashes(&self, bits: u32) -> Result<Vec<[u8; 16]>> {
        let bits = bits.min(MAX_BUCKET_BITS);
        let mut leaves = vec![Vec::new(); 1 << bits];
        for (id, v) in self.entry_summary()? {
            let leaf = &mut leaves[bucket_of(id, bits)];
            leaf.extend_from_slice(id);
            leaf.extend_from_slice(&v.hash);
            leaf.extend_from_slice(&v.order.to_be_bytes());
        }
        leaves
            .iter()
            .map(|leaf| {
                let hash = primitives::sha256(&[b"ipa-ku/anchor-bucket/v1\0", leaf])?;
                let mut short = [0; 16];
                short.copy_from_slice(&hash[..16]);
                Ok(short)
            })
            .collect()
    }

    /// The summary entries in `buckets` of `2^bits`.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn bucket_summary(
        &self,
        bits: u32,
        buckets: &BTreeSet<usize>,
    ) -> Result<BTreeMap<EntryId, EntryVersion>> {
        Ok(self
            .entry_summary()?
            .iter()
            .filter(|(id, _)| buckets.contains(&bucket_of(id, bits)))
            .map(|(id, v)| (*id, *v))
            .collect())
    }

    /// Select entries a peer with summary `peer` lacks or would replace
    /// with them, including vouch keys.  An entry older than the peer's
    /// version of it is left out: merging it would not change the peer.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn select_entries(&self, peer: &BTreeMap<EntryId, EntryVersion>) -> Result<Self> {
        self.select_entries_where(peer, |_| true)
    }

    /// [`Self::select_entries`] among the ids `keep` accepts.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn select_entries_where(
        &self,
        peer: &BTreeMap<EntryId, EntryVersion>,
        keep: impl Fn(&EntryId) -> bool,
    ) -> Result<Self> {
        let ids = self
            .entry_summary()?
            .iter()
            .filter(|(id, own)| keep(id) && own.replaces(peer.get(*id)))
            .map(|(id, _)| *id)
            .collect();
        self.entries(&ids)
    }

    /// The ids in a peer's summary whose entries this state lacks or would
    /// replace with the peer's: what [`Self::select_entries`] would choose
    /// on the peer's side for this state.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn wanted(&self, peer: &BTreeMap<EntryId, EntryVersion>) -> Result<BTreeSet<EntryId>> {
        let own = self.entry_summary()?;
        Ok(peer
            .iter()
            .filter(|(id, p)| p.replaces(own.get(*id)))
            .map(|(id, _)| *id)
            .collect())
    }

    /// The entries with these ids, including vouch keys.
    ///
    /// # Errors
    ///
    /// A cryptographic hash operation failed.
    pub fn entries(&self, ids: &BTreeSet<EntryId>) -> Result<Self> {
        let names = &self.index()?.names;
        let mut selected = Self::default();
        for name in ids.iter().filter_map(|id| names.get(id)) {
            let Some(slot) = self.slots.get(name) else {
                continue;
            };
            selected.slots_mut().insert(name.clone(), slot.clone());
            if let Entry::Vouch(vouch) = &slot.entry {
                let key = format!("k {}", vouch.vouch().anchor);
                if let Some(slot) = self.slots.get(&key) {
                    selected.slots_mut().insert(key, slot.clone());
                }
            }
        }
        Ok(selected)
    }

    /// Encode: `IPAS ‖ 1 ‖ n(u64) ‖ n × (tag(1) ‖ value)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(STATE_MAGIC);
        w.u8(1).u64(self.slots.len() as u64);
        for s in self.slots.values() {
            w.u8(s.entry.tag()).bytes(&s.entry.value());
        }
        w.finish()
    }

    /// Decode, without checking signatures (see [`Self::admit`]).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, STATE_MAGIC, "anchor state")?;
        if r.u8()? != 1 {
            return Err(Error::Malformed("anchor state version"));
        }
        let n = r.u64()?;
        let clock = GenerationClock::new();
        let mut state = Self::default();
        for _ in 0..n {
            let tag = r.u8()?;
            state.insert(Entry::decode(tag, r.bytes()?)?, &clock)?;
        }
        r.finish()?;
        Ok(state)
    }

    /// Assign loaded entries generations from the clock used by the engine.
    ///
    /// Call before sharing the state with a newly bootstrapped gossip engine.
    pub fn rebase_generations(&mut self, clock: &GenerationClock) {
        for slot in self.slots_mut().values_mut() {
            slot.generation = clock.bump();
        }
    }

    /// Add `entry` after checking it ([`Self::check`]); returns whether the
    /// state changed.
    ///
    /// # Errors
    ///
    /// See [`Self::check`].
    pub fn put(
        &mut self,
        entry: Entry,
        realm: &str,
        policy: &Policy,
        now: u64,
        clock: &GenerationClock,
    ) -> Result<bool> {
        self.check(&entry, None, realm, policy, now)?;
        self.insert(entry, clock)
    }

    /// Check one entry: a key the policy allows; a claim or vouch for
    /// `realm` that is valid at `now`; a vouch whose anchor's key is in this
    /// state (or in `more`) and that verifies with it.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::WrongRealm`], [`Error::Expired`],
    /// [`Error::UntrustedAnchor`], or [`Error::Missing`] for a vouch whose
    /// anchor key is unknown.
    pub fn check(
        &self,
        entry: &Entry,
        more: Option<&Self>,
        realm: &str,
        policy: &Policy,
        now: u64,
    ) -> Result<()> {
        match entry {
            Entry::Key(jwk) => {
                let key = VerifyingKey::from_jwk_json(jwk.as_bytes())?;
                if !policy.allows_signature(key.alg()) {
                    return Err(Error::UntrustedAnchor);
                }
            }
            Entry::Claim(c) => {
                if c.realm != realm {
                    return Err(Error::WrongRealm);
                }
                if !c.valid_at(now) {
                    return Err(Error::Expired);
                }
            }
            Entry::Vouch(v) => {
                let vouch = v.vouch();
                if vouch.realm != realm {
                    return Err(Error::WrongRealm);
                }
                if !vouch.valid_at(now) {
                    return Err(Error::Expired);
                }
                let key = self
                    .key(&vouch.anchor)
                    .or_else(|| more.and_then(|m| m.key(&vouch.anchor)))
                    .ok_or(Error::Missing("anchor key"))?;
                v.verify(&key, policy)?;
            }
            Entry::Succession(s) => {
                s.check(realm, policy, now)?;
            }
        }
        Ok(())
    }

    fn insert(&mut self, entry: Entry, clock: &GenerationClock) -> Result<bool> {
        let id = entry.id()?;
        if let Some(slot) = self.slots.get(&id) {
            let newer = match (&entry, &slot.entry) {
                (Entry::Vouch(new), Entry::Vouch(old)) => {
                    (new.vouch().iat, new.to_bytes()) > (old.vouch().iat, old.to_bytes())
                }
                // Two successions of one anchor exist only if its key was
                // stolen after the rotation; keep one, deterministically.
                (Entry::Succession(new), Entry::Succession(old)) => {
                    let iat = |s: &SignedSuccession| s.statement().map_or(0, |st| st.iat);
                    (iat(new), new.to_bytes()?) > (iat(old), old.to_bytes()?)
                }
                _ => false,
            };
            if !newer {
                return Ok(false);
            }
        }
        self.slots_mut().insert(
            id,
            Slot {
                entry,
                generation: clock.bump(),
            },
        );
        Ok(true)
    }

    /// Keep only the inbound entries (this state) that pass
    /// [`Self::check`] against the keys here and in `local`, belong to
    /// `servers`, and are not vouches by this server's `own` anchor (if it
    /// has one): this server is the only source of those.  Applied to every
    /// inbound state before merging.
    pub fn admit(
        &mut self,
        local: &Self,
        servers: &BTreeSet<String>,
        own: Option<&Thumbprint>,
        realm: &str,
        policy: &Policy,
        now: u64,
    ) {
        let inbound = self.clone();
        self.slots_mut().retain(|_, s| match &s.entry {
            Entry::Claim(c) if !servers.contains(&c.server) => false,
            Entry::Vouch(v) if Some(&v.vouch().anchor) == own => false,
            e => inbound.check(e, Some(local), realm, policy, now).is_ok(),
        });
    }

    /// Drop what is no longer wanted at `now`: claims and vouches that no
    /// longer check, claims of servers outside `servers` or that no vouch
    /// has covered for an hour, vouches by anchors no remaining claim
    /// names, and keys nothing refers to.
    pub fn retain(&mut self, servers: &BTreeSet<String>, realm: &str, policy: &Policy, now: u64) {
        let snapshot = self.clone();
        self.slots_mut().retain(|_, s| match &s.entry {
            Entry::Claim(c) => {
                servers.contains(&c.server)
                    && snapshot.check(&s.entry, None, realm, policy, now).is_ok()
            }
            Entry::Vouch(_) | Entry::Succession(_) => {
                snapshot.check(&s.entry, None, realm, policy, now).is_ok()
            }
            Entry::Key(_) => true,
        });
        let named: BTreeSet<Thumbprint> = self.claims().filter_map(|c| c.anchor).collect();
        self.slots_mut().retain(|_, s| match &s.entry {
            Entry::Vouch(v) => named.contains(&v.vouch().anchor),
            _ => true,
        });
        let vouches: Vec<SignedVouch> = self.vouches().cloned().collect();
        self.slots_mut().retain(|_, s| match &s.entry {
            Entry::Claim(c) => {
                now < c.iat + UNVOUCHED_GRACE
                    || vouches.iter().any(|v| v.covers(c).unwrap_or(false))
            }
            _ => true,
        });
        let referenced: BTreeSet<Thumbprint> = self
            .claims()
            .filter_map(|c| c.anchor)
            .chain(self.vouches().map(|v| v.vouch().anchor))
            .collect();
        self.slots_mut().retain(|_, s| match &s.entry {
            Entry::Key(jwk) => VerifyingKey::from_jwk_json(jwk.as_bytes())
                .is_ok_and(|k| referenced.contains(k.thumbprint())),
            _ => true,
        });
    }

    /// An anchor's key.
    #[must_use]
    pub fn key(&self, anchor: &Thumbprint) -> Option<VerifyingKey> {
        match &self.slots.get(&format!("k {anchor}"))?.entry {
            Entry::Key(jwk) => VerifyingKey::from_jwk_json(jwk.as_bytes()).ok(),
            _ => None,
        }
    }

    /// An anchor's vouch.
    #[must_use]
    pub fn vouch(&self, anchor: &Thumbprint) -> Option<&SignedVouch> {
        match &self.slots.get(&format!("v {anchor}"))?.entry {
            Entry::Vouch(v) => Some(v),
            _ => None,
        }
    }

    /// The newest claim of `server` naming `anchor` (`None`: claims
    /// without an anchor).
    #[must_use]
    pub fn latest_claim(&self, server: &str, anchor: Option<&Thumbprint>) -> Option<&Claim> {
        self.claims()
            .filter(|c| c.server == server && c.anchor.as_ref() == anchor)
            .max_by_key(|c| c.iat)
    }

    /// The newest claim of `server` that its own anchor (`key`) vouches for,
    /// with that proof: what the server sends in its syncs.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn own_delegation(&self, server: &str, key: &VerifyingKey) -> Result<Option<Delegation>> {
        let Some(v) = self.vouch(key.thumbprint()) else {
            return Ok(None);
        };
        let mut claims: Vec<&Claim> = self
            .claims()
            .filter(|c| c.server == server && c.anchor.as_ref() == Some(key.thumbprint()))
            .collect();
        claims.sort_by_key(|c| std::cmp::Reverse(c.iat));
        for c in claims {
            if let Some(proof) = v.proof(c, key)? {
                let mut d = Delegation::new(c);
                d.add([proof]);
                return Ok(Some(d));
            }
        }
        Ok(None)
    }

    /// Every claim.
    pub fn claims(&self) -> impl Iterator<Item = &Claim> {
        self.slots.values().filter_map(|s| match &s.entry {
            Entry::Claim(c) => Some(c),
            _ => None,
        })
    }

    /// Every vouch.
    pub fn vouches(&self) -> impl Iterator<Item = &SignedVouch> {
        self.slots.values().filter_map(|s| match &s.entry {
            Entry::Vouch(v) => Some(v),
            _ => None,
        })
    }

    /// Every succession.
    pub fn successions(&self) -> impl Iterator<Item = &SignedSuccession> {
        self.slots.values().filter_map(|s| match &s.entry {
            Entry::Succession(v) => Some(v),
            _ => None,
        })
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    fn select(&self, keep: impl Fn(Generation) -> bool) -> Self {
        Self {
            digest: Arc::default(),
            index: Arc::default(),
            slots: Arc::new(
                self.slots
                    .iter()
                    .filter(|(_, s)| keep(s.generation))
                    .map(|(k, s)| (k.clone(), s.clone()))
                    .collect(),
            ),
        }
    }
}

impl Serialize for AnchorState {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for AnchorState {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Bytes;
        impl<'de> Visitor<'de> for Bytes {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an encoded anchor state")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> std::result::Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> std::result::Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Vec<u8>, A::Error> {
                let mut v = Vec::new();
                while let Some(b) = seq.next_element()? {
                    v.push(b);
                }
                Ok(v)
            }
        }
        // Owned: a streaming decoder (CBOR from a reader) can only lend
        // byte strings that fit its scratch buffer.
        let bytes = d.deserialize_byte_buf(Bytes)?;
        Self::from_bytes(&bytes).map_err(de::Error::custom)
    }
}

impl Merge for AnchorState {
    fn merge(&mut self, other: &Self, clock: &GenerationClock) -> bool {
        let mut changed = false;
        for s in other.slots.values() {
            changed |= self.insert(s.entry.clone(), clock).unwrap_or(false);
        }
        changed
    }
}

impl Delta for AnchorState {
    fn delta_since(&self, since: Generation) -> Self {
        self.select(|g| g > since)
    }

    fn delta_range(&self, since: Generation, until: Generation) -> Self {
        self.select(|g| g > since && g <= until)
    }
}

/// What a server trusts, computed from the state.
#[derive(Clone, Debug, Default)]
pub struct Trust {
    /// Each trusted server's current claim.
    servers: BTreeMap<String, Claim>,
    /// Trusted anchors and their servers.
    anchors: BTreeMap<Thumbprint, String>,
    me: String,
}

impl Trust {
    /// Compute trust for the server making the claim `own`, from `state`,
    /// the delegations `attested` by Kerberos-authenticated syncs, and the
    /// current membership `servers`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn compute(
        state: &AnchorState,
        own: &Claim,
        attested: &[Delegation],
        servers: &BTreeSet<String>,
        policy: &Policy,
        now: u64,
    ) -> Result<Self> {
        let realm = &own.realm;
        let mut trust = Self {
            me: own.server.clone(),
            ..Self::default()
        };
        trust.admit(own);
        // A claim its own anchor vouches for, now; a claim without an
        // anchor has nothing to vouch for it but other servers' anchors.
        let self_vouched = |c: &Claim| match &c.anchor {
            Some(a) => state
                .vouch(a)
                .is_some_and(|v| v.vouch().valid_at(now) && v.covers(c).unwrap_or(false)),
            None => true,
        };
        let mut candidates: BTreeMap<&str, Vec<&Claim>> = BTreeMap::new();
        for c in state.claims() {
            if c.server != own.server
                && servers.contains(&c.server)
                && &c.realm == realm
                && c.valid_at(now)
                && self_vouched(c)
            {
                candidates.entry(&c.server).or_default().push(c);
            }
        }
        for list in candidates.values_mut() {
            list.sort_by_key(|c| std::cmp::Reverse(c.iat));
        }
        for d in attested {
            let Ok(c) = d.claim() else { continue };
            // Attested by Kerberos: proven by its own anchor, if it has one.
            if c.server != own.server
                && servers.contains(&c.server)
                && c.valid_at(now)
                && c.anchor
                    .is_none_or(|a| d.verify_at(&[a], policy, now).is_ok())
            {
                trust.admit(&c);
            }
        }
        // Admit vouched claims until nothing changes; each pass only
        // replaces a server's claim by a newer one, so this ends.
        loop {
            let mut changed = false;
            for (server, list) in &candidates {
                for c in list {
                    if trust.servers.get(*server).is_some_and(|t| t.iat >= c.iat) {
                        break;
                    }
                    if c.anchor
                        .and_then(|a| trust.anchors.get(&a))
                        .is_some_and(|s| s != server)
                    {
                        continue;
                    }
                    let vouched = trust.anchors.iter().any(|(t, s)| {
                        s != server
                            && state.vouch(t).is_some_and(|v| {
                                v.vouch().valid_at(now) && v.covers(c).unwrap_or(false)
                            })
                    });
                    if vouched {
                        trust.admit(c);
                        changed = true;
                        break;
                    }
                }
            }
            if !changed {
                return Ok(trust);
            }
        }
    }

    fn admit(&mut self, c: &Claim) {
        if c.anchor
            .and_then(|a| self.anchors.get(&a))
            .is_some_and(|s| *s != c.server)
        {
            return;
        }
        if let Some(old) = self.servers.get(&c.server) {
            if old.iat >= c.iat {
                return;
            }
            if let Some(a) = old.anchor {
                self.anchors.remove(&a);
            }
        }
        if let Some(a) = c.anchor {
            self.anchors.insert(a, c.server.clone());
        }
        self.servers.insert(c.server.clone(), c.clone());
    }

    /// Trusted anchors, this server's own first.
    #[must_use]
    pub fn anchors(&self) -> Vec<Thumbprint> {
        let own = self.anchor_of(&self.me);
        own.into_iter()
            .chain(self.anchors.keys().copied().filter(|a| Some(*a) != own))
            .collect()
    }

    /// The trusted anchor of `server`.
    #[must_use]
    pub fn anchor_of(&self, server: &str) -> Option<Thumbprint> {
        self.servers.get(server).and_then(|c| c.anchor)
    }

    /// Trusted servers.
    pub fn servers(&self) -> impl Iterator<Item = &str> {
        self.servers.keys().map(String::as_str)
    }

    /// The leaves this server's anchor should vouch for: every trusted
    /// claim, its own included, hashed with `alg` — the anchor key's
    /// ([`TreeHash::for_signer`]).
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn leaves(&self, alg: TreeHash) -> Result<Vec<Hash>> {
        self.servers.values().map(|c| c.leaf(alg)).collect()
    }

    /// This server's delegation: its claim with a proof from every trusted
    /// anchor whose vouch in `state` covers it, and every succession in
    /// `state`, for clients that pin rotated anchors (§4.7).
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn own_delegation(&self, state: &AnchorState) -> Result<Delegation> {
        let own = self
            .servers
            .get(&self.me)
            .ok_or(Error::Missing("own claim"))?;
        let mut d = Delegation::new(own);
        for anchor in self.anchors.keys() {
            if let (Some(v), Some(key)) = (state.vouch(anchor), state.key(anchor)) {
                d.add(v.proof(own, &key)?);
            }
        }
        d.add_successions(state.successions().cloned());
        Ok(d)
    }
}

fn delegation_json_hash(json: &str) -> Result<[u8; 32]> {
    Ok(primitives::sha256(&[
        b"ipa-ku/peer-delegation/v1\0",
        json.as_bytes(),
    ])?)
}

const SYNC_MAGIC: [u8; 4] = *b"IPPS";
const SYNC_VERSION: u8 = 4;
const SYNC_LABEL: &[u8] = b"ipa-ku-enroll/v4 peer";

/// An authenticated digest-first reconciliation request.
/// The payload, the hashes of the delegation and epoch window, identities
/// and version are bound to the GSS token.  The delegation and the window
/// may be left out when the receiver already holds the content of that
/// hash from an earlier authenticated sync by the same sender.
#[derive(Clone, Debug)]
pub struct PeerSync {
    /// The sending server.
    pub sender: String,
    /// The receiving server.
    pub receiver: String,
    /// [`Self::delegation_hash`] of the sender's own delegation.
    pub own_hash: [u8; 32],
    /// The sender's own claim with its own anchor's proof, if sent.
    pub own: Option<Delegation>,
    /// The encoded reconciliation message.
    pub payload: Vec<u8>,
    /// The GSS-API token.
    pub token: Vec<u8>,
    /// [`Self::chain_hash`] of the sender's epoch window.
    pub chain_hash: [u8; 32],
    /// The sender's chain entries, oldest first, each encoded by
    /// [`crate::epoch::encode`], if sent.
    pub chain: Option<Vec<Vec<u8>>>,
}

impl PeerSync {
    /// The hash identifying a delegation in a sync.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn delegation_hash(own: &Delegation) -> Result<[u8; 32]> {
        delegation_json_hash(&own.to_json())
    }

    /// The hash identifying an epoch window in a sync.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn chain_hash(chain: &[Vec<u8>]) -> Result<[u8; 32]> {
        let mut w = Writer::new(*b"IPCW");
        w.u64(chain.len() as u64);
        for c in chain {
            w.bytes(c);
        }
        Ok(primitives::sha256(&[
            b"ipa-ku/peer-epochs/v1\0",
            &w.finish(),
        ])?)
    }

    /// The channel binding for the token: a hash of every other field,
    /// with the delegation and window represented by their hashes,
    /// SHA-384 under every policy (no single key decides it, and both
    /// servers must agree), taken to the 32 bytes every channel binding
    /// has.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn channel_binding(
        sender: &str,
        receiver: &str,
        own_hash: &[u8; 32],
        payload: &[u8],
        chain_hash: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut w = Writer::with_version(SYNC_MAGIC, SYNC_VERSION);
        w.str(sender)
            .str(receiver)
            .fixed(own_hash)
            .bytes(payload)
            .fixed(chain_hash);
        let digest = primitives::sha384(&[SYNC_LABEL, &w.finish()])?;
        Ok(crate::join::channel_binding_of(&digest))
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_version(SYNC_MAGIC, SYNC_VERSION);
        w.str(&self.sender)
            .str(&self.receiver)
            .fixed(&self.own_hash)
            .str(
                &self
                    .own
                    .as_ref()
                    .map(Delegation::to_json)
                    .unwrap_or_default(),
            )
            .bytes(&self.payload)
            .bytes(&self.token)
            .fixed(&self.chain_hash);
        match &self.chain {
            None => w.u8(0),
            Some(chain) => {
                w.u8(1).u64(chain.len() as u64);
                for c in chain {
                    w.bytes(c);
                }
                &mut w
            }
        };
        w.finish()
    }

    /// Decode, checking that sent content matches its hash.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::with_version(buf, SYNC_MAGIC, SYNC_VERSION, "peer sync")?;
        let sender = r.str()?.into();
        let receiver = r.str()?.into();
        let own_hash = r.fixed()?;
        let own = match r.str()? {
            "" => None,
            json => {
                if delegation_json_hash(json)? != own_hash {
                    return Err(Error::Malformed("peer sync context hash"));
                }
                Some(Delegation::from_json(json.as_bytes())?)
            }
        };
        let payload = r.bytes()?.into();
        let token = r.bytes()?.into();
        let chain_hash = r.fixed()?;
        let chain = match r.u8()? {
            0 => None,
            1 => {
                let n = r.u64()?;
                if n > 1024 {
                    return Err(Error::Malformed("peer sync epoch count"));
                }
                let mut chain = Vec::new();
                for _ in 0..n {
                    chain.push(r.bytes()?.into());
                }
                Some(chain)
            }
            _ => return Err(Error::Malformed("peer sync epoch window")),
        };
        r.finish()?;
        if chain
            .as_deref()
            .map(Self::chain_hash)
            .transpose()?
            .is_some_and(|h| h != chain_hash)
        {
            return Err(Error::Malformed("peer sync context hash"));
        }
        Ok(Self {
            sender,
            receiver,
            own_hash,
            own,
            payload,
            token,
            chain_hash,
            chain,
        })
    }

    /// Attest the sender's claim using the receiver's membership and policy.
    ///
    /// # Errors
    ///
    /// Returns an error if the sender or its delegation is invalid.
    pub fn attest(
        &self,
        own: &Delegation,
        principal: &str,
        context: &PeerAttestation<'_>,
    ) -> Result<Delegation> {
        let PeerAttestation {
            me,
            servers,
            realm,
            policy,
            now,
        } = *context;
        if self.receiver != me {
            return Err(Error::PeerSync("addressed to another server"));
        }
        if principal != peer_principal(&self.sender, realm) || !servers.contains(&self.sender) {
            return Err(Error::PeerSync(
                "the token does not authenticate the sender",
            ));
        }
        let c = own.claim()?;
        if c.server != self.sender
            || c.realm != realm
            || !c.valid_at(now)
            || c.anchor
                .is_some_and(|a| own.verify_at(&[a], policy, now).is_err())
        {
            return Err(Error::PeerSync("not the sender's own delegation"));
        }
        Ok(own.clone())
    }
}

/// Receiver context for authenticating a peer's delegation.
#[derive(Clone, Copy, Debug)]
pub struct PeerAttestation<'a> {
    /// This receiver's FQDN.
    pub me: &'a str,
    /// Current member FQDNs.
    pub servers: &'a BTreeSet<String>,
    /// Kerberos realm.
    pub realm: &'a str,
    /// Accepted cryptographic policy.
    pub policy: &'a Policy,
    /// Current Unix time.
    pub now: u64,
}

#[cfg(test)]
#[path = "anchor_selective_comparison.rs"]
mod selective_comparison;

#[cfg(test)]
mod tests {
    use tang_pqc::{SignatureAlg, SigningKey};

    use super::*;
    use crate::delegation::DEFAULT_VALIDITY;

    const NOW: u64 = 1_800_000_000;
    const REALM: &str = "R";

    struct Server {
        name: &'static str,
        anchor: SigningKey,
        signing: SigningKey,
        /// Whether it has the anchor role.
        anchored: bool,
        /// Seconds before additions are vouched for.
        interval: u64,
    }

    impl Server {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                anchor: SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
                signing: SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
                anchored: true,
                interval: 0,
            }
        }

        fn claim(&self, iat: u64) -> Claim {
            Claim {
                realm: REALM.into(),
                server: self.name.into(),
                anchor: self.anchored.then(|| self.thp()),
                key: *self.signing.public().thumbprint(),
                iat,
                exp: iat + DEFAULT_VALIDITY,
            }
        }

        /// The delegation sent in its syncs: its claim with its own proof.
        fn own(&self, state: &AnchorState, iat: u64) -> Delegation {
            let c = self.claim(iat);
            let mut d = Delegation::new(&c);
            if !self.anchored {
                return d;
            }
            d.add(
                state
                    .vouch(&self.thp())
                    .unwrap()
                    .proof(&c, self.anchor.public())
                    .unwrap(),
            );
            d
        }

        fn thp(&self) -> Thumbprint {
            *self.anchor.public().thumbprint()
        }

        /// What the daemon does each round: key, claim, trust, vouch.
        fn step(
            &self,
            state: &mut AnchorState,
            iat: u64,
            attested: &[Delegation],
            all: &BTreeSet<String>,
            clock: &GenerationClock,
        ) -> Trust {
            let p = Policy::default();
            if self.anchored {
                state
                    .put(
                        Entry::Key(self.anchor.public().to_jwk_json()),
                        REALM,
                        &p,
                        NOW,
                        clock,
                    )
                    .unwrap();
            }
            let own = self.claim(iat);
            state
                .put(Entry::Claim(own.clone()), REALM, &p, NOW, clock)
                .unwrap();
            let t = Trust::compute(state, &own, attested, all, &p, NOW).unwrap();
            let leaves = t.leaves(TreeHash::Sha256).unwrap();
            if self.anchored && needs_vouch(state.vouch(&self.thp()), &leaves, NOW, self.interval) {
                let iat = next_vouch_iat(state.vouch(&self.thp()), NOW);
                let previous = state.vouch(&self.thp()).cloned();
                let v = SignedVouch::issue(
                    &self.anchor,
                    REALM,
                    leaves,
                    iat,
                    iat + VOUCH_VALIDITY,
                    previous.as_ref(),
                )
                .unwrap();
                state.put(Entry::Vouch(v), REALM, &p, NOW, clock).unwrap();
            }
            t
        }
    }

    fn servers(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn trust_spreads_from_kerberos_attestation() {
        let (a, b, c) = (Server::new("a"), Server::new("b"), Server::new("c"));
        let all = servers(&["a", "b", "c"]);
        let clock = GenerationClock::new();
        let mut state = AnchorState::default();
        for s in [&a, &b, &c] {
            let t = s.step(&mut state, NOW, &[], &all, &clock);
            assert_eq!(t.anchors(), [s.thp()], "only its own anchor at first");
        }

        // a <-> b and b <-> c sync directly; a and c never do.
        let (own_a, own_b, own_c) = (a.own(&state, NOW), b.own(&state, NOW), c.own(&state, NOW));
        a.step(&mut state, NOW, std::slice::from_ref(&own_b), &all, &clock);
        let tb = b.step(&mut state, NOW, &[own_a, own_c], &all, &clock);
        assert_eq!(tb.anchors().len(), 3);

        // a now trusts c through b's vouch, and vouches for it itself.
        let ta = a.step(&mut state, NOW, std::slice::from_ref(&own_b), &all, &clock);
        assert_eq!(ta.anchor_of("c"), Some(c.thp()));
        let tc = c.step(&mut state, NOW, &[own_b], &all, &clock);
        assert_eq!(tc.anchors().len(), 3);
        assert_eq!(tc.anchors()[0], c.thp());

        // c's delegation carries all three anchors' proofs.
        let own = tc.own_delegation(&state).unwrap();
        assert_eq!(own.proof_count(), 3);
        for s in [&a, &b, &c] {
            own.verify_at(&[s.thp()], &Policy::default(), NOW).unwrap();
        }
        // One vouch per anchor, each over all three claims.
        assert_eq!(state.vouches().count(), 3);
        assert!(state.vouches().all(|v| v.leaves().len() == 3));
    }

    #[test]
    fn a_rotated_anchor_is_succeeded() {
        let (a, b) = (Server::new("a"), Server::new("b"));
        let all = servers(&["a", "b"]);
        let clock = GenerationClock::new();
        let p = Policy::default();
        let mut state = AnchorState::default();
        for s in [&a, &b] {
            s.step(&mut state, NOW, &[], &all, &clock);
        }
        let (own_a, own_b) = (a.own(&state, NOW), b.own(&state, NOW));
        a.step(&mut state, NOW, std::slice::from_ref(&own_b), &all, &clock);
        let tb = b.step(&mut state, NOW, std::slice::from_ref(&own_a), &all, &clock);
        assert_eq!(tb.anchor_of("a"), Some(a.thp()));

        // a rotates: the old anchor signs the succession and is gone; a's
        // next claim names the new one.
        let Server {
            name,
            anchor: old_anchor,
            signing,
            ..
        } = a;
        let old = *old_anchor.public().thumbprint();
        let a = Server {
            name,
            anchor: SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
            signing,
            anchored: true,
            interval: 0,
        };
        let lifetime = crate::delegation::DEFAULT_SUCCESSION_VALIDITY;
        let succession =
            SignedSuccession::issue(&old_anchor, REALM, &a.thp(), NOW, NOW + lifetime).unwrap();
        drop(old_anchor);
        let entry = Entry::Succession(succession.clone());
        assert!(
            state.put(entry.clone(), "S", &p, NOW, &clock).is_err(),
            "other realm"
        );
        assert!(state.put(entry, REALM, &p, NOW, &clock).unwrap());
        let back = AnchorState::from_bytes(&state.to_bytes()).unwrap();
        assert_eq!(back.successions().collect::<Vec<_>>(), [&succession]);

        // Kerberos attests a's new claim to b, which switches to the new
        // anchor and drops the old one.
        a.step(
            &mut state,
            NOW + 1,
            std::slice::from_ref(&own_b),
            &all,
            &clock,
        );
        let own_a = a.own(&state, NOW + 1);
        let tb = b.step(&mut state, NOW, std::slice::from_ref(&own_a), &all, &clock);
        assert_eq!(tb.anchor_of("a"), Some(a.thp()));
        assert!(!tb.anchors().contains(&old));

        // Clients that pin the old anchor verify both servers' delegations
        // through the succession they carry.
        let ta = a.step(
            &mut state,
            NOW + 1,
            std::slice::from_ref(&own_b),
            &all,
            &clock,
        );
        let tb = b.step(&mut state, NOW, std::slice::from_ref(&own_a), &all, &clock);
        for t in [&ta, &tb] {
            let v = t
                .own_delegation(&state)
                .unwrap()
                .verify_at(&[old], &p, NOW + 1)
                .unwrap();
            assert_eq!(v.succeeded, vec![(old, a.thp())]);
        }

        // The succession lives until it expires.
        state.retain(&all, REALM, &p, NOW + 2);
        assert_eq!(state.successions().count(), 1);
        state.retain(
            &all,
            REALM,
            &p,
            NOW + lifetime + crate::delegation::CLOCK_SKEW + 1,
        );
        assert_eq!(state.successions().count(), 0);
    }

    #[test]
    fn servers_without_the_anchor_role() {
        let (a, b) = (Server::new("a"), Server::new("b"));
        let n = Server {
            anchored: false,
            ..Server::new("n")
        };
        let all = servers(&["a", "b", "n"]);
        let clock = GenerationClock::new();
        let mut state = AnchorState::default();
        for s in [&a, &b, &n] {
            s.step(&mut state, NOW, &[], &all, &clock);
        }
        assert!(state.key(&n.thp()).is_none(), "no anchor key, no vouch");
        // n syncs with b only; a syncs with b.
        let (own_a, own_b, own_n) = (a.own(&state, NOW), b.own(&state, NOW), n.own(&state, NOW));
        assert_eq!(own_n.proof_count(), 0);
        b.step(&mut state, NOW, &[own_a, own_n], &all, &clock);
        let ta = a.step(&mut state, NOW, std::slice::from_ref(&own_b), &all, &clock);
        assert!(ta.servers().any(|s| s == "n"), "trusted through b's vouch");
        assert_eq!(ta.anchors().len(), 2, "n adds no anchor");

        let tn = n.step(&mut state, NOW, std::slice::from_ref(&own_b), &all, &clock);
        assert_eq!(tn.anchors(), {
            let mut v = vec![a.thp(), b.thp()];
            v.sort();
            v
        });
        let d = tn.own_delegation(&state).unwrap();
        assert_eq!(d.proof_count(), 2, "proven by both anchors");
        d.verify_at(&[a.thp()], &Policy::default(), NOW).unwrap();
        assert_eq!(state.vouches().count(), 2, "only anchors vouch");
    }

    #[test]
    fn additions_are_batched_and_removals_are_not() {
        let a = Server {
            interval: 3600,
            ..Server::new("a")
        };
        let b = Server::new("b");
        let all = servers(&["a", "b"]);
        let clock = GenerationClock::new();
        let mut state = AnchorState::default();
        a.step(&mut state, NOW, &[], &all, &clock);
        b.step(&mut state, NOW, &[], &all, &clock);
        // b is trusted, but a's fresh vouch does not grow yet.
        let own_b = b.own(&state, NOW);
        let t = a.step(&mut state, NOW, &[own_b], &all, &clock);
        assert!(t.servers().any(|s| s == "b"));
        let v = state.vouch(&a.thp()).unwrap();
        assert_eq!(v.leaves().len(), 1);
        let leaves = t.leaves(TreeHash::Sha256).unwrap();
        assert!(!needs_vouch(Some(v), &leaves, NOW + 10, 3600));
        assert!(needs_vouch(Some(v), &leaves, NOW + 3600, 3600));
        // A removal (here a renewed own claim replacing the old one) does
        // not wait.
        let renewed = [a.claim(NOW + 5).leaf(TreeHash::Sha256).unwrap()];
        assert!(needs_vouch(Some(v), &renewed, NOW + 10, 3600));
    }

    #[test]
    fn untrusted_and_removed_servers() {
        let (a, b, rogue) = (Server::new("a"), Server::new("b"), Server::new("b"));
        let all = servers(&["a", "b"]);
        let clock = GenerationClock::new();
        let mut state = AnchorState::default();
        a.step(&mut state, NOW, &[], &all, &clock);
        // A self-vouched claim for b that no trusted anchor vouches for is
        // not trusted.
        rogue.step(&mut state, NOW, &[], &all, &clock);
        let t = a.step(&mut state, NOW, &[], &all, &clock);
        assert_eq!(t.anchor_of("b"), None);

        // The Kerberos-attested b is, and the rogue's later claim for the
        // same name does not displace it without a trusted vouch.
        b.step(&mut state, NOW, &[], &all, &clock);
        let attested = b.own(&state, NOW);
        let t = a.step(&mut state, NOW, &[attested], &all, &clock);
        assert_eq!(t.anchor_of("b"), Some(b.thp()));
        rogue.step(&mut state, NOW + 10, &[], &all, &clock);
        let t = a.step(&mut state, NOW, &[], &all, &clock);
        assert_eq!(t.anchor_of("b"), Some(b.thp()));

        // b leaves the topology: its anchor is no longer trusted, and a's
        // next vouch no longer covers b's claim.
        let t = a.step(&mut state, NOW, &[], &servers(&["a"]), &clock);
        assert_eq!(t.anchors(), [a.thp()]);
        assert!(
            !state
                .vouch(&a.thp())
                .unwrap()
                .covers(&b.claim(NOW))
                .unwrap()
        );
        state.retain(&servers(&["a"]), REALM, &Policy::default(), NOW);
        assert_eq!(state.claims().count(), 1);
        assert_eq!(state.vouches().count(), 1);
    }

    #[test]
    fn renewal_replaces_claims_and_vouches() {
        let (a, b) = (Server::new("a"), Server::new("b"));
        let all = servers(&["a", "b"]);
        let clock = GenerationClock::new();
        let mut state = AnchorState::default();
        a.step(&mut state, NOW, &[], &all, &clock);
        b.step(&mut state, NOW, &[], &all, &clock);
        let attested = b.own(&state, NOW);
        a.step(&mut state, NOW, &[attested], &all, &clock);
        let attested = a.own(&state, NOW);
        b.step(&mut state, NOW, &[attested], &all, &clock);

        // b renews; a vouches for the renewed claim after the next
        // authenticated sync, replacing its vouch.
        let attested = a.own(&state, NOW);
        b.step(&mut state, NOW + 100, &[attested], &all, &clock);
        let attested = b.own(&state, NOW + 100);
        a.step(&mut state, NOW, &[attested], &all, &clock);
        let tb = Trust::compute(
            &state,
            &b.claim(NOW + 100),
            &[],
            &all,
            &Policy::default(),
            NOW,
        )
        .unwrap();
        let d = tb.own_delegation(&state).unwrap();
        assert_eq!(d.claim().unwrap(), b.claim(NOW + 100));
        assert_eq!(d.proof_count(), 2);
        // The old claim is covered by nothing and goes after the grace.
        state.retain(&all, REALM, &Policy::default(), NOW + UNVOUCHED_GRACE + 200);
        assert_eq!(state.claims().count(), 2);

        // Renewal and vouch timing.
        let renewed = b.claim(NOW + 100);
        let key = *b.signing.public().thumbprint();
        assert!(!needs_renewal(Some(&renewed), &key, NOW + 100));
        assert!(needs_renewal(
            Some(&renewed),
            a.signing.public().thumbprint(),
            NOW
        ));
        assert!(needs_renewal(
            Some(&renewed),
            &key,
            NOW + 100 + DEFAULT_VALIDITY / 3 * 2
        ));
        let v = state.vouch(&a.thp()).unwrap();
        assert!(!needs_vouch(Some(v), v.live(), NOW, 0));
        assert!(needs_vouch(
            Some(v),
            v.live(),
            v.vouch().iat + VOUCH_VALIDITY / 2,
            0
        ));
        assert!(needs_vouch(Some(v), &[crate::merkle::test_hash(9)], NOW, 0));

        // Advertising choice.
        let fresh = Delegation::new(&b.claim(NOW + 200));
        assert!(prefer(Some(d.clone()), fresh.clone(), NOW).same_claim(&d));
        assert!(prefer(Some(d), fresh.clone(), NOW + VOUCH_VALIDITY).same_claim(&fresh));
    }

    #[test]
    fn state_merges_admits_and_encodes() {
        let (a, b) = (Server::new("a"), Server::new("b"));
        let all = servers(&["a", "b"]);
        let p = Policy::default();
        let clock = GenerationClock::new();
        let mut one = AnchorState::default();
        a.step(&mut one, NOW, &[], &all, &clock);
        let mark = clock.current();
        b.step(&mut one, NOW, &[], &all, &clock);
        assert_eq!(one.delta_since(mark).len(), 3, "b's key, claim and vouch");

        let mut two = AnchorState::default();
        assert!(two.merge(&one, &clock));
        assert!(!two.merge(&one, &clock));
        assert_eq!(one, two);
        let back = AnchorState::from_bytes(&one.to_bytes()).unwrap();
        assert_eq!(back, one);
        let json = serde_json::to_vec(&one).unwrap();
        assert_eq!(serde_json::from_slice::<AnchorState>(&json).unwrap(), one);

        // Inbound: a's own vouch is dropped at a, a vouch whose key is
        // unknown is dropped, a claim of a non-member is dropped.
        let mut inbound = one.clone();
        inbound.admit(
            &AnchorState::default(),
            &all,
            Some(&a.thp()),
            REALM,
            &p,
            NOW,
        );
        assert!(inbound.vouch(&a.thp()).is_none());
        assert!(inbound.vouch(&b.thp()).is_some());
        let mut keyless = AnchorState::default();
        keyless
            .insert(Entry::Vouch(one.vouch(&b.thp()).unwrap().clone()), &clock)
            .unwrap();
        keyless.admit(
            &AnchorState::default(),
            &all,
            Some(&a.thp()),
            REALM,
            &p,
            NOW,
        );
        assert!(keyless.is_empty());
        let mut stranger = one.clone();
        stranger.admit(
            &AnchorState::default(),
            &servers(&["a"]),
            Some(&a.thp()),
            REALM,
            &p,
            NOW,
        );
        assert_eq!(stranger.claims().count(), 1);

        // Entries for another realm, expired, or with a forged signature
        // are refused.
        let mut other = a.claim(NOW);
        other.realm = "X".into();
        assert!(
            one.put(Entry::Claim(other), REALM, &p, NOW, &clock)
                .is_err()
        );
        assert!(
            one.put(
                Entry::Claim(a.claim(NOW)),
                REALM,
                &p,
                NOW + 2 * DEFAULT_VALIDITY,
                &clock
            )
            .is_err()
        );
        let forged = SignedVouch::issue(
            &b.anchor,
            REALM,
            [crate::merkle::test_hash(1)],
            NOW,
            NOW + 100,
            None,
        )
        .unwrap();
        let mut wrong_key = AnchorState::default();
        wrong_key
            .put(
                Entry::Key(a.anchor.public().to_jwk_json()),
                REALM,
                &p,
                NOW,
                &clock,
            )
            .unwrap();
        assert!(
            wrong_key
                .put(Entry::Vouch(forged), REALM, &p, NOW, &clock)
                .is_err()
        );
    }

    #[test]
    fn cached_digest_follows_every_mutation() {
        let (a, b) = (Server::new("a"), Server::new("b"));
        let all = servers(&["a", "b"]);
        let p = Policy::default();
        let clock = GenerationClock::new();
        let encoded = |s: &AnchorState| state_digest(&s.to_bytes()).unwrap();
        let mut one = AnchorState::default();
        a.step(&mut one, NOW, &[], &all, &clock);
        let base = one.digest().unwrap();
        let base_summary = one.entry_summary().unwrap().clone();
        // A decoded copy has no cache: its summary is computed afresh.
        let fresh = |s: &AnchorState| {
            AnchorState::from_bytes(&s.to_bytes())
                .unwrap()
                .entry_summary()
                .unwrap()
                .clone()
        };

        // Each mutation of a clone sharing a computed digest.
        let mut two = one.clone();
        b.step(&mut two, NOW, &[], &all, &clock);
        assert_eq!(two.digest().unwrap(), encoded(&two));
        assert_eq!(*two.entry_summary().unwrap(), fresh(&two));
        assert_eq!(
            *one.entry_summary().unwrap(),
            base_summary,
            "a mutated clone leaves the original's index"
        );
        assert_ne!(two.digest().unwrap(), base);
        assert_eq!(
            one.digest().unwrap(),
            base,
            "a mutated clone leaves the original's digest"
        );
        let mut merged = one.clone();
        assert!(merged.merge(&two, &clock));
        assert_eq!(merged.digest().unwrap(), encoded(&merged));
        assert_eq!(*merged.entry_summary().unwrap(), fresh(&merged));
        let mut admitted = two.clone();
        admitted.admit(
            &AnchorState::default(),
            &all,
            Some(&a.thp()),
            REALM,
            &p,
            NOW,
        );
        assert_ne!(admitted, two);
        assert_eq!(admitted.digest().unwrap(), encoded(&admitted));
        assert_eq!(*admitted.entry_summary().unwrap(), fresh(&admitted));
        let mut retained = two.clone();
        retained.retain(&servers(&["a"]), REALM, &p, NOW);
        assert_ne!(retained, two);
        assert_eq!(retained.digest().unwrap(), encoded(&retained));
        assert_eq!(*retained.entry_summary().unwrap(), fresh(&retained));
        let decoded = AnchorState::from_bytes(&two.to_bytes()).unwrap();
        assert_eq!(decoded.digest().unwrap(), two.digest().unwrap());
    }

    #[test]
    fn state_grows_linearly() {
        let n = 16;
        let names: Vec<&'static str> = (0..n)
            .map(|i| &*Box::leak(format!("ipa{i}.example.test").into_boxed_str()))
            .collect();
        let all = servers(&names);
        let ss: Vec<Server> = names.iter().map(|s| Server::new(s)).collect();
        let clock = GenerationClock::new();
        let mut state = AnchorState::default();
        for s in &ss {
            s.step(&mut state, NOW, &[], &all, &clock);
        }
        // Everybody attested by everybody: the full mesh.
        let owns: Vec<_> = ss.iter().map(|s| s.own(&state, NOW)).collect();
        for s in &ss {
            s.step(&mut state, NOW, &owns, &all, &clock);
        }
        assert!(state.vouches().all(|v| v.leaves().len() == n));
        let size = state.to_bytes().len();
        // Per server: a 1952-byte key as JWK (~2.7 KB), a ~100-byte claim,
        // and a vouch with a 3309-byte signature and n 32-byte leaves.
        let bound = n * (2800 + 150 + 3500 + 32 * n);
        assert!(size < bound, "{size} bytes for {n} servers (bound {bound})");
        // An advertised proof stays small: one signature, log2(n) hashes.
        let t = Trust::compute(
            &state,
            &ss[0].claim(NOW),
            &owns,
            &all,
            &Policy::default(),
            NOW,
        )
        .unwrap();
        let one = t
            .own_delegation(&state)
            .unwrap()
            .select(&[])
            .to_json()
            .len();
        assert!(one < 8500, "{one} bytes");
    }

    #[test]
    fn loaded_state_uses_engine_generation_clock() {
        let server = Server::new("a");
        let clock = GenerationClock::new();
        let mut original = AnchorState::default();
        server.step(&mut original, NOW, &[], &servers(&["a"]), &clock);
        let mut loaded = AnchorState::from_bytes(&original.to_bytes()).unwrap();
        let engine_clock = GenerationClock::new();
        loaded.rebase_generations(&engine_clock);
        assert_eq!(
            loaded.delta_range(Generation::from_u64(0), engine_clock.current()),
            original,
            "a bounded response must include loaded entries"
        );
        let mark = engine_clock.current();
        server.step(&mut loaded, NOW + 1, &[], &servers(&["a"]), &engine_clock);
        assert!(
            !loaded.delta_since(mark).is_empty(),
            "writes after loading must be newer than the loaded state"
        );
    }

    /// Sizes for DESIGN §4.2: `cargo test --release -p kuipa-enroll
    /// measure_exchange_sizes -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement"]
    fn measure_exchange_sizes() {
        for (n, k) in [
            (10, 10),
            (60, 60),
            (60, 6),
            (100, 6),
            (100, 100),
            (200, 6),
            (200, 200),
            (300, 6),
            (300, 300),
        ] {
            let names: Vec<&'static str> = (0..n)
                .map(|i| &*Box::leak(format!("ipa{i}.example.test").into_boxed_str()))
                .collect();
            let all = servers(&names);
            let ss: Vec<Server> = names
                .iter()
                .enumerate()
                .map(|(i, s)| Server {
                    anchored: i < k,
                    ..Server::new(s)
                })
                .collect();
            let clock = GenerationClock::new();
            let mut state = AnchorState::default();
            for s in &ss {
                s.step(&mut state, NOW, &[], &all, &clock);
            }
            let owns: Vec<_> = ss.iter().map(|s| s.own(&state, NOW)).collect();
            for s in &ss {
                s.step(&mut state, NOW, &owns, &all, &clock);
            }
            let full = state.to_bytes().len();
            // One server renews its claim; every anchor vouches again.
            let mark = clock.current();
            ss[0].step(&mut state, NOW + 1, &owns, &all, &clock);
            let renewed = ss[0].own(&state, NOW + 1);
            for s in &ss[1..] {
                s.step(
                    &mut state,
                    NOW,
                    std::slice::from_ref(&renewed),
                    &all,
                    &clock,
                );
            }
            let delta = state.delta_since(mark).to_bytes().len();
            let t = Trust::compute(
                &state,
                &ss[1].claim(NOW),
                &owns,
                &all,
                &Policy::default(),
                NOW,
            )
            .unwrap();
            let d = t.own_delegation(&state).unwrap();
            println!(
                "{n} servers, {k} anchors: state {full} bytes, delta after one renewal {delta} bytes, \
                 advertised delegation {} bytes, all {} proofs {} bytes",
                d.select(&[]).to_json().len(),
                d.proof_count(),
                d.to_json().len()
            );
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "wire and attestation checks share one constructed exchange"
    )]
    #[test]
    fn sync_message_and_attestation() {
        let (a, b) = (Server::new("a"), Server::new("b"));
        let all = servers(&["a", "b"]);
        let clock = GenerationClock::new();
        let mut state = AnchorState::default();
        a.step(&mut state, NOW, &[], &all, &clock);
        b.step(&mut state, NOW, &[], &all, &clock);
        let own = b.own(&state, NOW);
        let own_hash = PeerSync::delegation_hash(&own).unwrap();
        let chain = vec![b"entry".to_vec()];
        let chain_hash = PeerSync::chain_hash(&chain).unwrap();
        let cb = PeerSync::channel_binding("b", "a", &own_hash, b"env", &chain_hash).unwrap();
        let sync = PeerSync {
            sender: "b".into(),
            receiver: "a".into(),
            own_hash,
            own: Some(own.clone()),
            payload: b"env".to_vec(),
            token: b"token".to_vec(),
            chain_hash,
            chain: Some(chain),
        };
        let back = PeerSync::from_bytes(&sync.to_bytes()).unwrap();
        let bind = |s: &PeerSync| {
            PeerSync::channel_binding(
                &s.sender,
                &s.receiver,
                &s.own_hash,
                &s.payload,
                &s.chain_hash,
            )
            .unwrap()
        };
        assert_eq!(bind(&back), cb);
        // Left-out context keeps the same binding and decodes.
        let elided = PeerSync {
            own: None,
            chain: None,
            ..back.clone()
        };
        let elided = PeerSync::from_bytes(&elided.to_bytes()).unwrap();
        assert!(elided.own.is_none() && elided.chain.is_none());
        assert_eq!(bind(&elided), cb);
        let mut moved = back.clone();
        moved.chain_hash[0] ^= 1;
        assert_ne!(
            bind(&moved),
            cb,
            "the chain is covered by the channel binding"
        );
        let mut moved = back.clone();
        moved.own_hash[0] ^= 1;
        assert_ne!(
            bind(&moved),
            cb,
            "the delegation is covered by the channel binding"
        );
        // Sent content must match the bound hash.
        let mut swapped = back.clone();
        swapped.chain = Some(vec![b"other".to_vec()]);
        assert!(PeerSync::from_bytes(&swapped.to_bytes()).is_err());
        let mut swapped = back.clone();
        swapped.own = Some(a.own(&state, NOW));
        assert!(PeerSync::from_bytes(&swapped.to_bytes()).is_err());
        let mut moved = back.clone();
        moved.payload[0] ^= 1;
        assert_ne!(
            bind(&moved),
            cb,
            "the repair nonce, digest and snapshot are bound through the payload"
        );
        let policy = Policy::default();
        let context = PeerAttestation {
            me: "a",
            servers: &all,
            realm: REALM,
            policy: &policy,
            now: NOW,
        };
        back.attest(&own, "ipa-ku/b@R", &context).unwrap();
        for (principal, me, members) in [
            ("ipa-ku/a@R", "a", &all),
            ("host/b@R", "a", &all),
            ("ipa-ku/b@R", "b", &all),
            ("ipa-ku/b@R", "a", &servers(&["a"])),
        ] {
            assert!(
                back.attest(
                    &own,
                    principal,
                    &PeerAttestation {
                        me,
                        servers: members,
                        ..context
                    }
                )
                .is_err()
            );
        }
        // Someone else's delegation, even if valid, is not the sender's.
        assert!(
            back.attest(&a.own(&state, NOW), "ipa-ku/b@R", &context)
                .is_err()
        );
        // Only version 4 parses.
        let mut tampered = sync.to_bytes();
        tampered[4] = 1;
        assert!(PeerSync::from_bytes(&tampered).is_err());

        // A server without an anchor sends its claim without a proof;
        // Kerberos alone attests it, and only for the sender's own name.
        let n = Server {
            anchored: false,
            ..Server::new("n")
        };
        let with_n = servers(&["a", "b", "n"]);
        let plain = PeerSync {
            sender: "n".into(),
            ..back.clone()
        };
        let context_n = PeerAttestation {
            servers: &with_n,
            ..context
        };
        plain
            .attest(&n.own(&state, NOW), "ipa-ku/n@R", &context_n)
            .unwrap();
        let claiming_b = Delegation::new(&Claim {
            server: "b".into(),
            ..n.claim(NOW)
        });
        assert!(plain.attest(&claiming_b, "ipa-ku/n@R", &context_n).is_err());
    }
}
