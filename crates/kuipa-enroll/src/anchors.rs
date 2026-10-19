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

use agirru_crdt::{Delta, Generation, GenerationClock, Merge};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{Policy, Thumbprint, VerifyingKey, b64, primitives};

use crate::delegation::{Claim, Delegation, SignedSuccession, SignedVouch, VOUCH_VALIDITY};
use crate::error::{Error, Result};
use crate::merkle::Hash;

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
    let mut sorted = leaves.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if v.leaves() == sorted.as_slice() {
        return false;
    }
    let drops = v.leaves().iter().any(|l| sorted.binary_search(l).is_err());
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
            Self::Claim(c) => format!("c {}", b64::encode(&c.leaf()?)),
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
    slots: BTreeMap<String, Slot>,
}

impl PartialEq for AnchorState {
    fn eq(&self, other: &Self) -> bool {
        self.slots.len() == other.slots.len()
            && self
                .slots
                .iter()
                .zip(&other.slots)
                .all(|((k, a), (l, b))| k == l && a.entry == b.entry)
    }
}

const STATE_MAGIC: [u8; 4] = *b"IPAS";

impl AnchorState {
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
        self.slots.insert(
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
        self.slots.retain(|_, s| match &s.entry {
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
        self.slots.retain(|_, s| match &s.entry {
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
        self.slots.retain(|_, s| match &s.entry {
            Entry::Vouch(v) => named.contains(&v.vouch().anchor),
            _ => true,
        });
        let vouches: Vec<SignedVouch> = self.vouches().cloned().collect();
        self.slots.retain(|_, s| match &s.entry {
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
        self.slots.retain(|_, s| match &s.entry {
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
            slots: self
                .slots
                .iter()
                .filter(|(_, s)| keep(s.generation))
                .map(|(k, s)| (k.clone(), s.clone()))
                .collect(),
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
    /// claim, its own included.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn leaves(&self) -> Result<Vec<Hash>> {
        self.servers.values().map(Claim::leaf).collect()
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

const SYNC_MAGIC: [u8; 4] = *b"IPPS";
const SYNC_LABEL: &[u8] = b"ipa-ku-enroll/v1 peer";

/// A gossip request from one server to another (`POST /ipa/ku/peer/sync`):
/// the agirru envelope, the sender's own delegation, and a GSS-API token
/// from the sender's `ipa-ku/<fqdn>` key whose channel binding covers
/// everything else.
#[derive(Clone, Debug)]
pub struct PeerSync {
    /// The sending server.
    pub sender: String,
    /// The receiving server.
    pub receiver: String,
    /// The sender's own claim with its own anchor's proof.
    pub own: Delegation,
    /// The agirru envelope.
    pub envelope: Vec<u8>,
    /// The GSS-API token.
    pub token: Vec<u8>,
}

impl PeerSync {
    /// The channel binding for the token: a hash of every other field.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn channel_binding(
        sender: &str,
        receiver: &str,
        own: &Delegation,
        envelope: &[u8],
    ) -> Result<[u8; 32]> {
        let fields = Writer::new(SYNC_MAGIC)
            .str(sender)
            .str(receiver)
            .str(&own.to_json())
            .bytes(envelope)
            .finish();
        Ok(primitives::sha256(&[SYNC_LABEL, &fields])?)
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(SYNC_MAGIC)
            .u8(1)
            .str(&self.sender)
            .str(&self.receiver)
            .str(&self.own.to_json())
            .bytes(&self.envelope)
            .bytes(&self.token)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, SYNC_MAGIC, "peer sync")?;
        if r.u8()? != 1 {
            return Err(Error::Malformed("peer sync version"));
        }
        let sync = Self {
            sender: r.str()?.into(),
            receiver: r.str()?.into(),
            own: Delegation::from_json(r.str()?.as_bytes())?,
            envelope: r.bytes()?.into(),
            token: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(sync)
    }

    /// Check a sync received by `me` whose token authenticated `principal`,
    /// and return the sender's own delegation, now attested by Kerberos.
    ///
    /// # Errors
    ///
    /// [`Error::PeerSync`] for a sync for another server, a principal that
    /// is not the sender's, a sender outside `servers`, or a delegation
    /// that is not the sender's or not proven by its own anchor.
    pub fn attest(
        &self,
        principal: &str,
        me: &str,
        servers: &BTreeSet<String>,
        realm: &str,
        policy: &Policy,
        now: u64,
    ) -> Result<Delegation> {
        if self.receiver != me {
            return Err(Error::PeerSync("addressed to another server"));
        }
        if principal != peer_principal(&self.sender, realm) || !servers.contains(&self.sender) {
            return Err(Error::PeerSync(
                "the token does not authenticate the sender",
            ));
        }
        let c = self.own.claim()?;
        if c.server != self.sender
            || c.realm != realm
            || !c.valid_at(now)
            || c.anchor
                .is_some_and(|a| self.own.verify_at(&[a], policy, now).is_err())
        {
            return Err(Error::PeerSync("not the sender's own delegation"));
        }
        Ok(self.own.clone())
    }
}

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
            let leaves = t.leaves().unwrap();
            if self.anchored && needs_vouch(state.vouch(&self.thp()), &leaves, NOW, self.interval) {
                let iat = next_vouch_iat(state.vouch(&self.thp()), NOW);
                let v = SignedVouch::issue(&self.anchor, REALM, leaves, iat, iat + VOUCH_VALIDITY)
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
        let leaves = t.leaves().unwrap();
        assert!(!needs_vouch(Some(v), &leaves, NOW + 10, 3600));
        assert!(needs_vouch(Some(v), &leaves, NOW + 3600, 3600));
        // A removal (here a renewed own claim replacing the old one) does
        // not wait.
        let renewed = [a.claim(NOW + 5).leaf().unwrap()];
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
        assert!(!needs_vouch(Some(v), v.leaves(), NOW, 0));
        assert!(needs_vouch(
            Some(v),
            v.leaves(),
            v.vouch().iat + VOUCH_VALIDITY / 2,
            0
        ));
        assert!(needs_vouch(Some(v), &[[9; 32]], NOW, 0));

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
        let forged = SignedVouch::issue(&b.anchor, REALM, [[1; 32]], NOW, NOW + 100).unwrap();
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

    /// Sizes for DESIGN §4.2: `cargo test --release -p kuipa-enroll
    /// measure_exchange_sizes -- --ignored --nocapture`.
    #[test]
    #[ignore = "measurement"]
    fn measure_exchange_sizes() {
        for (n, k) in [(10, 10), (60, 60), (60, 6)] {
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

    #[test]
    fn sync_message_and_attestation() {
        let (a, b) = (Server::new("a"), Server::new("b"));
        let all = servers(&["a", "b"]);
        let clock = GenerationClock::new();
        let mut state = AnchorState::default();
        a.step(&mut state, NOW, &[], &all, &clock);
        b.step(&mut state, NOW, &[], &all, &clock);
        let own = b.own(&state, NOW);
        let cb = PeerSync::channel_binding("b", "a", &own, b"env").unwrap();
        let sync = PeerSync {
            sender: "b".into(),
            receiver: "a".into(),
            own,
            envelope: b"env".to_vec(),
            token: b"token".to_vec(),
        };
        let back = PeerSync::from_bytes(&sync.to_bytes()).unwrap();
        assert_eq!(
            PeerSync::channel_binding(&back.sender, &back.receiver, &back.own, &back.envelope)
                .unwrap(),
            cb
        );
        let policy = Policy::default();
        back.attest("ipa-ku/b@R", "a", &all, REALM, &policy, NOW)
            .unwrap();
        for (principal, me, members) in [
            ("ipa-ku/a@R", "a", &all),
            ("host/b@R", "a", &all),
            ("ipa-ku/b@R", "b", &all),
            ("ipa-ku/b@R", "a", &servers(&["a"])),
        ] {
            assert!(
                back.attest(principal, me, members, REALM, &policy, NOW)
                    .is_err()
            );
        }
        // Someone else's delegation, even if valid, is not the sender's.
        let mut forged = back.clone();
        forged.own = a.own(&state, NOW);
        assert!(
            forged
                .attest("ipa-ku/b@R", "a", &all, REALM, &policy, NOW)
                .is_err()
        );
        let mut tampered = sync.to_bytes();
        tampered[4] = 2;
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
            own: n.own(&state, NOW),
            ..back.clone()
        };
        plain
            .attest("ipa-ku/n@R", "a", &with_n, REALM, &policy, NOW)
            .unwrap();
        let claiming_b = PeerSync {
            sender: "n".into(),
            own: Delegation::new(&Claim {
                server: "b".into(),
                ..n.claim(NOW)
            }),
            ..back
        };
        assert!(
            claiming_b
                .attest("ipa-ku/n@R", "a", &with_n, REALM, &policy, NOW)
                .is_err()
        );
    }
}
