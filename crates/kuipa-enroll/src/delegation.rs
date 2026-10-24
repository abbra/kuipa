//! Server delegations (§4.2): realm anchors vouch for one server's ML-DSA
//! signing key for a limited time.
//!
//! * A **claim** states, for one server, its realm, its own anchor and the
//!   thumbprint of its signing key, with a validity period.  It is small
//!   and unsigned.
//! * A **vouch** is one anchor's signature over two Merkle trees (RFC 9162
//!   hashing, as in Merkle Tree Certificates): its append-only **claim
//!   log**, whose dropped claims are retired by tombstones rather than
//!   removed (`DESIGN-tlog.md` §8), and the **live tree** of the claims it
//!   vouches for now.  One ML-DSA signature per anchor, however many
//!   servers it covers.  Every server's anchor vouches for its own claim
//!   and for every claim it trusts ([`crate::anchors`]).  Signature proofs
//!   are inclusion in the live tree, so a dropped claim stops proving at
//!   once; head proofs are inclusion in a pinned log head, checked with
//!   the retired claims the host learned (§4.9).
//! * A **proof** shows that one anchor vouched for a claim: the anchor's
//!   public key, the signed vouch and the claim's inclusion path.
//!
//! A [`Delegation`] is a claim with proofs; advertisements carry one proof,
//! chosen from the anchors the client pins.  Vouch signatures use the
//! ML-DSA context `ipa-ku-enroll/v1 vouch`, so they never verify as a JWS
//! or bundle signature by the same key.
//!
//! * A **succession** is an anchor's signed statement that another anchor
//!   replaces it (§4.7), made once when a server rotates its anchor, after
//!   which the old private key is deleted.  A delegation may carry the
//!   successions that lead from an anchor the client pins to the anchor of
//!   its proof; [`Delegation::verify_at`] follows at most
//!   [`MAX_SUCCESSION_HOPS`] of them.  They use the context
//!   `ipa-ku-enroll/v1 succession`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{Policy, SigningKey, Thumbprint, VerifyingKey, b64};

use crate::error::{Error, Result};
use crate::merkle::{self, Hash, TreeHash};

/// Accepted clock skew, in seconds.
pub const CLOCK_SKEW: u64 = 300;

/// Longest claim validity a verifier accepts, in seconds (400 days).
pub const MAX_VALIDITY: u64 = 400 * 24 * 3600;

/// Default validity of a new claim, in seconds (90 days).
pub const DEFAULT_VALIDITY: u64 = 90 * 24 * 3600;

/// Validity of a new vouch, in seconds (7 days); servers re-vouch at half
/// life and whenever the set of claims they vouch for changes.
pub const VOUCH_VALIDITY: u64 = 7 * 24 * 3600;

/// Longest vouch validity a verifier accepts, in seconds (31 days).
pub const MAX_VOUCH_VALIDITY: u64 = 31 * 24 * 3600;

const CLAIM_MAGIC: [u8; 4] = *b"IPDC";
const VOUCH_MAGIC: [u8; 4] = *b"IPVH";
const SIGNED_VOUCH_MAGIC: [u8; 4] = *b"IPSV";
const VOUCH_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 vouch";
const SUCCESSION_MAGIC: [u8; 4] = *b"IPAR";
const SIGNED_SUCCESSION_MAGIC: [u8; 4] = *b"IPSR";
const SUCCESSION_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 succession";

/// Most successions a verifier follows from a pinned anchor.
pub const MAX_SUCCESSION_HOPS: usize = 4;

/// Default validity of a succession, in seconds (400 days): it must
/// outlive the enrollment strings and images that pin the old anchor.
pub const DEFAULT_SUCCESSION_VALIDITY: u64 = MAX_VALIDITY;

fn check_period(iat: u64, exp: u64, max: u64, what: &'static str) -> Result<()> {
    if exp <= iat || exp - iat > max {
        return Err(Error::Malformed(what));
    }
    Ok(())
}

pub(crate) fn valid_at(iat: u64, exp: u64, at: u64) -> bool {
    at <= exp.saturating_add(CLOCK_SKEW) && iat <= at.saturating_add(CLOCK_SKEW)
}

/// One server's claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    /// Kerberos realm.
    pub realm: String,
    /// The server's FQDN.
    pub server: String,
    /// The server's own anchor; `None` for a server without the anchor
    /// role, which other servers' anchors vouch for.
    pub anchor: Option<Thumbprint>,
    /// The thumbprint of the server's signing key.
    pub key: Thumbprint,
    /// Issued at (Unix seconds).
    pub iat: u64,
    /// Expires at (Unix seconds).
    pub exp: u64,
}

impl Claim {
    /// Encode: `IPDC ‖ 1 ‖ realm ‖ server ‖ anchor(32) ‖ key(32) ‖ iat ‖ exp`,
    /// with an all-zero anchor for none.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(CLAIM_MAGIC)
            .u8(1)
            .str(&self.realm)
            .str(&self.server)
            .fixed(self.anchor.as_ref().map_or(&[0; 32], |a| a.as_bytes()))
            .fixed(self.key.as_bytes())
            .u64(self.iat)
            .u64(self.exp)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for an empty or too long validity period.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, CLAIM_MAGIC, "claim")?;
        if r.u8()? != 1 {
            return Err(Error::Malformed("claim version"));
        }
        let claim = Self {
            realm: r.str()?.into(),
            server: r.str()?.into(),
            anchor: Some(r.fixed::<32>()?)
                .filter(|a| a != &[0; 32])
                .map(Thumbprint::from_bytes),
            key: Thumbprint::from_bytes(r.fixed()?),
            iat: r.u64()?,
            exp: r.u64()?,
        };
        r.finish()?;
        check_period(claim.iat, claim.exp, MAX_VALIDITY, "claim validity")?;
        Ok(claim)
    }

    /// Its leaf hash in a claim log of `alg` — the vouching anchor's
    /// ([`TreeHash::for_signer`]): a typed log leaf of kind
    /// [`Kind::CLAIM`](crate::tlog::Kind::CLAIM), stamped with its `iat`,
    /// so a claim can never be read as another kind of leaf.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn leaf(&self, alg: TreeHash) -> Result<Hash> {
        crate::tlog::Leaf {
            kind: crate::tlog::Kind::CLAIM,
            time: self.iat,
            index: Hash::zero(alg),
            body: self.to_bytes(),
        }
        .hash()
    }

    /// Whether it is valid at `at`, with clock skew.
    #[must_use]
    pub fn valid_at(&self, at: u64) -> bool {
        valid_at(self.iat, self.exp, at)
    }
}

/// What an anchor signs: the tree over the claims it vouches for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vouch {
    /// Kerberos realm.
    pub realm: String,
    /// The vouching anchor.
    pub anchor: Thumbprint,
    /// Issued at (Unix seconds).
    pub iat: u64,
    /// Expires at (Unix seconds).
    pub exp: u64,
    /// Number of leaves in the claim log.
    pub size: u64,
    /// The claim log's tree hash.
    pub root: Hash,
    /// Number of claims vouched for now.
    pub live_size: u64,
    /// The live tree's hash.
    pub live_root: Hash,
}

impl Vouch {
    /// Encode: `IPVH ‖ 2 ‖ realm ‖ anchor(32) ‖ iat ‖ exp ‖ size ‖
    /// root ‖ live_size ‖ live_root`, the roots length prefixed (32 bytes
    /// for SHA-256, 48 for SHA-384, as the anchor's key decides); these
    /// are the signed bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::with_version(VOUCH_MAGIC, 2)
            .str(&self.realm)
            .fixed(self.anchor.as_bytes())
            .u64(self.iat)
            .u64(self.exp)
            .u64(self.size)
            .bytes(&self.root)
            .u64(self.live_size)
            .bytes(&self.live_root)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for an empty or too long validity period.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::with_version(buf, VOUCH_MAGIC, 2, "vouch")?;
        let vouch = Self {
            realm: r.str()?.into(),
            anchor: Thumbprint::from_bytes(r.fixed()?),
            iat: r.u64()?,
            exp: r.u64()?,
            size: r.u64()?,
            root: Hash::from_slice(r.bytes()?)?,
            live_size: r.u64()?,
            live_root: Hash::from_slice(r.bytes()?)?,
        };
        if vouch.root.alg() != vouch.live_root.alg() {
            return Err(Error::Malformed("vouch roots of two hashes"));
        }
        r.finish()?;
        check_period(vouch.iat, vouch.exp, MAX_VOUCH_VALIDITY, "vouch validity")?;
        Ok(vouch)
    }

    /// Whether it is valid at `at`, with clock skew.
    #[must_use]
    pub fn valid_at(&self, at: u64) -> bool {
        valid_at(self.iat, self.exp, at)
    }
}

/// One entry of an anchor's claim log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogEntry {
    /// A claim, by its leaf hash ([`Claim::leaf`]).
    Claim(Hash),
    /// The claim at `target` is no longer vouched for, from `time`.
    Tombstone {
        /// The retired claim's index in the log.
        target: u64,
        /// When (the `iat` of the vouch that dropped it).
        time: u64,
    },
}

/// The reason every claim-log tombstone carries.
const CLAIM_DROPPED: &str = "claim dropped";

impl LogEntry {
    /// Its leaf hash: a claim's own, or a typed tombstone leaf's.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn hash(&self, alg: TreeHash) -> Result<Hash> {
        match self {
            Self::Claim(h) if h.alg() == alg => Ok(*h),
            Self::Claim(_) => Err(Error::Malformed("vouch: a claim of another hash")),
            Self::Tombstone { target, time } => {
                crate::tlog::Leaf::tombstone(alg, *time, *target, CLAIM_DROPPED).hash()
            }
        }
    }
}

/// A claim log's leaf hashes, its live claims in log order, and the
/// claims it retired; checked: a claim is appended only while not live,
/// and a tombstone retires an earlier live claim.
struct Replayed {
    leaves: Vec<Hash>,
    live: Vec<Hash>,
    retired: Vec<Hash>,
}

fn replay(entries: &[LogEntry], alg: TreeHash) -> Result<Replayed> {
    let mut leaves = Vec::with_capacity(entries.len());
    let mut live: Vec<(u64, Hash)> = Vec::new();
    let mut retired = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        match e {
            LogEntry::Claim(h) => {
                if live.iter().any(|(_, l)| l == h) {
                    return Err(Error::Malformed("vouch: a claim already live"));
                }
                live.push((i as u64, *h));
            }
            LogEntry::Tombstone { target, .. } => {
                let Some(at) = live.iter().position(|(t, _)| t == target) else {
                    return Err(Error::Malformed("vouch: a tombstone for no live claim"));
                };
                let (_, h) = live.remove(at);
                if !retired.contains(&h) {
                    retired.push(h);
                }
            }
        }
        leaves.push(e.hash(alg)?);
    }
    let live: Vec<Hash> = live.into_iter().map(|(_, h)| h).collect();
    retired.retain(|h| !live.contains(h));
    Ok(Replayed {
        leaves,
        live,
        retired,
    })
}

/// A signed vouch with its claim log, as servers exchange it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedVouch {
    vouch: Vouch,
    signature: Vec<u8>,
    entries: Vec<LogEntry>,
    /// Derived from `entries`.
    leaves: Vec<Hash>,
    live: Vec<Hash>,
    retired: Vec<Hash>,
}

impl SignedVouch {
    /// Vouch, as `anchor`, for the claims with these `leaves` in `realm`,
    /// valid from `iat` to `exp`.  The **claim log** (§4.9,
    /// `DESIGN-tlog.md` §8) is the previous vouch's, extended: a claim no
    /// longer vouched for is retired by an appended tombstone stamped
    /// `iat`, and a new claim is appended.  Nothing is ever removed, so
    /// every earlier head is a prefix of this one.  The live tree is over
    /// the claims vouched for now, in log order.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for no leaves or a bad period, or a signing
    /// error.
    pub fn issue(
        anchor: &SigningKey,
        realm: &str,
        leaves: impl IntoIterator<Item = Hash>,
        iat: u64,
        exp: u64,
        previous: Option<&SignedVouch>,
    ) -> Result<Self> {
        check_period(iat, exp, MAX_VOUCH_VALIDITY, "vouch validity")?;
        let alg = TreeHash::for_signer(anchor.public().alg());
        let entries = continue_log(leaves, previous, iat);
        let replayed = replay(&entries, alg)?;
        let vouch = Vouch {
            realm: realm.into(),
            anchor: *anchor.public().thumbprint(),
            iat,
            exp,
            size: replayed.leaves.len() as u64,
            root: merkle::root(&replayed.leaves)?,
            live_size: replayed.live.len() as u64,
            live_root: merkle::root(&replayed.live)?,
        };
        let signature = anchor.sign_with_context(&vouch.to_bytes(), VOUCH_CONTEXT)?;
        Ok(Self {
            vouch,
            signature,
            entries,
            leaves: replayed.leaves,
            live: replayed.live,
            retired: replayed.retired,
        })
    }

    /// The vouch.
    #[must_use]
    pub fn vouch(&self) -> &Vouch {
        &self.vouch
    }

    /// The claim log's hash: the anchor key's ([`TreeHash::for_signer`]).
    #[must_use]
    pub fn alg(&self) -> TreeHash {
        self.vouch.root.alg()
    }

    /// The claim log's leaf hashes, in log order.
    #[must_use]
    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }

    /// The claim log's entries, in log order.
    #[must_use]
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// The claims vouched for now, in log order: the live tree's leaves.
    #[must_use]
    pub fn live(&self) -> &[Hash] {
        &self.live
    }

    /// The claims the log retired and has not vouched for again.
    #[must_use]
    pub fn retired(&self) -> &[Hash] {
        &self.retired
    }

    /// The claims retired within the log's first `size` entries, when
    /// those make `root`: what a host pinning the head `(size, root)`
    /// learns from this vouch's entries.  The entries are believed for
    /// making the pinned root, not for the vouch's signature, so a host
    /// learns from any page that carries them.  `None` for a head this
    /// log does not extend.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn retired_at(&self, size: u64, root: &Hash) -> Result<Option<Vec<Hash>>> {
        let Some(n) = usize::try_from(size)
            .ok()
            .filter(|n| *n > 0 && *n <= self.leaves.len())
        else {
            return Ok(None);
        };
        if merkle::root(&self.leaves[..n])? != *root {
            return Ok(None);
        }
        Ok(Some(replay(&self.entries[..n], self.alg())?.retired))
    }

    /// Check it against the anchor's `key`: the key's thumbprint, the
    /// policy, the signature, and that the entries follow the log's rules
    /// and make both signed trees.
    ///
    /// # Errors
    ///
    /// [`Error::UntrustedAnchor`] for another anchor's key or a bad
    /// signature, [`Error::Malformed`] for entries that do not make the
    /// trees.
    pub fn verify(&self, key: &VerifyingKey, policy: &Policy) -> Result<()> {
        if key.thumbprint() != &self.vouch.anchor || !policy.allows_signature(key.alg()) {
            return Err(Error::UntrustedAnchor);
        }
        key.verify_with_context(&self.vouch.to_bytes(), VOUCH_CONTEXT, &self.signature)
            .map_err(|_| Error::UntrustedAnchor)?;
        let replayed = replay(&self.entries, self.alg())?;
        if replayed.leaves.len() as u64 != self.vouch.size
            || replayed.live.len() as u64 != self.vouch.live_size
            || merkle::root(&replayed.leaves)? != self.vouch.root
            || merkle::root(&replayed.live)? != self.vouch.live_root
        {
            return Err(Error::Malformed("vouch leaves"));
        }
        Ok(())
    }

    /// Whether it covers `claim`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn covers(&self, claim: &Claim) -> Result<bool> {
        Ok(self.live.contains(&claim.leaf(self.alg())?))
    }

    /// The proof that it covers `claim`, by the anchor with `key`; `None`
    /// if it does not cover it.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn proof(&self, claim: &Claim, key: &VerifyingKey) -> Result<Option<Proof>> {
        let leaf = claim.leaf(self.alg())?;
        let Some(index) = self.live.iter().position(|l| *l == leaf) else {
            return Ok(None);
        };
        Ok(Some(Proof {
            anchor: to_value(&key.to_jwk_json()),
            vouch: b64::encode(&self.vouch.to_bytes()),
            signature: b64::encode(&self.signature),
            index: index as u64,
            path: merkle::path(&self.live, index)?
                .iter()
                .map(|h| b64::encode(h))
                .collect(),
        }))
    }

    /// The head of this vouch's claim log: the `(size, root)` a client
    /// can pin, so an inclusion proof at that prefix verifies with no
    /// signature (§4.9).
    #[must_use]
    pub fn head(&self) -> (u64, Hash) {
        (self.vouch.size, self.vouch.root)
    }

    /// The prefix head proof for `claim` against the pinned `head`: the
    /// claim's position in the log and its inclusion path within the
    /// first `head.0` leaves.  `None` if the claim is not in that
    /// prefix, or the prefix does not make the pinned root (a stale
    /// head, or another anchor's log).
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn head_proof(
        &self,
        claim: &Claim,
        anchor: &Thumbprint,
        head: (u64, Hash),
    ) -> Result<Option<HeadProof>> {
        let prefix = usize::try_from(head.0)
            .ok()
            .filter(|n| *n > 0 && *n <= self.leaves.len());
        if anchor != &self.vouch.anchor
            || prefix.is_none()
            || merkle::root(&self.leaves[..prefix.unwrap_or(0)])? != head.1
        {
            return Ok(None);
        }
        let leaf = claim.leaf(self.alg())?;
        let n = prefix.unwrap_or(0);
        // Live within the prefix: its last appearance there, and no
        // tombstone for it inside the prefix.
        let Some(index) = self.leaves[..n].iter().rposition(|l| *l == leaf) else {
            return Ok(None);
        };
        if self.entries[..n]
            .iter()
            .any(|e| matches!(e, LogEntry::Tombstone { target, .. } if *target == index as u64))
        {
            return Ok(None);
        }
        let prefix = &self.leaves[..n];
        Ok(Some(HeadProof::new(
            *anchor,
            index as u64,
            head.0,
            merkle::path(prefix, index)?
                .iter()
                .map(|h| b64::encode(h))
                .collect(),
        )))
    }

    /// Encode: `IPSV ‖ 2 ‖ vouch ‖ signature ‖ n(u64) ‖ [entry]`, an
    /// entry `1 ‖ leaf(32)` for a claim or `2 ‖ target(u64) ‖ time(u64)`
    /// for a tombstone.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_version(SIGNED_VOUCH_MAGIC, 2);
        w.bytes(&self.vouch.to_bytes())
            .bytes(&self.signature)
            .u64(self.entries.len() as u64);
        for e in &self.entries {
            match e {
                LogEntry::Claim(h) => w.u8(1).bytes(h),
                LogEntry::Tombstone { target, time } => w.u8(2).u64(*target).u64(*time),
            };
        }
        w.finish()
    }

    /// Decode (not verified).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::with_version(buf, SIGNED_VOUCH_MAGIC, 2, "signed vouch")?;
        let vouch = Vouch::from_bytes(r.bytes()?)?;
        let signature = r.bytes()?.to_vec();
        let n = r.u64()?;
        if n != vouch.size || n > 1 << 20 {
            return Err(Error::Malformed("vouch leaves"));
        }
        let mut entries = Vec::new();
        for _ in 0..n {
            entries.push(match r.u8()? {
                1 => LogEntry::Claim(Hash::from_slice(r.bytes()?)?),
                2 => LogEntry::Tombstone {
                    target: r.u64()?,
                    time: r.u64()?,
                },
                _ => return Err(Error::Malformed("vouch entry")),
            });
        }
        r.finish()?;
        let replayed = replay(&entries, vouch.root.alg())?;
        Ok(Self {
            vouch,
            signature,
            entries,
            leaves: replayed.leaves,
            live: replayed.live,
            retired: replayed.retired,
        })
    }
}

/// The next claim log for an anchor that vouches for `leaves`, given its
/// `previous` vouch: the previous log kept whole, a tombstone stamped
/// `time` for each live claim no longer wanted, then each wanted claim
/// not live yet, in the caller's order.  Without a previous log, the
/// wanted claims, deduplicated.
fn continue_log(
    leaves: impl IntoIterator<Item = Hash>,
    previous: Option<&SignedVouch>,
    time: u64,
) -> Vec<LogEntry> {
    let mut wanted: Vec<Hash> = Vec::new();
    for l in leaves {
        if !wanted.contains(&l) {
            wanted.push(l);
        }
    }
    let Some(previous) = previous else {
        return wanted.into_iter().map(LogEntry::Claim).collect();
    };
    let mut log = previous.entries.clone();
    // Live claims with their index: the last appearance of each, untombstoned.
    let mut live: Vec<(u64, Hash)> = Vec::new();
    for (i, e) in previous.entries.iter().enumerate() {
        match e {
            LogEntry::Claim(h) => live.push((i as u64, *h)),
            LogEntry::Tombstone { target, .. } => live.retain(|(t, _)| t != target),
        }
    }
    for (target, h) in &live {
        if !wanted.contains(h) {
            log.push(LogEntry::Tombstone {
                target: *target,
                time,
            });
        }
    }
    for w in wanted {
        if !live.iter().any(|(_, h)| *h == w) {
            log.push(LogEntry::Claim(w));
        }
    }
    log
}

/// What an anchor signs when another anchor replaces it (§4.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Succession {
    /// Kerberos realm.
    pub realm: String,
    /// The replaced anchor, which signs.
    pub old: Thumbprint,
    /// Its successor.
    pub new: Thumbprint,
    /// Issued at (Unix seconds).
    pub iat: u64,
    /// Expires at (Unix seconds).
    pub exp: u64,
}

impl Succession {
    /// Encode: `IPAR ‖ 1 ‖ realm ‖ old(32) ‖ new(32) ‖ iat ‖ exp`; these
    /// are the signed bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(SUCCESSION_MAGIC)
            .u8(1)
            .str(&self.realm)
            .fixed(self.old.as_bytes())
            .fixed(self.new.as_bytes())
            .u64(self.iat)
            .u64(self.exp)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for an empty or too long validity period
    /// or an anchor succeeding itself.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, SUCCESSION_MAGIC, "succession")?;
        if r.u8()? != 1 {
            return Err(Error::Malformed("succession version"));
        }
        let succession = Self {
            realm: r.str()?.into(),
            old: Thumbprint::from_bytes(r.fixed()?),
            new: Thumbprint::from_bytes(r.fixed()?),
            iat: r.u64()?,
            exp: r.u64()?,
        };
        r.finish()?;
        check_period(
            succession.iat,
            succession.exp,
            MAX_VALIDITY,
            "succession validity",
        )?;
        if succession.old == succession.new {
            return Err(Error::Malformed("succession to itself"));
        }
        Ok(succession)
    }

    /// Whether it is valid at `at`, with clock skew.
    #[must_use]
    pub fn valid_at(&self, at: u64) -> bool {
        valid_at(self.iat, self.exp, at)
    }
}

/// A succession signed by the old anchor, with that anchor's public key:
/// it verifies on its own, with nothing but the old thumbprint pinned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSuccession {
    /// The old anchor's public key (JWK).
    from: Value,
    /// The succession (base64url).
    statement: String,
    /// The old anchor's signature (base64url).
    signature: String,
}

impl SignedSuccession {
    /// Hand `old`'s role in `realm` over to the anchor `new`, valid from
    /// `iat` to `exp`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a bad period or `new` being `old`, or a
    /// signing error.
    pub fn issue(
        old: &SigningKey,
        realm: &str,
        new: &Thumbprint,
        iat: u64,
        exp: u64,
    ) -> Result<Self> {
        check_period(iat, exp, MAX_VALIDITY, "succession validity")?;
        let succession = Succession {
            realm: realm.into(),
            old: *old.public().thumbprint(),
            new: *new,
            iat,
            exp,
        };
        if succession.old == succession.new {
            return Err(Error::Malformed("succession to itself"));
        }
        let statement = succession.to_bytes();
        let signature = old.sign_with_context(&statement, SUCCESSION_CONTEXT)?;
        Ok(Self {
            from: to_value(&old.public().to_jwk_json()),
            statement: b64::encode(&statement),
            signature: b64::encode(&signature),
        })
    }

    /// The statement, **unverified**.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn statement(&self) -> Result<Succession> {
        Succession::from_bytes(&b64::decode(&self.statement)?)
    }

    /// The base64 statement: the ordering key for canonical succession
    /// lists (the anchor epoch, §4.8).
    #[must_use]
    pub fn order_key(&self) -> &str {
        &self.statement
    }

    /// Check it: the embedded key is the old anchor's, its algorithm is
    /// allowed, the signature verifies, and it is for `realm` and valid at
    /// `at`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::WrongRealm`], [`Error::Expired`], or
    /// [`Error::UntrustedAnchor`] for another key or a bad signature.
    pub fn check(&self, realm: &str, policy: &Policy, at: u64) -> Result<Succession> {
        let succession = self.check_signature(realm, policy)?;
        if !succession.valid_at(at) {
            return Err(Error::Expired);
        }
        Ok(succession)
    }

    /// [`check`](Self::check) without the validity period: a record of a
    /// rotation outlives the succession itself (the anchor epoch, §4.8).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::WrongRealm`], or
    /// [`Error::UntrustedAnchor`] for another key or a bad signature.
    pub fn check_signature(&self, realm: &str, policy: &Policy) -> Result<Succession> {
        let statement = b64::decode(&self.statement)?;
        let succession = Succession::from_bytes(&statement)?;
        let key = VerifyingKey::from_jwk_json(self.from.to_string().as_bytes())?;
        if key.thumbprint() != &succession.old || !policy.allows_signature(key.alg()) {
            return Err(Error::UntrustedAnchor);
        }
        key.verify_with_context(
            &statement,
            SUCCESSION_CONTEXT,
            &b64::decode(&self.signature)?,
        )
        .map_err(|_| Error::UntrustedAnchor)?;
        if succession.realm != realm {
            return Err(Error::WrongRealm);
        }
        Ok(succession)
    }

    /// Encode for the anchor exchange: `IPSR ‖ 1 ‖ key(JWK) ‖ statement ‖
    /// signature`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if a field is not valid base64url.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(Writer::new(SIGNED_SUCCESSION_MAGIC)
            .u8(1)
            .str(&self.from.to_string())
            .bytes(&b64::decode(&self.statement)?)
            .bytes(&b64::decode(&self.signature)?)
            .finish())
    }

    /// Decode (not verified).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, SIGNED_SUCCESSION_MAGIC, "signed succession")?;
        if r.u8()? != 1 {
            return Err(Error::Malformed("signed succession version"));
        }
        let from =
            serde_json::from_str(r.str()?).map_err(|_| Error::Malformed("succession key"))?;
        let statement = r.bytes()?;
        Succession::from_bytes(statement)?;
        let signed = Self {
            from,
            statement: b64::encode(statement),
            signature: b64::encode(r.bytes()?),
        };
        r.finish()?;
        Ok(signed)
    }
}

/// One anchor's proof for a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// The anchor's public key (JWK).
    anchor: Value,
    /// The vouch (base64url).
    vouch: String,
    /// The anchor's signature (base64url).
    signature: String,
    /// The claim's leaf index.
    index: u64,
    /// The inclusion path (base64url hashes), leaf level first.
    path: Vec<String>,
}

impl Proof {
    fn anchor_key(&self) -> Option<VerifyingKey> {
        VerifyingKey::from_jwk_json(self.anchor.to_string().as_bytes()).ok()
    }

    /// The anchor's thumbprint, unverified.
    fn signer(&self) -> Option<Thumbprint> {
        self.anchor_key().map(|k| *k.thumbprint())
    }

    /// The anchor's vouch statement, **verified**: its embedded key is
    /// allowed, the statement names that key's anchor, the proof's
    /// signature is the key's over the statement (`(size, root)` and the
    /// period included), and it is valid at `at`.
    fn verified_vouch(&self, policy: &Policy, at: u64) -> Option<Vouch> {
        let key = self.anchor_key()?;
        if !policy.allows_signature(key.alg()) {
            return None;
        }
        let bytes = b64::decode(&self.vouch).ok()?;
        let vouch = Vouch::from_bytes(&bytes).ok()?;
        if &vouch.anchor != key.thumbprint() {
            return None;
        }
        let signature = b64::decode(&self.signature).ok()?;
        if key
            .verify_with_context(&bytes, VOUCH_CONTEXT, &signature)
            .is_err()
            || !valid_at(vouch.iat, vouch.exp, at)
        {
            return None;
        }
        Some(vouch)
    }

    /// Check it for `claim` (only from `anchors`, when given) and return
    /// the anchor and the vouch.
    fn check(
        &self,
        claim: &Claim,
        anchors: Option<&[Thumbprint]>,
        policy: &Policy,
    ) -> Option<(Thumbprint, Vouch)> {
        let key = self.anchor_key()?;
        if !policy.allows_signature(key.alg())
            || anchors.is_some_and(|a| !a.contains(key.thumbprint()))
        {
            return None;
        }
        let vouch_bytes = b64::decode(&self.vouch).ok()?;
        let vouch = Vouch::from_bytes(&vouch_bytes).ok()?;
        if &vouch.anchor != key.thumbprint() || vouch.realm != claim.realm {
            return None;
        }
        let signature = b64::decode(&self.signature).ok()?;
        key.verify_with_context(&vouch_bytes, VOUCH_CONTEXT, &signature)
            .ok()?;
        let path: Vec<Hash> = self
            .path
            .iter()
            .map(|h| Hash::from_slice(&b64::decode(h).ok()?).ok())
            .collect::<Option<_>>()?;
        // Signature proofs are inclusion in the live tree: a claim the
        // anchor dropped stops proving with the next vouch.  The tree's
        // hash is the anchor key's.
        if vouch.live_root.alg() != TreeHash::for_signer(key.alg()) {
            return None;
        }
        merkle::verify(
            &claim.leaf(vouch.live_root.alg()).ok()?,
            self.index,
            vouch.live_size,
            &path,
            &vouch.live_root,
        )
        .ok()?
        .then_some((*key.thumbprint(), vouch))
    }
}

/// A pinned vouch head (§4.9): the anchor it names and the `(size,
/// root)` of its claim log when the pin was written.  Nothing in it is
/// secret, and nothing in it is trusted until the whole pin is: it comes
/// from the same out-of-band channel as the thumbprint it extends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadPin {
    /// The anchor whose claim log this head names.
    pub anchor: Thumbprint,
    /// The number of leaves in the log at the pinned head.
    pub size: u64,
    /// The tree hash over those leaves.
    pub root: Hash,
}

impl HeadPin {
    /// The JSON form, as thumbprints are on the wire: `{"anchor": …,
    /// "size": …, "root": …}` with base64url strings.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "anchor": self.anchor.to_string(),
            "size": self.size,
            "root": b64::encode(&self.root),
        })
    }

    /// Parse the JSON form.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for anything else.
    pub fn from_json(value: &Value) -> Result<Self> {
        let malformed = || Error::Malformed("head pin");
        let anchor = value
            .get("anchor")
            .and_then(Value::as_str)
            .and_then(|a| a.parse().ok())
            .ok_or_else(malformed)?;
        let size = value
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(malformed)?;
        let root = value
            .get("root")
            .and_then(Value::as_str)
            .and_then(|r| b64::decode(r).ok())
            .and_then(|r| Hash::from_slice(&r).ok())
            .ok_or_else(malformed)?;
        Ok(Self { anchor, size, root })
    }

    /// Check `proof` for `claim` against this head: the proof must be by
    /// this anchor, and its inclusion path must lead from the claim's
    /// leaf to the pinned root within `size` leaves.  There is no
    /// signature: the pin is the whole authority (§4.9.4).
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn check(&self, claim: &Claim, proof: &HeadProof) -> Result<bool> {
        Ok(proof.anchor() == &self.anchor
            && proof.size == self.size
            && merkle::verify(
                &claim.leaf(self.root.alg())?,
                proof.index,
                self.size,
                &proof.decode_path()?,
                &self.root,
            )?)
    }
}

/// One anchor's head proof for a claim (§4.9): the anchor, the claim's
/// position in the claim log, the size of the prefix the pinned head
/// names, and the inclusion path within that prefix.  No key, no
/// signature — it verifies only against a pinned [`HeadPin`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadProof {
    /// The anchor's thumbprint.
    anchor: String,
    /// The claim's leaf index in the claim log.
    index: u64,
    /// The size of the prefix the pinned head names.
    size: u64,
    /// The inclusion path (base64url hashes), leaf level first.
    path: Vec<String>,
    /// The parsed `anchor`, private.
    parsed_anchor: Thumbprint,
}

impl HeadProof {
    /// The anchor's thumbprint, unverified.
    #[must_use]
    pub fn anchor(&self) -> &Thumbprint {
        &self.parsed_anchor
    }

    /// Parse `anchor` once, on construction.
    fn new(anchor: Thumbprint, index: u64, size: u64, path: Vec<String>) -> Self {
        Self {
            anchor: anchor.to_string(),
            index,
            size,
            path,
            parsed_anchor: anchor,
        }
    }

    /// The JSON form, as it appears in a delegation: the anchor, the
    /// index, the prefix size and the path.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "anchor": self.anchor,
            "index": self.index,
            "size": self.size,
            "path": self.path,
        })
    }

    /// Parse the JSON form.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for anything else.
    pub fn from_json(value: &Value) -> Result<Self> {
        let malformed = || Error::Malformed("head proof");
        let anchor = value
            .get("anchor")
            .and_then(Value::as_str)
            .and_then(|a| a.parse().ok())
            .ok_or_else(malformed)?;
        let index = value
            .get("index")
            .and_then(Value::as_u64)
            .ok_or_else(malformed)?;
        let size = value
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(malformed)?;
        let path = value
            .get("path")
            .and_then(Value::as_array)
            .map(|p| {
                p.iter()
                    .filter_map(|h| h.as_str().map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .ok_or_else(malformed)?;
        Ok(Self::new(anchor, index, size, path))
    }

    fn decode_path(&self) -> Result<Vec<Hash>> {
        self.path
            .iter()
            .map(|h| b64::decode(h).ok().and_then(|b| Hash::from_slice(&b).ok()))
            .collect::<Option<_>>()
            .ok_or(Error::Malformed("head proof path"))
    }

    /// Check it for `claim` against the pinned `heads`, returning the
    /// anchor whose head proved it.  Only the anchor's pin is consulted:
    /// there is no signature to verify.  A claim among `retired` — the
    /// claims the host learned the pinned logs retired — proves nothing:
    /// it is still in every later tree, but no longer vouched for.
    fn check(&self, claim: &Claim, heads: &[HeadPin], retired: &[Hash]) -> Option<Thumbprint> {
        heads.iter().find_map(|h| {
            // The claim's leaf in this head's log, of the head's hash.
            let retired_here = claim
                .leaf(h.root.alg())
                .map_or(true, |l| retired.contains(&l));
            (!retired_here && h.check(claim, self).ok()?).then_some(h.anchor)
        })
    }
}

fn to_value(json: &str) -> Value {
    serde_json::from_str(json).expect("JWK serialisation is valid JSON")
}

/// A claim with proofs, as published in advertisements and bundles, and
/// the successions that lead from rotated anchors to those of the proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// The claim (base64url).
    claim: String,
    proofs: Vec<Proof>,
    /// Head proofs (§4.9), for clients that pin a vouch head: at most
    /// one per anchor, and none in a delegation that also carries that
    /// anchor's signature proof (a head proof subsumes it, for a client
    /// that can check it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    head_proofs: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    successions: Vec<SignedSuccession>,
}

/// The content of a delegation that verified against a pinned anchor.
#[derive(Clone, Debug)]
pub struct VerifiedDelegation {
    /// Kerberos realm.
    pub realm: String,
    /// The delegated server's FQDN.
    pub server: String,
    /// The thumbprint of the delegated server's signing key.
    pub key: Thumbprint,
    /// The claim was issued at (Unix seconds).
    pub iat: u64,
    /// The claim expires at (Unix seconds).
    pub exp: u64,
    /// The pinned anchor whose proof was accepted.
    pub anchor: Thumbprint,
    /// The pinned anchor whose **head** proved the claim, if one did
    /// (§4.9): a different fact from `anchor`, which names the signature
    /// proof's signer (an anchor whose head proved it when no signature
    /// was needed).
    pub head_anchor: Option<Thumbprint>,
    /// When that anchor's vouch expires (Unix seconds).
    /// `u64::MAX` when the claim was proven by a **head** (§4.9): a
    /// head proof carries no lifetime — the pinned head is a landmark,
    /// and a head-proven reader's trust does not ride on a vouch's
    /// expiry — so nothing expires for it.
    pub vouched_until: u64,
    /// The successions followed from a pinned anchor to `anchor`, as
    /// `(old, new)` from the pinned one; empty if `anchor` is pinned.
    pub succeeded: Vec<(Thumbprint, Thumbprint)>,
}

impl Delegation {
    /// `claim` without proofs.
    #[must_use]
    pub fn new(claim: &Claim) -> Self {
        Self {
            claim: b64::encode(&claim.to_bytes()),
            proofs: Vec::new(),
            head_proofs: Vec::new(),
            successions: Vec::new(),
        }
    }

    /// A claim of `server` for its signing `key`, valid from `iat` to `exp`,
    /// with a proof by the server's own `anchor`, which vouches for this
    /// claim alone (a server that has not exchanged anchors yet, tests).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a bad period, or a signing error.
    pub fn issue(
        anchor: &SigningKey,
        realm: &str,
        server: &str,
        key: &VerifyingKey,
        iat: u64,
        exp: u64,
    ) -> Result<Self> {
        check_period(iat, exp, MAX_VALIDITY, "claim validity")?;
        let claim = Claim {
            realm: realm.into(),
            server: server.into(),
            anchor: Some(*anchor.public().thumbprint()),
            key: *key.thumbprint(),
            iat,
            exp,
        };
        let vouch = SignedVouch::issue(
            anchor,
            realm,
            [claim.leaf(TreeHash::for_signer(anchor.public().alg()))?],
            iat,
            (iat + VOUCH_VALIDITY).min(exp),
            None,
        )?;
        let mut d = Self::new(&claim);
        d.add(vouch.proof(&claim, anchor.public())?);
        Ok(d)
    }

    /// Add `proof`s (for this claim), at most one per anchor.
    pub fn add(&mut self, proofs: impl IntoIterator<Item = Proof>) {
        for p in proofs {
            let signer = p.signer();
            if signer.is_some() && !self.proofs.iter().any(|q| q.signer() == signer) {
                self.proofs.push(p);
            }
        }
    }

    /// Add `proof`s (for this claim), at most one per anchor; the head
    /// proofs replace a signature proof by the same anchor, which they
    /// subsume for a client that can check them (§4.9).
    pub fn add_head_proofs(&mut self, proofs: impl IntoIterator<Item = HeadProof>) {
        for p in proofs {
            if self
                .head_proofs
                .iter()
                .any(|q| HeadProof::from_json(q).is_ok_and(|q| *q.anchor() == *p.anchor()))
            {
                continue;
            }
            self.head_proofs.push(p.to_json());
        }
    }

    /// The anchors whose head proofs it carries, **unverified**.
    #[must_use]
    pub fn head_proofs(&self) -> Vec<HeadProof> {
        self.head_proofs
            .iter()
            .filter_map(|v| HeadProof::from_json(v).ok())
            .collect()
    }

    /// The vouch heads this delegation proves **by signature**: for each
    /// signature proof, the `(size, root)` of the vouch its embedded
    /// anchor key signed, valid at `at`.  This is what a head pin must be
    /// taken **from**: an advertised head that does not appear here is
    /// the advertising server's assertion, not the anchor's (§4.9.6,
    /// DESIGN-claim-logs.md §4).
    #[must_use]
    pub fn verified_heads(&self, policy: &Policy, at: u64) -> Vec<HeadPin> {
        self.proofs
            .iter()
            .filter_map(|p| {
                let v = p.verified_vouch(policy, at)?;
                Some(HeadPin {
                    anchor: v.anchor,
                    size: v.size,
                    root: v.root,
                })
            })
            .collect()
    }

    /// The vouch head (§4.9) of the proof by `anchor`, if it carries one:
    /// the `(size, root)` its vouch signed, **unverified**.
    #[must_use]
    pub fn vouch_head(&self, anchor: &Thumbprint) -> Option<(u64, Hash)> {
        let bytes = b64::decode(
            &self
                .proofs
                .iter()
                .find(|p| p.signer() == Some(*anchor))?
                .vouch,
        )
        .ok()?;
        let vouch = Vouch::from_bytes(&bytes).ok()?;
        Some((vouch.size, vouch.root))
    }

    /// Add `successions`, each once.
    pub fn add_successions(&mut self, successions: impl IntoIterator<Item = SignedSuccession>) {
        for s in successions {
            if !self.successions.contains(&s) {
                self.successions.push(s);
            }
        }
    }

    /// The successions it carries, **unverified**.
    #[must_use]
    pub fn successions(&self) -> &[SignedSuccession] {
        &self.successions
    }

    /// The claim, **unverified**.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn claim(&self) -> Result<Claim> {
        Claim::from_bytes(&b64::decode(&self.claim)?)
    }

    /// The anchors whose proofs verify (at any time, trusted or not), in
    /// order.
    #[must_use]
    pub fn signers(&self, policy: &Policy) -> Vec<Thumbprint> {
        let Ok(claim) = self.claim() else {
            return Vec::new();
        };
        self.proofs
            .iter()
            .filter_map(|p| p.check(&claim, None, policy).map(|(a, _)| a))
            .collect()
    }

    /// The number of proofs, verified or not.
    #[must_use]
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    /// When the last of its proofs' vouches expires, **unverified**.
    #[must_use]
    pub fn vouched_until(&self) -> u64 {
        self.proofs
            .iter()
            .filter_map(|p| Vouch::from_bytes(&b64::decode(&p.vouch).ok()?).ok())
            .map(|v| v.exp)
            .max()
            .unwrap_or(0)
    }

    /// Whether `other` has the same claim.
    #[must_use]
    pub fn same_claim(&self, other: &Self) -> bool {
        self.claim == other.claim
    }

    /// The same claim with one proof: by the first anchor in `wanted` that
    /// has one, else by the server's own anchor, else the first.
    ///
    /// Advertisements carry one proof, chosen from the anchors the client
    /// pins, instead of every anchor's (§4.3).
    ///
    /// If no wanted anchor has a proof, the proof is the one reached by the
    /// shortest chain of successions from the first wanted anchor that has
    /// one, and the delegation keeps that chain.  With nothing wanted (a
    /// bundle, whose reader is unknown) it keeps every succession.
    ///
    /// With `wanted_heads` (§4.9), a head proof for the first pinned head
    /// wins over everything: no signature is needed, and none is served.
    /// A client that pins a head for an anchor that also has a signature
    /// proof served gets the head proof only.
    #[must_use]
    pub fn select(&self, wanted: &[Thumbprint]) -> Self {
        self.select_with_heads(wanted, &[])
    }

    /// [`select`](Self::select) with the client's pinned vouch heads.
    #[must_use]
    pub fn select_with_heads(&self, wanted: &[Thumbprint], heads: &[HeadPin]) -> Self {
        let own = self.claim().ok().and_then(|c| c.anchor);
        let by = |a: &Thumbprint| self.proofs.iter().find(|p| p.signer() == Some(*a));
        let proofs = self.head_proofs();
        let matching: Vec<Value> = proofs
            .iter()
            .filter(|p| {
                heads
                    .iter()
                    .any(|h| h.anchor == *p.anchor() && h.size == p.size)
            })
            .map(HeadProof::to_json)
            .collect();
        if !matching.is_empty() {
            // The head wins over everything (§4.9): no signature, and
            // **every** matching head — a frozen host's §2 gate demands
            // a proof per frozen anchor, not the first one.
            return Self {
                claim: self.claim.clone(),
                proofs: Vec::new(),
                head_proofs: matching,
                successions: Vec::new(),
            };
        }
        let direct = wanted.iter().find_map(by);
        let chained = if direct.is_some() {
            None
        } else {
            wanted.iter().find_map(|w| {
                let chain = self.chain_from(w, |a| by(a).is_some())?;
                let last = chain.last().map(|(_, s)| s.new)?;
                Some((by(&last)?, chain))
            })
        };
        let (chosen, successions) = match (direct, chained) {
            (Some(p), _) => (Some(p), Vec::new()),
            (None, Some((p, chain))) => (Some(p), chain.into_iter().map(|(s, _)| s).collect()),
            (None, None) => (
                self.proofs
                    .iter()
                    .find(|p| p.signer() == own)
                    .or_else(|| self.proofs.first()),
                if wanted.is_empty() {
                    self.successions.clone()
                } else {
                    Vec::new()
                },
            ),
        };
        Self {
            claim: self.claim.clone(),
            proofs: chosen.cloned().into_iter().collect(),
            head_proofs: Vec::new(),
            successions,
        }
    }

    /// The shortest chain of carried successions (unverified, at most
    /// [`MAX_SUCCESSION_HOPS`]) from `start` to an anchor for which `done`
    /// holds, in order.
    fn chain_from(
        &self,
        start: &Thumbprint,
        done: impl Fn(&Thumbprint) -> bool,
    ) -> Option<Vec<(SignedSuccession, Succession)>> {
        let statements: Vec<(SignedSuccession, Succession)> = self
            .successions
            .iter()
            .filter_map(|s| Some((s.clone(), s.statement().ok()?)))
            .collect();
        let mut paths = vec![(*start, Vec::new())];
        let mut seen = vec![*start];
        for _ in 0..MAX_SUCCESSION_HOPS {
            let mut next = Vec::new();
            for (at, path) in &paths {
                for (signed, s) in statements.iter().filter(|(_, s)| &s.old == at) {
                    if seen.contains(&s.new) {
                        continue;
                    }
                    seen.push(s.new);
                    let mut longer: Vec<(SignedSuccession, Succession)> = path.clone();
                    longer.push((signed.clone(), s.clone()));
                    if done(&s.new) {
                        return Some(longer);
                    }
                    next.push((s.new, longer));
                }
            }
            paths = next;
        }
        None
    }

    /// Verify against the pinned `anchors`, as of `at` (Unix seconds).
    ///
    /// Offline bundles pass their own `iat` here, online clients the current
    /// time (§8.4).
    ///
    /// # Errors
    ///
    /// - [`Error::UntrustedAnchor`] if no proof by a pinned anchor whose
    ///   algorithm `policy` allows verifies with a vouch valid at `at`;
    /// - [`Error::Expired`] if the claim is not valid at `at`;
    /// - [`Error::Malformed`] if it cannot be parsed.
    pub fn verify_at(
        &self,
        anchors: &[Thumbprint],
        policy: &Policy,
        at: u64,
    ) -> Result<VerifiedDelegation> {
        self.verify_at_with_heads(anchors, &[], &[], policy, at)
    }

    /// [`verify_at`](Self::verify_at) with the client's pinned vouch
    /// heads (§4.9) and the claims it learned their logs retired: a head
    /// proof that checks against one of them, for a claim not retired, is
    /// accepted with no signature, and wins over a signature proof.  The
    /// claim's validity is still checked, and the successions still lead
    /// to signature proofs — a head proof needs none.
    ///
    /// # Errors
    ///
    /// As [`verify_at`](Self::verify_at).
    pub fn verify_at_with_heads(
        &self,
        anchors: &[Thumbprint],
        heads: &[HeadPin],
        retired: &[Hash],
        policy: &Policy,
        at: u64,
    ) -> Result<VerifiedDelegation> {
        let claim = self.claim()?;
        let head_proofs = self.head_proofs();
        if let Some(anchor) = head_proofs
            .iter()
            .find_map(|p| p.check(&claim, heads, retired))
        {
            if !claim.valid_at(at) {
                return Err(Error::Expired);
            }
            return Ok(VerifiedDelegation {
                realm: claim.realm,
                server: claim.server,
                key: claim.key,
                iat: claim.iat,
                exp: claim.exp,
                anchor,
                head_anchor: Some(anchor),
                // No vouch lifetime: the pinned head is the proof.
                vouched_until: u64::MAX,
                succeeded: Vec::new(),
            });
        }
        let proven = |pinned: &[Thumbprint]| {
            self.proofs
                .iter()
                .filter_map(|p| p.check(&claim, Some(pinned), policy))
                .find(|(_, v)| v.valid_at(at))
        };
        let (anchor, vouch, succeeded) = if let Some((a, v)) = proven(anchors) {
            (a, v, Vec::new())
        } else {
            let parents = self.successors(anchors, &claim.realm, policy, at);
            let reached: Vec<Thumbprint> = parents.keys().copied().collect();
            let (a, v) = proven(&reached).ok_or(Error::UntrustedAnchor)?;
            let mut chain = Vec::new();
            let mut at_anchor = a;
            while let Some(old) = parents.get(&at_anchor) {
                chain.push((*old, at_anchor));
                at_anchor = *old;
            }
            chain.reverse();
            (a, v, chain)
        };
        if !claim.valid_at(at) {
            return Err(Error::Expired);
        }
        Ok(VerifiedDelegation {
            realm: claim.realm,
            server: claim.server,
            key: claim.key,
            iat: claim.iat,
            exp: claim.exp,
            anchor,
            head_anchor: None,
            vouched_until: vouch.exp,
            succeeded,
        })
    }

    /// The anchors reachable from `pinned` through carried successions that
    /// check for `realm` at `at`, within [`MAX_SUCCESSION_HOPS`], each
    /// mapped to the anchor it succeeds (pinned anchors are not keys).
    fn successors(
        &self,
        pinned: &[Thumbprint],
        realm: &str,
        policy: &Policy,
        at: u64,
    ) -> std::collections::BTreeMap<Thumbprint, Thumbprint> {
        let valid: Vec<Succession> = self
            .successions
            .iter()
            .filter_map(|s| s.check(realm, policy, at).ok())
            .collect();
        let mut parents = std::collections::BTreeMap::new();
        let mut frontier: Vec<Thumbprint> = pinned.to_vec();
        for _ in 0..MAX_SUCCESSION_HOPS {
            let mut next = Vec::new();
            for s in valid.iter().filter(|s| frontier.contains(&s.old)) {
                if pinned.contains(&s.new) || parents.contains_key(&s.new) {
                    continue;
                }
                parents.insert(s.new, s.old);
                next.push(s.new);
            }
            frontier = next;
        }
        parents
    }

    /// The claim's expiry, **unverified**: for the issuing side, which must
    /// not stage bundles that outlive its claim.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn expires_unverified(&self) -> Result<u64> {
        Ok(self.claim()?.exp)
    }

    /// The JSON value embedded in advertisements and bundles.
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // serialising plain strings cannot fail
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("serialisable")
    }

    /// Parse the embedded JSON value.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_value(value: Value) -> Result<Self> {
        serde_json::from_value(value).map_err(|_| Error::Malformed("delegation"))
    }

    /// Serialise as JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        self.to_value().to_string()
    }

    /// Parse JSON.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_json(json: &[u8]) -> Result<Self> {
        serde_json::from_slice(json).map_err(|_| Error::Malformed("delegation"))
    }
}

#[cfg(test)]
mod tests {
    use tang_pqc::SignatureAlg;

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn key() -> SigningKey {
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap()
    }

    fn claim(anchor: &SigningKey, server: &str, signing: &SigningKey) -> Claim {
        Claim {
            realm: "R".into(),
            server: server.into(),
            anchor: Some(*anchor.public().thumbprint()),
            key: *signing.public().thumbprint(),
            iat: NOW,
            exp: NOW + DEFAULT_VALIDITY,
        }
    }

    /// `old` → `new`, valid for 400 days from `NOW`.
    fn succeed(old: &SigningKey, new: &SigningKey) -> SignedSuccession {
        SignedSuccession::issue(
            old,
            "R",
            new.public().thumbprint(),
            NOW,
            NOW + DEFAULT_SUCCESSION_VALIDITY,
        )
        .unwrap()
    }

    #[test]
    fn successions_lead_from_rotated_anchors() {
        let (a0, a1, a2, server) = (key(), key(), key(), key());
        // The server's anchor is a2 now: a0 → a1 → a2.
        let mut d = Delegation::issue(
            &a2,
            "R",
            "ipa1.r",
            server.public(),
            NOW,
            NOW + DEFAULT_VALIDITY,
        )
        .unwrap();
        let (s01, s12) = (succeed(&a0, &a1), succeed(&a1, &a2));
        d.add_successions([s12.clone(), s01.clone(), s01.clone()]);
        assert_eq!(d.successions().len(), 2);
        let d = Delegation::from_json(d.to_json().as_bytes()).unwrap();
        let p = Policy::default();
        let thp = |k: &SigningKey| *k.public().thumbprint();

        // Pinned directly: no succession followed.
        let v = d.verify_at(&[thp(&a2)], &p, NOW).unwrap();
        assert_eq!(v.succeeded, []);
        // One and two hops.
        let v = d.verify_at(&[thp(&a1)], &p, NOW).unwrap();
        assert_eq!(v.succeeded, vec![(thp(&a1), thp(&a2))]);
        assert_eq!(v.anchor, thp(&a2));
        let v = d.verify_at(&[thp(&a0)], &p, NOW).unwrap();
        assert_eq!(
            v.succeeded,
            vec![(thp(&a0), thp(&a1)), (thp(&a1), thp(&a2))]
        );

        // select keeps the chain a client pinning a0 needs, and nothing
        // when it pins the proof's anchor.
        let chosen = d.select(&[thp(&a0)]);
        assert_eq!(chosen.successions(), &[s01.clone(), s12.clone()]);
        assert!(chosen.verify_at(&[thp(&a0)], &p, NOW).is_ok());
        assert_eq!(d.select(&[thp(&a2)]).successions(), []);
        assert_eq!(d.select(&[thp(&server)]).successions(), []);
        assert_eq!(d.select(&[]).successions().len(), 2, "bundles keep all");

        // Expired, wrong realm, forged or misattributed successions are not
        // followed.
        let late = NOW + DEFAULT_SUCCESSION_VALIDITY + CLOCK_SKEW + 1;
        assert!(succeed(&a0, &a1).check("R", &p, late).is_err());
        assert!(matches!(s01.check("S", &p, NOW), Err(Error::WrongRealm)));
        let mut forged = s01.clone();
        forged.statement = s12.statement.clone();
        assert!(
            forged.check("R", &p, NOW).is_err(),
            "statement by another anchor"
        );
        let mut forged = s01.clone();
        forged.from = s12.from.clone();
        assert!(forged.check("R", &p, NOW).is_err(), "key of another anchor");
        let mut lone = Delegation::from_json(d.to_json().as_bytes()).unwrap();
        lone.successions = vec![forged, s12.clone()];
        assert!(matches!(
            lone.verify_at(&[thp(&a0)], &p, NOW),
            Err(Error::UntrustedAnchor)
        ));
        assert!(SignedSuccession::issue(&a0, "R", &thp(&a0), NOW, NOW + 1).is_err());

        // Wire form for the anchor exchange.
        let back = SignedSuccession::from_bytes(&s01.to_bytes().unwrap()).unwrap();
        assert_eq!(back, s01);
        assert!(SignedSuccession::from_bytes(b"IPSR").is_err());
    }

    #[test]
    fn succession_chains_are_bounded_and_acyclic() {
        let keys: Vec<SigningKey> = (0..=MAX_SUCCESSION_HOPS + 1).map(|_| key()).collect();
        let server = key();
        let last = keys.last().unwrap();
        let mut d = Delegation::issue(
            last,
            "R",
            "ipa1.r",
            server.public(),
            NOW,
            NOW + DEFAULT_VALIDITY,
        )
        .unwrap();
        d.add_successions(keys.windows(2).map(|w| succeed(&w[0], &w[1])));
        // A cycle back to the start does not loop.
        d.add_successions([succeed(&keys[1], &keys[0])]);
        let p = Policy::default();
        let thp = |k: &SigningKey| *k.public().thumbprint();
        assert!(
            d.verify_at(&[thp(&keys[1])], &p, NOW).is_ok(),
            "within the bound"
        );
        assert!(
            matches!(
                d.verify_at(&[thp(&keys[0])], &p, NOW),
                Err(Error::UntrustedAnchor)
            ),
            "one hop too many"
        );
        assert_eq!(d.select(&[thp(&keys[0])]).successions(), []);
    }

    #[test]
    fn delegations_without_successions_keep_their_shape() {
        let (anchor, server) = (key(), key());
        let d = Delegation::issue(&anchor, "R", "s", server.public(), NOW, NOW + 10).unwrap();
        assert!(!d.to_json().contains("successions"));
        let old = serde_json::json!({"claim": d.claim, "proofs": d.proofs}).to_string();
        assert_eq!(Delegation::from_json(old.as_bytes()).unwrap(), d);
    }

    #[test]
    fn claim_logs_append_and_keep_old_heads() {
        let anchor = key();
        let servers: Vec<_> = (0..4).map(|_| key()).collect();
        let claims: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, s)| claim(&anchor, &format!("s{i}"), s))
            .collect();
        let leaves = |n: usize| {
            claims[..n]
                .iter()
                .map(|c| c.leaf(TreeHash::Sha256).unwrap())
        };

        // The first vouch covers two claims; a head pinned at it.
        let v1 = SignedVouch::issue(&anchor, "R", leaves(2), NOW, NOW + 100, None).unwrap();
        let head1 = HeadPin {
            anchor: *anchor.public().thumbprint(),
            size: v1.vouch().size,
            root: v1.vouch().root,
        };

        // Two more claims join: the log keeps its order and appends, so
        // the old head still names a prefix of the new log.
        let v2 =
            SignedVouch::issue(&anchor, "R", leaves(4), NOW + 1, NOW + 101, Some(&v1)).unwrap();
        assert_eq!(v1.leaves(), &v2.leaves()[..2], "the log extends, in order");
        assert_eq!(merkle::root(&v2.leaves()[..2]).unwrap(), head1.root);

        // The old claim's head proof against the pinned head verifies,
        // from the new vouch, with no signature.
        let thp = *anchor.public().thumbprint();
        let hp = v2
            .head_proof(&claims[0], &thp, (head1.size, head1.root))
            .unwrap()
            .expect("the old claim is under the pinned head");
        let mut d = Delegation::new(&claims[0]);
        d.add_head_proofs([hp]);
        let v = d
            .verify_at_with_heads(&[], &[head1], &[], &Policy::default(), NOW + 5)
            .unwrap();
        assert_eq!(v.head_anchor, Some(head1.anchor));
        assert_eq!(v.vouched_until, u64::MAX, "a head proof never expires");
        assert_eq!(&v.key, servers[0].public().thumbprint());

        // A new claim is not under the pinned head: no head proof for it.
        assert!(
            v2.head_proof(&claims[3], &thp, (head1.size, head1.root))
                .unwrap()
                .is_none()
        );
        // A head the log does not make (wrong root, or too long) is
        // refused: no head proof at all.
        let wrong = (head1.size, crate::merkle::test_hash(9));
        assert!(v2.head_proof(&claims[0], &thp, wrong).unwrap().is_none());
        let beyond = (v2.leaves().len() as u64 + 1, v2.vouch().root);
        assert!(v2.head_proof(&claims[0], &thp, beyond).unwrap().is_none());
    }

    #[test]
    fn dropping_a_claim_appends_a_tombstone() {
        let anchor = key();
        let thp = *anchor.public().thumbprint();
        let servers: Vec<_> = (0..3).map(|_| key()).collect();
        let claims: Vec<_> = servers
            .iter()
            .enumerate()
            .map(|(i, s)| claim(&anchor, &format!("s{i}"), s))
            .collect();
        let leaves = |keep: &[usize]| {
            keep.iter()
                .map(|i| claims[*i].leaf(TreeHash::Sha256).unwrap())
                .collect::<Vec<_>>()
        };

        let v1 =
            SignedVouch::issue(&anchor, "R", leaves(&[0, 1, 2]), NOW, NOW + 100, None).unwrap();
        let v2 = SignedVouch::issue(&anchor, "R", leaves(&[0, 2]), NOW + 1, NOW + 101, Some(&v1))
            .unwrap();
        v2.verify(anchor.public(), &Policy::default()).unwrap();
        // Claim 1 dropped: the log grows by a tombstone, so the old head is
        // still a prefix of the new one…
        assert_eq!(v2.leaves().len(), 4);
        assert_eq!(&v2.leaves()[..3], v1.leaves());
        assert_eq!(
            v2.entries()[3],
            LogEntry::Tombstone {
                target: 1,
                time: NOW + 1
            }
        );
        assert_eq!(v2.live(), &leaves(&[0, 2])[..]);
        assert_eq!(v2.retired(), &leaves(&[1])[..]);
        // …but the dropped claim no longer proves: not by signature (the
        // live tree lacks it), not by the new head, and not by the old head
        // for a host that learned the tombstone.
        assert!(v2.proof(&claims[1], anchor.public()).unwrap().is_none());
        assert!(!v2.covers(&claims[1]).unwrap());
        let head1 = (v1.vouch().size, v1.vouch().root);
        let head2 = (v2.vouch().size, v2.vouch().root);
        assert!(v2.head_proof(&claims[1], &thp, head2).unwrap().is_none());
        let old = v2.head_proof(&claims[1], &thp, head1).unwrap().unwrap();
        let pin1 = HeadPin {
            anchor: thp,
            size: head1.0,
            root: head1.1,
        };
        let mut dropped = Delegation::new(&claims[1]);
        dropped.head_proofs = vec![old.to_json()];
        dropped
            .verify_at_with_heads(&[], &[pin1], &[], &Policy::default(), NOW + 2)
            .unwrap();
        assert!(
            dropped
                .verify_at_with_heads(&[], &[pin1], v2.retired(), &Policy::default(), NOW + 2)
                .is_err(),
            "a retired claim proves nothing by an old head"
        );
        // The kept claims prove by the old head and the new.
        assert!(v2.head_proof(&claims[0], &thp, head1).unwrap().is_some());
        assert!(v2.head_proof(&claims[2], &thp, head2).unwrap().is_some());
        // A host pinning either head learns what that prefix retired.
        assert_eq!(v2.retired_at(head1.0, &head1.1).unwrap(), Some(Vec::new()));
        assert_eq!(
            v2.retired_at(head2.0, &head2.1).unwrap(),
            Some(leaves(&[1]))
        );
        assert_eq!(v2.retired_at(head2.0, &head1.1).unwrap(), None);
        assert_eq!(v2.retired_at(head2.0 + 1, &head2.1).unwrap(), None);
        // Vouching for it again appends it again, live once more.
        let v3 = SignedVouch::issue(
            &anchor,
            "R",
            leaves(&[0, 1, 2]),
            NOW + 2,
            NOW + 102,
            Some(&v2),
        )
        .unwrap();
        v3.verify(anchor.public(), &Policy::default()).unwrap();
        assert_eq!(v3.leaves().len(), 5);
        assert!(v3.covers(&claims[1]).unwrap() && v3.retired().is_empty());
    }

    #[test]
    fn claim_logs_follow_the_tombstone_rules() {
        let anchor = key();
        let sign = |entries: Vec<LogEntry>| {
            // A vouch over any entries, signed honestly over what they make.
            let replayed = replay(&entries, TreeHash::Sha256);
            replayed.map(|r| {
                let vouch = Vouch {
                    realm: "R".into(),
                    anchor: *anchor.public().thumbprint(),
                    iat: NOW,
                    exp: NOW + 100,
                    size: r.leaves.len() as u64,
                    root: merkle::root(&r.leaves).unwrap(),
                    live_size: r.live.len() as u64,
                    live_root: merkle::root(&r.live).unwrap_or(crate::merkle::test_hash(0)),
                };
                let signature = anchor
                    .sign_with_context(&vouch.to_bytes(), VOUCH_CONTEXT)
                    .unwrap();
                SignedVouch {
                    vouch,
                    signature,
                    entries,
                    leaves: r.leaves,
                    live: r.live,
                    retired: r.retired,
                }
            })
        };
        let t = |target| LogEntry::Tombstone { target, time: NOW };
        let c = |n: u8| LogEntry::Claim(crate::merkle::test_hash(n));
        // A tombstone for a later index, for a tombstone, twice; a claim
        // appended while live: none replays.
        for bad in [
            vec![t(1), c(1)],
            vec![c(1), t(0), t(1)],
            vec![c(1), t(0), t(0)],
            vec![c(1), c(1)],
        ] {
            assert!(sign(bad.clone()).is_err(), "{bad:?}");
        }
        // A good log survives the wire with its entries.
        let good = sign(vec![c(1), c(2), t(0), c(1)]).unwrap();
        good.verify(anchor.public(), &Policy::default()).unwrap();
        let parsed = SignedVouch::from_bytes(&good.to_bytes()).unwrap();
        assert_eq!(parsed, good);
        assert_eq!(
            parsed.live(),
            &[crate::merkle::test_hash(2), crate::merkle::test_hash(1)]
        );
        // A tampered entry no longer makes the signed trees.
        let mut tampered = good.clone();
        tampered.entries[1] = c(3);
        assert!(
            tampered
                .verify(anchor.public(), &Policy::default())
                .is_err()
        );
    }

    // PoC port (adversary poc_log_prefix): the production caller passes
    // `Trust::leaves()` — claim leaves in server-name order — so a new
    // member can sort *in front of* the existing log.  The old log's
    // order must survive regardless of caller order: every earlier
    // prefix is the tree an earlier vouch signed (§4.9.1).
    #[test]
    fn log_extends_in_log_order_when_a_new_member_sorts_first() {
        let anchor = key();
        let thp = *anchor.public().thumbprint();
        let b = claim(&anchor, "b.example.test", &key());
        let a = claim(&anchor, "a.example.test", &key());

        let v1 = SignedVouch::issue(
            &anchor,
            "R",
            [b.leaf(TreeHash::Sha256).unwrap()],
            NOW,
            NOW + 100,
            None,
        )
        .unwrap();
        let pinned = v1.head();

        // "a" joins and sorts before "b": the caller hands [a, b].
        let v2 = SignedVouch::issue(
            &anchor,
            "R",
            [
                a.leaf(TreeHash::Sha256).unwrap(),
                b.leaf(TreeHash::Sha256).unwrap(),
            ],
            NOW + 1,
            NOW + 101,
            Some(&v1),
        )
        .unwrap();
        assert_eq!(
            v2.leaves(),
            &[
                b.leaf(TreeHash::Sha256).unwrap(),
                a.leaf(TreeHash::Sha256).unwrap()
            ],
            "the old log keeps its order; the new claim appends"
        );
        assert!(v2.covers(&b).unwrap());
        assert_eq!(merkle::root(&v2.leaves()[..1]).unwrap(), pinned.1);
        assert!(
            v2.head_proof(&b, &thp, pinned).unwrap().is_some(),
            "the pinned head still proves the older claim, without a signature"
        );
    }

    // PoC port (adversary poc_merkle_edges, duplicate leaves): leaves
    // are deduplicated on every path, so the server can never sign a
    // vouch its own verify() rejects.
    #[test]
    fn duplicate_leaves_are_deduplicated_on_issue() {
        let anchor = key();
        let c1 = claim(&anchor, "a", &key());
        let c2 = claim(&anchor, "b", &key());
        let v = SignedVouch::issue(
            &anchor,
            "R",
            [
                c1.leaf(TreeHash::Sha256).unwrap(),
                c2.leaf(TreeHash::Sha256).unwrap(),
                c1.leaf(TreeHash::Sha256).unwrap(),
            ],
            NOW,
            NOW + 100,
            None,
        )
        .unwrap();
        assert_eq!(
            v.leaves(),
            &[
                c1.leaf(TreeHash::Sha256).unwrap(),
                c2.leaf(TreeHash::Sha256).unwrap()
            ]
        );
        v.verify(anchor.public(), &Policy::default())
            .unwrap_or_else(|e| panic!("an issued vouch must survive verify: {e}"));
    }

    // PoC port (adversary poc_merkle_edges, zero-size head): size 0 is
    // not a head — it proves nothing, and never errors into a 503.
    #[test]
    fn a_zero_size_head_proves_nothing() {
        let anchor = key();
        let thp = *anchor.public().thumbprint();
        let c = claim(&anchor, "a", &key());
        let v = SignedVouch::issue(
            &anchor,
            "R",
            [c.leaf(TreeHash::Sha256).unwrap()],
            NOW,
            NOW + 100,
            None,
        )
        .unwrap();
        assert!(
            v.head_proof(&c, &thp, (0, crate::merkle::test_hash(0)))
                .unwrap()
                .is_none()
        );
    }

    // The heads a delegation proves by signature (§4.9.6): an advertised
    // head must appear here to be the anchor's own.  A tampered vouch
    // proves no head; an expired vouch proves none either.
    #[test]
    fn verified_heads_follow_the_signed_vouch_only() {
        let anchor = key();
        let server = key();
        let d = Delegation::issue(
            &anchor,
            "R",
            "ipa1.r",
            server.public(),
            NOW,
            NOW + DEFAULT_VALIDITY,
        )
        .unwrap();
        let p = Policy::default();
        let leaf = d.claim().unwrap().leaf(TreeHash::Sha256).unwrap();
        assert_eq!(
            d.verified_heads(&p, NOW),
            vec![HeadPin {
                anchor: *anchor.public().thumbprint(),
                size: 1,
                root: merkle::root(&[leaf]).unwrap(),
            }]
        );
        let mut forged = d.clone();
        forged.proofs[0].vouch = b64::encode(&[0u8; 8]);
        assert!(
            forged.verified_heads(&p, NOW).is_empty(),
            "a vouch its anchor did not sign proves no head"
        );
        assert!(
            d.verified_heads(&p, NOW + VOUCH_VALIDITY + CLOCK_SKEW + 1)
                .is_empty(),
            "an expired vouch proves no head"
        );
    }

    #[test]
    fn head_proofs_do_not_verify_against_other_heads_or_tampering() {
        let anchor = key();
        let server = key();
        let c = claim(&anchor, "s", &server);
        let c2 = claim(&anchor, "t", &server);
        let v = SignedVouch::issue(
            &anchor,
            "R",
            [
                c.leaf(TreeHash::Sha256).unwrap(),
                c2.leaf(TreeHash::Sha256).unwrap(),
            ],
            NOW,
            NOW + 100,
            None,
        )
        .unwrap();
        let head = HeadPin {
            anchor: *anchor.public().thumbprint(),
            size: 2,
            root: v.vouch().root,
        };
        let thp = *anchor.public().thumbprint();
        let hp = v
            .head_proof(&c, &thp, (head.size, head.root))
            .unwrap()
            .unwrap();

        // Another anchor's head does not prove it.
        let other = key();
        let foreign = HeadPin {
            anchor: *other.public().thumbprint(),
            size: head.size,
            root: head.root,
        };
        assert!(!foreign.check(&c, &hp).unwrap());
        // A tampered path does not verify.
        let mut tampered = hp.clone();
        tampered.path[0] = b64::encode(&[0; 32]);
        assert!(!head.check(&c, &tampered).unwrap());
        // A head proof for another claim does not verify for this one.
        let c2 = claim(&anchor, "t", &server);
        assert!(!head.check(&c2, &hp).unwrap());

        // JSON round trip keeps the proof.
        let back = HeadProof::from_json(&hp.to_json()).unwrap();
        assert_eq!(back, hp);
        assert_eq!(HeadPin::from_json(&head.to_json()).unwrap(), head);
    }

    #[test]
    fn issue_and_verify() {
        let (anchor, server) = (key(), key());
        let d = Delegation::issue(
            &anchor,
            "R",
            "ipa1.r",
            server.public(),
            NOW,
            NOW + DEFAULT_VALIDITY,
        )
        .unwrap();
        let d = Delegation::from_json(d.to_json().as_bytes()).unwrap();
        let pinned = [*anchor.public().thumbprint()];
        let v = d.verify_at(&pinned, &Policy::default(), NOW + 10).unwrap();
        assert_eq!(v.server, "ipa1.r");
        assert_eq!(&v.key, server.public().thumbprint());
        assert_eq!(v.anchor, pinned[0]);
        assert_eq!(v.vouched_until, NOW + VOUCH_VALIDITY);

        let other = [*server.public().thumbprint()];
        assert!(matches!(
            d.verify_at(&other, &Policy::default(), NOW),
            Err(Error::UntrustedAnchor)
        ));
        // The vouch lapses long before the claim.
        assert!(matches!(
            d.verify_at(
                &pinned,
                &Policy::default(),
                NOW + VOUCH_VALIDITY + CLOCK_SKEW + 1
            ),
            Err(Error::UntrustedAnchor)
        ));
        assert!(matches!(
            d.verify_at(&pinned, &Policy::cnsa2(), NOW),
            Err(Error::UntrustedAnchor)
        ));
        assert!(Delegation::issue(&anchor, "R", "s", server.public(), NOW, NOW).is_err());
    }

    #[test]
    fn a_cnsa_anchor_keeps_a_sha_384_claim_log() {
        // An ML-DSA-87 anchor (CNSA 2.0) hashes its claim log with
        // SHA-384: the vouch's roots are 48 bytes, the delegation's
        // proof verifies under CNSA, and SHA-256 leaves are refused.
        let anchor = SigningKey::generate(SignatureAlg::MlDsa87).unwrap();
        let server = SigningKey::generate(SignatureAlg::MlDsa87).unwrap();
        let d = Delegation::issue(
            &anchor,
            "R",
            "ipa1.r",
            server.public(),
            NOW,
            NOW + DEFAULT_VALIDITY,
        )
        .unwrap();
        let d = Delegation::from_json(d.to_json().as_bytes()).unwrap();
        let pinned = [*anchor.public().thumbprint()];
        d.verify_at(&pinned, &Policy::cnsa2(), NOW + 10).unwrap();
        let c = claim(&anchor, "ipa1.r", &server);
        let v = SignedVouch::issue(
            &anchor,
            "R",
            [c.leaf(TreeHash::Sha384).unwrap()],
            NOW,
            NOW + 100,
            None,
        )
        .unwrap();
        let v = SignedVouch::from_bytes(&v.to_bytes()).unwrap();
        assert_eq!(v.alg(), TreeHash::Sha384);
        assert_eq!((v.vouch().root.len(), v.vouch().live_root.len()), (48, 48));
        assert!(v.covers(&c).unwrap());
        let head = (v.vouch().size, v.vouch().root);
        assert!(
            v.head_proof(&c, anchor.public().thumbprint(), head)
                .unwrap()
                .is_some()
        );
        assert!(
            SignedVouch::issue(
                &anchor,
                "R",
                [c.leaf(TreeHash::Sha256).unwrap()],
                NOW,
                NOW + 100,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn one_vouch_covers_many_claims() {
        let anchors: Vec<_> = (0..3).map(|_| key()).collect();
        let signing: Vec<_> = (0..3).map(|_| key()).collect();
        let claims: Vec<_> = (0..3)
            .map(|i| claim(&anchors[i], &format!("s{i}"), &signing[i]))
            .collect();
        // Anchor 0 vouches for all three claims with one signature.
        let v = SignedVouch::issue(
            &anchors[0],
            "R",
            claims.iter().map(|c| c.leaf(TreeHash::Sha256).unwrap()),
            NOW,
            NOW + VOUCH_VALIDITY,
            None,
        )
        .unwrap();
        v.verify(anchors[0].public(), &Policy::default()).unwrap();
        assert!(v.verify(anchors[1].public(), &Policy::default()).is_err());
        let back = SignedVouch::from_bytes(&v.to_bytes()).unwrap();
        assert_eq!(back, v);
        for c in &claims {
            assert!(v.covers(c).unwrap());
            let mut d = Delegation::new(c);
            d.add(v.proof(c, anchors[0].public()).unwrap());
            d.verify_at(
                &[*anchors[0].public().thumbprint()],
                &Policy::default(),
                NOW,
            )
            .unwrap();
        }
        let stranger = claim(&anchors[1], "s9", &signing[1]);
        assert!(!v.covers(&stranger).unwrap());
        assert!(v.proof(&stranger, anchors[0].public()).unwrap().is_none());
    }

    #[test]
    fn proofs_combine_and_select() {
        let (own, other, signing) = (key(), key(), key());
        let c = claim(&own, "s", &signing);
        let vouch = |a: &SigningKey| {
            SignedVouch::issue(
                a,
                "R",
                [c.leaf(TreeHash::Sha256).unwrap()],
                NOW,
                NOW + VOUCH_VALIDITY,
                None,
            )
            .unwrap()
        };
        let mut d = Delegation::new(&c);
        d.add(vouch(&own).proof(&c, own.public()).unwrap());
        d.add(vouch(&other).proof(&c, other.public()).unwrap());
        d.add(vouch(&other).proof(&c, other.public()).unwrap());
        assert_eq!(d.proof_count(), 2, "one proof per anchor");
        assert_eq!(
            d.signers(&Policy::default()),
            [*own.public().thumbprint(), *other.public().thumbprint()]
        );
        let wanted = d.select(&[*other.public().thumbprint()]);
        assert_eq!(
            wanted.signers(&Policy::default()),
            [*other.public().thumbprint()]
        );
        let default = d.select(&[Thumbprint::from_bytes([7; 32])]);
        assert_eq!(
            default.signers(&Policy::default()),
            [*own.public().thumbprint()]
        );
    }

    #[test]
    fn tampering_is_detected() {
        let (anchor, signing) = (key(), key());
        let d = Delegation::issue(&anchor, "R", "s", signing.public(), NOW, NOW + 100).unwrap();
        let pinned = [*anchor.public().thumbprint()];
        // Another claim under the same proof.
        let mut v = d.to_value();
        let mut c = d.claim().unwrap();
        c.server = "evil".into();
        v["claim"] = b64::encode(&c.to_bytes()).into();
        let forged = Delegation::from_value(v).unwrap();
        assert!(matches!(
            forged.verify_at(&pinned, &Policy::default(), NOW),
            Err(Error::UntrustedAnchor)
        ));
        // A vouch for another realm.
        let claim = d.claim().unwrap();
        let other = SignedVouch::issue(
            &anchor,
            "X",
            [claim.leaf(TreeHash::Sha256).unwrap()],
            NOW,
            NOW + 100,
            None,
        )
        .unwrap();
        let mut d2 = Delegation::new(&claim);
        d2.add(other.proof(&claim, anchor.public()).unwrap());
        assert!(d2.verify_at(&pinned, &Policy::default(), NOW).is_err());
        // Leaves that do not make the signed tree.
        let mut sv = SignedVouch::issue(
            &anchor,
            "R",
            [crate::merkle::test_hash(1), crate::merkle::test_hash(2)],
            NOW,
            NOW + 100,
            None,
        )
        .unwrap();
        sv.entries[1] = LogEntry::Claim(crate::merkle::test_hash(3));
        assert!(sv.verify(anchor.public(), &Policy::default()).is_err());
    }
}
