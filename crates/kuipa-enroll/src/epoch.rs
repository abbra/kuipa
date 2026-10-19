//! The anchor epoch log: an append-only record of the realm's anchor
//! history (§4.8).
//!
//! Each entry states the realm's anchor set and its succession proofs
//! at a sequence number and commits to the head of the entry before it,
//! canonical so that the same state gives the same bytes, head and
//! entry on every server: servers that see the same realm converge on
//! one log, even when they arrived at that state by different paths.
//! The current anchors sign it.  A client that has
//! seen the realm once stores the head as a watermark: any later
//! observation must extend it, so a server built on a stolen or frozen
//! anchor key cannot keep serving the world from before the theft once
//! the realm has moved on.  Unlike §4.4's quorum, which needs a second
//! key, this needs only a second *looking*.
//!
//! An entry is a single statement, so it is signed directly, as a
//! [`Succession`](crate::delegation::Succession) is, not through a Merkle vootch.  Each signature
//! carries its anchor's public key, as a [`crate::delegation::Proof`]
//! does, so a fetched chain can be verified from the pinned thumbprints
//! alone.  A key is *proven* when it is pinned, or is the new end of a
//! [`SignedSuccession`] the chain lists whose old end is proven — at most
//! [`MAX_SUCCESSION_HOPS`] deep, as in [`crate::delegation`].  A part of
//! the chain is believed only when signed by a proven key: §4.2's trust
//! rule, transplanted.  A new anchor therefore enters either behind a
//! succession signed by the anchor it replaces, or behind a signature
//! from an anchor already believed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{Policy, SigningKey, Thumbprint, VerifyingKey, b64, primitives};

use crate::delegation::{MAX_SUCCESSION_HOPS, SignedSuccession};
use crate::error::{Error, Result};

const EPOCH_MAGIC: [u8; 4] = *b"IPAE";
const SIGNED_EPOCH_MAGIC: [u8; 4] = *b"IEPS";
const EPOCH_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 epoch";
const EPOCH_HEAD_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 epoch head";

/// Most entries fetched or listed at once.  Chains grow with anchor
/// changes, not with time: this is generous for real realms.
pub const MAX_EPOCH_FETCH: usize = 64;

/// One entry: the realm's anchors and succession proofs at `seq`,
/// committing to the entry before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorEpoch {
    realm: String,
    seq: u64,
    prev: [u8; 32],
    anchors: Vec<Thumbprint>,
    successions: Vec<SignedSuccession>,
}

/// The first entry's predecessor: nothing.
pub const GENESIS: [u8; 32] = [0; 32];

impl AnchorEpoch {
    /// The entry at sequence `seq`.  `prev` is the head of the entry at
    /// `seq - 1`, or [`GENESIS`] for the first entry.  `anchors` and
    /// `successions` are sorted and deduplicated, so every server derives
    /// the same entry, and the same head, from the same state.
    #[must_use]
    pub fn new(
        realm: &str,
        seq: u64,
        prev: [u8; 32],
        anchors: impl IntoIterator<Item = Thumbprint>,
        successions: impl IntoIterator<Item = SignedSuccession>,
    ) -> Self {
        let mut anchors: Vec<Thumbprint> = anchors.into_iter().collect();
        anchors.sort_unstable();
        anchors.dedup();
        let mut successions: Vec<SignedSuccession> = successions.into_iter().collect();
        successions.sort_by(|a, b| a.order_key().cmp(b.order_key()));
        successions.dedup();
        Self {
            realm: realm.into(),
            seq,
            prev,
            anchors,
            successions,
        }
    }

    /// The sequence number.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// The head of the entry before this one, or [`GENESIS`].
    #[must_use]
    pub fn prev(&self) -> [u8; 32] {
        self.prev
    }

    /// The anchor set.
    #[must_use]
    pub fn anchors(&self) -> &[Thumbprint] {
        &self.anchors
    }

    /// The realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The succession proofs.
    #[must_use]
    pub fn successions(&self) -> &[SignedSuccession] {
        &self.successions
    }

    /// Encode: `IPAE ‖ 1 ‖ realm ‖ seq ‖ prev(32) ‖ n ‖ anchors(32·n) ‖
    /// m ‖ signed-successions · m`; these are the signed bytes, and the
    /// bytes the head hashes.
    #[allow(clippy::missing_panics_doc)] // fields are checked when built or parsed
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(EPOCH_MAGIC);
        w.u8(1)
            .str(&self.realm)
            .u64(self.seq)
            .fixed(&self.prev)
            .u64(self.anchors.len() as u64);
        for a in &self.anchors {
            w.fixed(a.as_bytes());
        }
        w.u64(self.successions.len() as u64);
        for s in &self.successions {
            w.bytes(&s.to_bytes().expect("valid fields"));
        }
        w.finish()
    }

    /// Decode, checking the anchor and succession lists are sorted and
    /// unique as `new` writes them, so the encoding is canonical.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, EPOCH_MAGIC, "epoch")?;
        if r.u8()? != 1 {
            return Err(Error::Malformed("epoch version"));
        }
        let realm = r.str()?.into();
        let seq = r.u64()?;
        let prev = r.fixed()?;
        let n = count(&mut r, "epoch anchor count")?;
        let mut anchors = Vec::with_capacity(n);
        for _ in 0..n {
            anchors.push(Thumbprint::from_bytes(r.fixed()?));
        }
        let m = count(&mut r, "epoch succession count")?;
        let mut successions = Vec::with_capacity(m);
        for _ in 0..m {
            successions.push(SignedSuccession::from_bytes(r.bytes()?)?);
        }
        r.finish()?;
        if !anchors.windows(2).all(|w| w[0] < w[1]) {
            return Err(Error::Malformed("epoch anchors not canonical"));
        }
        let keys: Vec<&str> = successions
            .iter()
            .map(SignedSuccession::order_key)
            .collect();
        if !keys.windows(2).all(|w| w[0] < w[1]) {
            return Err(Error::Malformed("epoch successions not canonical"));
        }
        Ok(Self {
            realm,
            seq,
            prev,
            anchors,
            successions,
        })
    }

    /// The entry's hash: what the advertisement names as the log's
    /// head, and what the client stores as its watermark.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn head(&self) -> Result<[u8; 32]> {
        Ok(primitives::sha256(&[EPOCH_HEAD_CONTEXT, &self.to_bytes()])?)
    }
}

fn count(r: &mut Reader<'_>, what: &'static str) -> Result<usize> {
    let n = r.u64()?;
    usize::try_from(n)
        .ok()
        .filter(|n| *n <= MAX_EPOCH_FETCH * 16)
        .ok_or(Error::Malformed(what))
}

/// One anchor's signature on an entry: the key travels with it, as in a
/// [`crate::delegation::Proof`], so a fetched chain verifies from
/// thumbprints alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochSignature {
    /// The anchor's public key (JWK).
    anchor: Value,
    /// The signature (base64url).
    signature: String,
}

/// An entry with the signatures of the anchors that signed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEpoch {
    /// The entry (base64url).
    entry: String,
    /// The anchors' signatures.
    signatures: Vec<EpochSignature>,
}

impl SignedEpoch {
    /// Sign `epoch` with `anchor`.
    ///
    /// # Errors
    ///
    /// A signing or OpenSSL error.
    pub fn issue(anchor: &SigningKey, epoch: &AnchorEpoch) -> Result<Self> {
        let statement = epoch.to_bytes();
        let signature = anchor.sign_with_context(&statement, EPOCH_CONTEXT)?;
        Ok(Self {
            entry: b64::encode(&statement),
            signatures: vec![Self::signature_of(anchor.public(), &signature)],
        })
    }

    fn signature_of(key: &VerifyingKey, signature: &[u8]) -> EpochSignature {
        EpochSignature {
            anchor: serde_json::from_str(&key.to_jwk_json()).expect("a JWK is valid JSON"),
            signature: b64::encode(signature),
        }
    }

    /// The entry, **unverified**.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn statement(&self) -> Result<AnchorEpoch> {
        AnchorEpoch::from_bytes(&b64::decode(&self.entry)?)
    }

    /// Add the signatures of `other` if it is the same entry: every
    /// current anchor signs it, and servers learn each other's signatures
    /// through the exchange.
    #[must_use]
    pub fn merge(&mut self, other: &Self) -> bool {
        if self.entry != other.entry {
            return false;
        }
        for s in &other.signatures {
            if !self.signatures.iter().any(|e| e.anchor == s.anchor) {
                self.signatures.push(s.clone());
            }
        }
        true
    }

    /// Check the entry's own signatures — each by a key named in the
    /// entry's anchor set — and return the thumbprints whose signatures
    /// verified, for [`verify_chain`] to match against proven keys.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an unparsable key or signature,
    /// [`Error::UntrustedAnchor`] for no signatures, a signer outside the
    /// entry's anchors, or a bad signature or disallowed algorithm.
    pub fn verify(&self, epoch: &AnchorEpoch, policy: &Policy) -> Result<BTreeSet<Thumbprint>> {
        if self.signatures.is_empty() {
            return Err(Error::UntrustedAnchor);
        }
        let statement = b64::decode(&self.entry)?;
        let mut verified = BTreeSet::new();
        for s in &self.signatures {
            let key = VerifyingKey::from_jwk_json(s.anchor.to_string().as_bytes())
                .map_err(|_| Error::Malformed("epoch signature key"))?;
            if !epoch.anchors().contains(key.thumbprint()) || !policy.allows_signature(key.alg()) {
                return Err(Error::UntrustedAnchor);
            }
            key.verify_with_context(&statement, EPOCH_CONTEXT, &b64::decode(&s.signature)?)
                .map_err(|_| Error::UntrustedAnchor)?;
            verified.insert(*key.thumbprint());
        }
        Ok(verified)
    }
}

/// The keys proven by a set of succession proofs, from `trusted`:
/// `trusted`, then the new ends of successions whose old end is proven,
/// at most [`MAX_SUCCESSION_HOPS`] deep — `Delegation::proven`'s rule.
fn closure(
    trusted: &BTreeSet<Thumbprint>,
    adjacency: &BTreeMap<Thumbprint, Vec<Thumbprint>>,
) -> BTreeSet<Thumbprint> {
    let mut proven: BTreeSet<Thumbprint> = trusted.clone();
    for _ in 0..MAX_SUCCESSION_HOPS {
        let opened: Vec<Thumbprint> = adjacency
            .iter()
            .filter(|(old, _)| proven.contains(old))
            .flat_map(|(_, news)| news.iter().copied())
            .collect();
        let before = proven.len();
        proven.extend(opened);
        if proven.len() == before {
            break;
        }
    }
    proven
}

/// Verify a fetched piece of the chain: it continues `known` (a stored
/// `(seq, head)`; none only for a whole chain from the first entry) —
/// contiguity **and** each entry's commitment to its predecessor — its
/// succession proofs are signed by the anchors they replace, and each
/// entry carries a signature from a key believed so far: the pins, the
/// keys their successions reach, and the anchors of every entry a
/// believed key signed (§4.2).  Succession *signatures* are checked with
/// the realm's policy but not their expiry: the record of a rotation
/// outlives the succession that opened it.
///
/// Returns the `(seq, head)` to store as the new watermark.
///
/// # Errors
///
/// A [`String`] naming why the chain does not extend what is known, for
/// the caller to report and fail over on.
pub fn verify_chain(
    entries: &[SignedEpoch],
    realm: &str,
    pins: &[Thumbprint],
    known: Option<(u64, [u8; 32])>,
    policy: &Policy,
) -> std::result::Result<(u64, [u8; 32]), String> {
    if entries.is_empty() || entries.len() > MAX_EPOCH_FETCH {
        return Err("the anchor log answer is empty or too long".into());
    }
    let (mut seq, mut head) = known.unwrap_or((0, [0; 32]));
    // §4.2: believed keys: the pins first, then the anchors of every
    // entry a believed key signed, entry by entry.
    let mut trusted: BTreeSet<Thumbprint> = pins.iter().copied().collect();
    let mut adjacency: BTreeMap<Thumbprint, Vec<Thumbprint>> = BTreeMap::new();
    for signed in entries {
        let epoch = signed
            .statement()
            .map_err(|_| "the anchor log is malformed".to_string())?;
        if epoch.realm != realm {
            return Err("the anchor log is for another realm".into());
        }
        if epoch.seq != seq + 1 {
            return Err("the anchor log does not continue what this host knows".into());
        }
        if epoch.prev() != head {
            return Err("an entry of the anchor log does not commit to the entry before it".into());
        }
        for s in epoch.successions() {
            let st = s.check_signature(realm, policy).map_err(|_| {
                "a succession in the anchor log is not signed by the anchor it replaces".to_string()
            })?;
            adjacency.entry(st.old).or_default().push(st.new);
        }
        let signed_by = signed
            .verify(&epoch, policy)
            .map_err(|_| "the anchor log is not signed by the anchors it names".to_string())?;
        let proven = closure(&trusted, &adjacency);
        if !signed_by.iter().any(|a| proven.contains(a)) {
            return Err(
                "this part of the anchor log is not signed by an anchor this host can vouch for"
                    .into(),
            );
        }
        trusted.extend(epoch.anchors().iter().copied());
        head = epoch
            .head()
            .map_err(|_| "cannot hash the anchor log".to_string())?;
        seq = epoch.seq();
    }
    Ok((seq, head))
}

/// Encode a signed entry for the wire: `IEPS ‖ 1 ‖ entry ‖ n ‖
/// (key JWK, signature)·n`.
///
/// # Errors
///
/// [`Error::Malformed`] if a field is not valid base64url.
pub fn encode(signed: &SignedEpoch) -> Result<Vec<u8>> {
    let mut w = Writer::new(SIGNED_EPOCH_MAGIC);
    w.u8(1).bytes(&b64::decode(&signed.entry)?);
    w.u64(signed.signatures.len() as u64);
    for s in &signed.signatures {
        w.str(&s.anchor.to_string())
            .bytes(&b64::decode(&s.signature)?);
    }
    Ok(w.finish())
}

/// Decode (not verified).
///
/// # Errors
///
/// [`Error::Malformed`].
pub fn decode(buf: &[u8]) -> Result<SignedEpoch> {
    let mut r = Reader::new(buf, SIGNED_EPOCH_MAGIC, "signed epoch")?;
    if r.u8()? != 1 {
        return Err(Error::Malformed("signed epoch version"));
    }
    let entry = b64::encode(r.bytes()?);
    let n = count(&mut r, "epoch signature count")?;
    let mut signatures = Vec::with_capacity(n);
    for _ in 0..n {
        let anchor =
            serde_json::from_str(r.str()?).map_err(|_| Error::Malformed("epoch signature key"))?;
        signatures.push(EpochSignature {
            anchor,
            signature: b64::encode(r.bytes()?),
        });
    }
    r.finish()?;
    Ok(SignedEpoch { entry, signatures })
}

#[cfg(test)]
mod tests {
    use tang_pqc::{SignatureAlg, unix_seconds};

    use super::*;

    fn key() -> SigningKey {
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap()
    }

    fn thp(k: &SigningKey) -> Thumbprint {
        *k.public().thumbprint()
    }

    fn succession(old: &SigningKey, new: &Thumbprint) -> SignedSuccession {
        let now = unix_seconds(std::time::SystemTime::now());
        SignedSuccession::issue(old, "R", new, now - 60, now + 86_400).unwrap()
    }

    /// Three entries: `{a1}`, then a1 → a2 giving `{a2}`, then both.
    fn chain(a1: &SigningKey, a2: &SigningKey) -> Vec<SignedEpoch> {
        let e1 = AnchorEpoch::new("R", 1, GENESIS, [thp(a1)], []);
        let s1 = SignedEpoch::issue(a1, &e1).unwrap();
        let succ = succession(a1, &thp(a2));
        let e2 = AnchorEpoch::new("R", 2, e1.head().unwrap(), [thp(a2)], [succ.clone()]);
        let s2 = SignedEpoch::issue(a2, &e2).unwrap();
        let e3 = AnchorEpoch::new("R", 3, e2.head().unwrap(), [thp(a1), thp(a2)], [succ]);
        let mut s3 = SignedEpoch::issue(a1, &e3).unwrap();
        assert!(s3.merge(&SignedEpoch::issue(a2, &e3).unwrap()));
        vec![s1, s2, s3]
    }

    #[test]
    fn chain_extends_a_watermark_through_a_rotation() {
        let (a1, a2) = (key(), key());
        let full = chain(&a1, &a2);
        // The host pinned a1 and saw the first entry.
        let e1 = AnchorEpoch::new("R", 1, GENESIS, [thp(&a1)], []);
        let wm = (1, e1.head().unwrap());
        let now = verify_chain(&full[1..], "R", &[thp(&a1)], Some(wm), &Policy::default())
            .expect("the rotation is proven by the listed succession");
        assert_eq!(now.0, 3);
        assert_eq!(
            now.1,
            full[2].statement().unwrap().head().unwrap(),
            "the new watermark is the head"
        );
    }

    #[test]
    fn a_joining_anchor_needs_an_endorsement_it_has() {
        let (a1, a2) = (key(), key());
        // a2 joins the quorum without replacing anyone: entry 2 names
        // both and is signed by both; entry 2 signed only by a2 alone is
        // believed too, because §4.2's rule only needs one proven signer
        // — a1's membership in the entry is what the entry states.
        let e1 = AnchorEpoch::new("R", 1, GENESIS, [thp(&a1)], []);
        let wm = (1, e1.head().unwrap());
        let e2 = AnchorEpoch::new("R", 2, wm.1, [thp(&a1), thp(&a2)], []);
        let mut signed = SignedEpoch::issue(&a1, &e2).unwrap();
        assert!(signed.merge(&SignedEpoch::issue(&a2, &e2).unwrap()));
        let now = verify_chain(
            std::slice::from_ref(&signed),
            "R",
            &[thp(&a1)],
            Some(wm),
            &Policy::default(),
        )
        .expect("a1, proven, signs the entry that introduces a2");
        assert_eq!(now.0, 2);
    }

    #[test]
    fn a_self_asserted_entry_is_refused() {
        let (a1, a2) = (key(), key());
        let e1 = AnchorEpoch::new("R", 1, GENESIS, [thp(&a1)], []);
        let wm = (1, e1.head().unwrap());
        // a2 names itself as the only anchor, claiming no succession:
        // only a2 signs it, and nothing proves a2 to a host that knows
        // only a1.
        let e2 = AnchorEpoch::new("R", 2, wm.1, [thp(&a2)], []);
        let signed = SignedEpoch::issue(&a2, &e2).unwrap();
        let err = verify_chain(
            std::slice::from_ref(&signed),
            "R",
            &[thp(&a1)],
            Some(wm),
            &Policy::default(),
        )
        .expect_err("nothing vouches for a2");
        assert!(
            err.contains("not signed by an anchor this host can vouch for"),
            "{err}"
        );
    }

    #[test]
    fn a_self_asserted_succession_is_refused() {
        let (a1, a2) = (key(), key());
        let e1 = AnchorEpoch::new("R", 1, GENESIS, [thp(&a1)], []);
        let wm = (1, e1.head().unwrap());
        // A succession claiming to replace a1 but signed by a2: the
        // fields are private, so build it the way the wire would.
        let statement = crate::delegation::Succession {
            realm: "R".into(),
            old: thp(&a1),
            new: thp(&a2),
            iat: 1_000_000,
            exp: 2_000_000,
        };
        let bytes = statement.to_bytes();
        let signature = a2
            .sign_with_context(&bytes, b"ipa-ku-enroll/v1 succession")
            .unwrap();
        let lying: SignedSuccession = serde_json::from_value(serde_json::json!({
            "from": serde_json::from_str::<Value>(&a2.public().to_jwk_json()).unwrap(),
            "statement": b64::encode(&bytes),
            "signature": b64::encode(&signature),
        }))
        .unwrap();
        let e2 = AnchorEpoch::new("R", 2, wm.1, [thp(&a2)], [lying]);
        let signed = SignedEpoch::issue(&a2, &e2).unwrap();
        let err = verify_chain(
            std::slice::from_ref(&signed),
            "R",
            &[thp(&a1)],
            Some(wm),
            &Policy::default(),
        )
        .expect_err("the succession names a1 but is signed by a2");
        assert!(
            err.contains("not signed by the anchor it replaces"),
            "{err}"
        );
    }

    #[test]
    fn a_gap_or_a_replay_is_refused() {
        let (a1, a2) = (key(), key());
        let full = chain(&a1, &a2);
        let e1 = AnchorEpoch::new("R", 1, GENESIS, [thp(&a1)], []);
        let wm = (1, e1.head().unwrap());
        // Skipping entry 2: a verified log must not skip one.
        let err = verify_chain(&full[2..], "R", &[thp(&a1)], Some(wm), &Policy::default())
            .expect_err("a gap skips a sequence");
        assert!(err.contains("does not continue"), "{err}");
        // An answer starting at the watermark itself is not an extension.
        let err = verify_chain(&full[..1], "R", &[thp(&a1)], Some(wm), &Policy::default())
            .expect_err("a replay of the watermark");
        assert!(err.contains("does not continue"), "{err}");
    }

    #[test]
    fn a_forged_entry_by_an_unreachable_anchor_is_refused() {
        let (a1, a2, thief) = (key(), key(), key());
        let full = chain(&a1, &a2);
        let wm = full[2].statement().unwrap().head().unwrap();
        // The thief appends an entry naming itself, carrying the real
        // successions: in order and self-consistent, but no proven
        // key signs it and no succession leads to the thief.
        let e4 = AnchorEpoch::new(
            "R",
            4,
            wm,
            [thp(&thief)],
            full[2].statement().unwrap().successions().to_vec(),
        );
        let forged = SignedEpoch::issue(&thief, &e4).unwrap();
        let err = verify_chain(
            std::slice::from_ref(&forged),
            "R",
            &[thp(&a1)],
            Some((3, wm)),
            &Policy::default(),
        )
        .expect_err("a2's succession does not reach the thief");
        assert!(
            err.contains("not signed by an anchor this host can vouch for"),
            "{err}"
        );
    }

    #[test]
    fn a_signed_entry_survives_the_wire() {
        let a1 = key();
        let epoch = AnchorEpoch::new("R", 1, GENESIS, [thp(&a1)], []);
        let signed = SignedEpoch::issue(&a1, &epoch).unwrap();
        let back = decode(&encode(&signed).unwrap()).unwrap();
        assert_eq!(back, signed);
        assert_eq!(epoch, AnchorEpoch::from_bytes(&epoch.to_bytes()).unwrap());
    }

    #[test]
    fn an_entry_that_does_not_commit_to_its_predecessor_is_refused() {
        let a1 = key();
        let e1 = AnchorEpoch::new("R", 1, GENESIS, [thp(&a1)], []);
        let wm = (1, e1.head().unwrap());
        // In order, correctly signed, but committing to an entry this
        // host has never seen: its log is not a prefix of the answer.
        let e2 = AnchorEpoch::new("R", 2, [7; 32], [thp(&a1)], []);
        let signed = SignedEpoch::issue(&a1, &e2).unwrap();
        let err = verify_chain(
            std::slice::from_ref(&signed),
            "R",
            &[thp(&a1)],
            Some(wm),
            &Policy::default(),
        )
        .expect_err("entry 2 commits elsewhere");
        assert!(err.contains("does not commit"), "{err}");
    }

    #[test]
    fn an_anchor_endorsed_by_a_believed_entry_carries_the_chain() {
        let (a1, a2) = (key(), key());
        // Entry 2 names a2 with a1's signature: a2 is believed from
        // then on (§4.2), so entry 3 may continue on a2 alone — the
        // belief a proven signer endorses must carry past one page.
        let e1 = AnchorEpoch::new("R", 1, GENESIS, [thp(&a1)], []);
        let e2 = AnchorEpoch::new("R", 2, e1.head().unwrap(), [thp(&a1), thp(&a2)], []);
        let s2 = SignedEpoch::issue(&a1, &e2).unwrap();
        let e3 = AnchorEpoch::new("R", 3, e2.head().unwrap(), [thp(&a2)], []);
        let s3 = SignedEpoch::issue(&a2, &e3).unwrap();
        let now = verify_chain(
            &[s2, s3],
            "R",
            &[thp(&a1)],
            Some((1, e1.head().unwrap())),
            &Policy::default(),
        )
        .expect("a1 endorses a2 in entry 2");
        assert_eq!(now.0, 3, "the chain continues on a2's signature");
    }
}
