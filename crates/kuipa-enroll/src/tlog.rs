//! Typed transparency logs (`docs/DESIGN-tlog.md`).
//!
//! Each server keeps one append-only log of typed leaves — the claims
//! its anchor vouches for, and the vault, signing and token events it
//! handled — and signs its head with its delegation-vouched key.  Unlike
//! the claim log of §4.9, a leaf that stops being current is not dropped
//! (which restarted that log): a [`Kind::TOMBSTONE`] leaf naming it is
//! appended, so every head extends every earlier one and a monitor can
//! check that with a consistency proof instead of refetching the log.
//!
//! A leaf's kind is inside its hashed bytes, so leaves of different kinds
//! can never be confused.  A leaf carries an opaque `index` — an HMAC of
//! its subject (a vault, a principal) under a realm secret — so the log
//! can be published and audited without listing who it is about; only an
//! authenticated lookup maps a subject to its index.
//!
//! Witnesses cosign heads ([`SignedHead::cosign`]) only after checking
//! that the new head extends the last one they cosigned ([`witness`]),
//! so a server that shows different logs to different clients needs its
//! witnesses to collude.
//!
//! This module does no I/O: storage and serving belong to `kuipad`.

use std::collections::BTreeSet;

use native_ossl::digest::DigestAlg;
use native_ossl::mac::HmacCtx;
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{Policy, SigningKey, Thumbprint, VerifyingKey, primitives};

use crate::error::{Error, Result};
use crate::merkle::{self, Hash};

const LEAF_MAGIC: [u8; 4] = *b"IPLF";
const TOMBSTONE_MAGIC: [u8; 4] = *b"IPLT";
const HEAD_MAGIC: [u8; 4] = *b"IPLH";
const SIGNED_HEAD_MAGIC: [u8; 4] = *b"IPLS";
const COSIGNATURE_MAGIC: [u8; 4] = *b"IPLC";
const HEAD_CONTEXT: &[u8] = b"ipa-ku-log/v1 head";
const COSIGNATURE_CONTEXT: &[u8] = b"ipa-ku-log/v1 cosignature";
const LOG_ID_CONTEXT: &[u8] = b"ipa-ku-log/v1 id";

/// Largest leaf body accepted.
pub const MAX_BODY: usize = 64 * 1024;

/// Most cosignatures a signed head carries.
pub const MAX_COSIGNATURES: usize = 16;

/// A leaf's kind.  Unknown kinds parse, so monitors and mirrors keep
/// working when a server logs kinds they do not know yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Kind(pub u16);

impl Kind {
    /// A server claim (`IPDC`) its anchor vouches for.
    pub const CLAIM: Self = Self(1);
    /// A device added to or removed from a user vault.
    pub const VAULT_DEVICE: Self = Self(2);
    /// A vault policy set, or a vault revoked.
    pub const VAULT_POLICY: Self = Self(3);
    /// An escrow share released (unlock, offline session, override).
    pub const ESCROW_RELEASE: Self = Self(4);
    /// A signing statement.
    pub const STATEMENT: Self = Self(5);
    /// A Keys-operation fetch.
    pub const KEYS_FETCH: Self = Self(6);
    /// A token key epoch.
    pub const TOKEN_KEY: Self = Self(7);
    /// A leaf that is no longer current ([`Tombstone`]).
    pub const TOMBSTONE: Self = Self(0xFFFF);
}

/// One log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// What the body is.
    pub kind: Kind,
    /// When the server logged it (Unix seconds).
    pub time: u64,
    /// The subject's [`index`], or zeros for none.
    pub index: [u8; 32],
    /// The kind's own encoding.
    pub body: Vec<u8>,
}

impl Leaf {
    /// `IPLF ‖ 1 ‖ kind(2) ‖ time ‖ index(32) ‖ body`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(LEAF_MAGIC)
            .fixed(&self.kind.0.to_be_bytes())
            .u64(self.time)
            .fixed(&self.index)
            .bytes(&self.body)
            .finish()
    }

    /// Parse a leaf.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, LEAF_MAGIC, "log leaf")?;
        let kind = Kind(u16::from_be_bytes(r.fixed()?));
        let time = r.u64()?;
        let index = r.fixed()?;
        let body = r.bytes()?;
        if body.len() > MAX_BODY {
            return Err(Error::Malformed("log leaf body"));
        }
        let body = body.to_vec();
        r.finish()?;
        Ok(Self {
            kind,
            time,
            index,
            body,
        })
    }

    /// The leaf's tree hash.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn hash(&self) -> Result<Hash> {
        merkle::leaf_hash(&self.to_bytes())
    }

    /// A tombstone for the leaf at `target`.
    #[must_use]
    pub fn tombstone(time: u64, target: u64, reason: &str) -> Self {
        Self {
            kind: Kind::TOMBSTONE,
            time,
            index: [0; 32],
            body: Tombstone {
                target,
                reason: reason.to_owned(),
            }
            .to_bytes(),
        }
    }
}

/// The body of a [`Kind::TOMBSTONE`] leaf: the leaf at `target` is no
/// longer current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tombstone {
    /// The index of the leaf it retires.
    pub target: u64,
    /// Why, for auditors.
    pub reason: String,
}

impl Tombstone {
    /// `IPLT ‖ 1 ‖ target ‖ reason`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(TOMBSTONE_MAGIC)
            .u64(self.target)
            .str(&self.reason)
            .finish()
    }

    /// Parse a tombstone body.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, TOMBSTONE_MAGIC, "tombstone")?;
        let target = r.u64()?;
        let reason = r.str()?.to_owned();
        r.finish()?;
        Ok(Self { target, reason })
    }
}

/// The opaque index of `subject` under the realm's index key:
/// `HMAC-SHA-256(key, subject)`.
///
/// # Errors
///
/// An OpenSSL error.
pub fn index(key: &[u8; 32], subject: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacCtx::new(&DigestAlg::fetch(c"SHA2-256", None)?, key)?;
    mac.update(subject)?;
    let mut out = [0u8; 32];
    if mac.finish(&mut out)? != out.len() {
        return Err(Error::Malformed("log index"));
    }
    Ok(out)
}

/// A log's identity: one per server, stable across key rotations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LogId(pub [u8; 32]);

impl LogId {
    /// The log of `server` in `realm`:
    /// `SHA-256("ipa-ku-log/v1 id" ‖ len(realm) ‖ realm ‖ server)`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn of(realm: &str, server: &str) -> Result<Self> {
        let len = u32::try_from(realm.len())
            .map_err(|_| Error::Malformed("realm"))?
            .to_be_bytes();
        Ok(Self(primitives::sha256(&[
            LOG_ID_CONTEXT,
            &len,
            realm.as_bytes(),
            server.as_bytes(),
        ])?))
    }
}

/// A log, as the hashes and kinds of its leaves: enough to append, prove
/// and sign.  The leaves themselves live in the server's store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    id: LogId,
    hashes: Vec<Hash>,
    kinds: Vec<Kind>,
    retired: BTreeSet<u64>,
}

impl Log {
    /// An empty log.
    #[must_use]
    pub fn new(id: LogId) -> Self {
        Self {
            id,
            hashes: Vec::new(),
            kinds: Vec::new(),
            retired: BTreeSet::new(),
        }
    }

    /// Rebuild a log from its stored leaves, in order.
    ///
    /// # Errors
    ///
    /// As [`append`](Self::append).
    pub fn replay<'a>(id: LogId, leaves: impl IntoIterator<Item = &'a Leaf>) -> Result<Self> {
        let mut log = Self::new(id);
        for leaf in leaves {
            log.append(leaf)?;
        }
        Ok(log)
    }

    /// The log's identity.
    #[must_use]
    pub fn id(&self) -> LogId {
        self.id
    }

    /// How many leaves it holds.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.hashes.len() as u64
    }

    /// The leaf hashes, in order.
    #[must_use]
    pub fn hashes(&self) -> &[Hash] {
        &self.hashes
    }

    /// Whether a tombstone retires the leaf at `index`.
    #[must_use]
    pub fn is_retired(&self, index: u64) -> bool {
        self.retired.contains(&index)
    }

    /// Append `leaf` and return its index.  A tombstone must name an
    /// earlier leaf that is neither a tombstone nor already retired.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a tombstone that breaks those rules, an
    /// OpenSSL error otherwise.
    pub fn append(&mut self, leaf: &Leaf) -> Result<u64> {
        if leaf.kind == Kind::TOMBSTONE {
            let target = Tombstone::from_bytes(&leaf.body)?.target;
            let kind = usize::try_from(target)
                .ok()
                .and_then(|t| self.kinds.get(t))
                .ok_or(Error::Malformed("tombstone target"))?;
            if *kind == Kind::TOMBSTONE || self.retired.contains(&target) {
                return Err(Error::Malformed("tombstone target"));
            }
            self.retired.insert(target);
        }
        self.hashes.push(leaf.hash()?);
        self.kinds.push(leaf.kind);
        Ok(self.size() - 1)
    }

    /// The tree hash over all leaves.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an empty log.
    pub fn root(&self) -> Result<Hash> {
        merkle::root(&self.hashes)
    }

    /// The inclusion path of the leaf at `index` in the current tree.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an index outside the log.
    pub fn inclusion(&self, index: u64) -> Result<Vec<Hash>> {
        let index = usize::try_from(index).map_err(|_| Error::Malformed("leaf index"))?;
        merkle::path(&self.hashes, index)
    }

    /// The proof that the log at `old_size` is a prefix of the current one.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an `old_size` of zero or beyond the log.
    pub fn consistency(&self, old_size: u64) -> Result<Vec<Hash>> {
        merkle::consistency(&self.hashes, old_size)
    }

    /// The current head, stamped `time`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an empty log.
    pub fn head(&self, time: u64) -> Result<Head> {
        Ok(Head {
            log: self.id,
            size: self.size(),
            root: self.root()?,
            time,
        })
    }
}

/// A log's state at a moment: what its server signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The log.
    pub log: LogId,
    /// Its size.
    pub size: u64,
    /// Its tree hash.
    pub root: Hash,
    /// When it was signed (Unix seconds).
    pub time: u64,
}

impl Head {
    /// `IPLH ‖ 1 ‖ log(32) ‖ size ‖ root(32) ‖ time`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(HEAD_MAGIC)
            .fixed(&self.log.0)
            .u64(self.size)
            .fixed(&self.root)
            .u64(self.time)
            .finish()
    }

    /// Parse a head.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for a size of zero.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, HEAD_MAGIC, "log head")?;
        let head = Self {
            log: LogId(r.fixed()?),
            size: r.u64()?,
            root: r.fixed()?,
            time: r.u64()?,
        };
        r.finish()?;
        if head.size == 0 {
            return Err(Error::Malformed("log head size"));
        }
        Ok(head)
    }

    /// Whether this head extends `older`: the same log, no smaller, no
    /// earlier, and consistent by `proof`.
    ///
    /// # Errors
    ///
    /// None in practice; the signature matches the tree functions.
    pub fn extends(&self, older: &Self, proof: &[Hash]) -> Result<bool> {
        if self.log != older.log || self.size < older.size || self.time < older.time {
            return Ok(false);
        }
        merkle::verify_consistency(older.size, &older.root, self.size, &self.root, proof)
    }

    /// Whether `leaf` is at `index` in this head's tree, by `path`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn includes(&self, leaf: &Leaf, index: u64, path: &[Hash]) -> Result<bool> {
        merkle::verify(&leaf.hash()?, index, self.size, path, &self.root)
    }
}

/// A witness's signature on a head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosignature {
    /// The witness key's thumbprint.
    pub witness: Thumbprint,
    /// When the witness cosigned (Unix seconds).
    pub time: u64,
    /// The signature over `IPLC ‖ 1 ‖ time ‖ head`.
    pub signature: Vec<u8>,
}

impl Cosignature {
    fn statement(time: u64, head: &Head) -> Vec<u8> {
        Writer::new(COSIGNATURE_MAGIC)
            .u64(time)
            .bytes(&head.to_bytes())
            .finish()
    }
}

/// A head with its server's signature and its witnesses' cosignatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHead {
    /// The head.
    pub head: Head,
    /// The server's signature over the head's bytes.
    pub signature: Vec<u8>,
    /// Witness cosignatures, at most one per witness.
    pub cosignatures: Vec<Cosignature>,
}

impl SignedHead {
    /// Sign `head` with the log's key.
    ///
    /// # Errors
    ///
    /// An OpenSSL error, or the system policy refusing the key.
    pub fn issue(key: &SigningKey, head: Head) -> Result<Self> {
        Ok(Self {
            signature: key.sign_with_context(&head.to_bytes(), HEAD_CONTEXT)?,
            head,
            cosignatures: Vec::new(),
        })
    }

    /// Check the server's signature with the log's key.
    ///
    /// # Errors
    ///
    /// [`Error::UntrustedAnchor`] for a bad signature or an algorithm
    /// `policy` refuses.
    pub fn verify(&self, key: &VerifyingKey, policy: &Policy) -> Result<()> {
        if !policy.allows_signature(key.alg()) {
            return Err(Error::UntrustedAnchor);
        }
        key.verify_with_context(&self.head.to_bytes(), HEAD_CONTEXT, &self.signature)
            .map_err(|_| Error::UntrustedAnchor)
    }

    /// Add `witness`'s cosignature at `time`, replacing an earlier one by
    /// the same witness.  Use [`witness`] to cosign only consistent heads.
    ///
    /// # Errors
    ///
    /// An OpenSSL error, the system policy refusing the key, or
    /// [`Error::Malformed`] past [`MAX_COSIGNATURES`].
    pub fn cosign(&mut self, witness: &SigningKey, time: u64) -> Result<()> {
        let signature = witness.sign_with_context(
            &Cosignature::statement(time, &self.head),
            COSIGNATURE_CONTEXT,
        )?;
        let thumbprint = *witness.public().thumbprint();
        self.cosignatures.retain(|c| c.witness != thumbprint);
        if self.cosignatures.len() >= MAX_COSIGNATURES {
            return Err(Error::Malformed("too many cosignatures"));
        }
        self.cosignatures.push(Cosignature {
            witness: thumbprint,
            time,
            signature,
        });
        Ok(())
    }

    /// The `trusted` witnesses whose cosignatures verify under `policy`;
    /// others, and cosignatures from untrusted keys, are ignored.
    #[must_use]
    pub fn witnesses(&self, trusted: &[VerifyingKey], policy: &Policy) -> BTreeSet<Thumbprint> {
        self.cosignatures
            .iter()
            .filter_map(|c| {
                let key = trusted.iter().find(|k| *k.thumbprint() == c.witness)?;
                let statement = Cosignature::statement(c.time, &self.head);
                (policy.allows_signature(key.alg())
                    && key
                        .verify_with_context(&statement, COSIGNATURE_CONTEXT, &c.signature)
                        .is_ok())
                .then_some(c.witness)
            })
            .collect()
    }

    /// `IPLS ‖ 1 ‖ head ‖ signature ‖ n(1) ‖ [witness(32) ‖ time ‖ signature]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(SIGNED_HEAD_MAGIC);
        w.bytes(&self.head.to_bytes()).bytes(&self.signature);
        // At most MAX_COSIGNATURES, enforced by cosign() and from_bytes().
        w.u8(u8::try_from(self.cosignatures.len()).unwrap_or(u8::MAX));
        for c in &self.cosignatures {
            w.fixed(c.witness.as_bytes())
                .u64(c.time)
                .bytes(&c.signature);
        }
        w.finish()
    }

    /// Parse a signed head, **unverified**.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, SIGNED_HEAD_MAGIC, "signed log head")?;
        let head = Head::from_bytes(r.bytes()?)?;
        let signature = r.bytes()?.to_vec();
        let n = usize::from(r.u8()?);
        if n > MAX_COSIGNATURES {
            return Err(Error::Malformed("too many cosignatures"));
        }
        let mut cosignatures: Vec<Cosignature> = Vec::with_capacity(n);
        for _ in 0..n {
            let witness = Thumbprint::from_bytes(r.fixed()?);
            if cosignatures.iter().any(|c| c.witness == witness) {
                return Err(Error::Malformed("duplicate cosignature"));
            }
            cosignatures.push(Cosignature {
                witness,
                time: r.u64()?,
                signature: r.bytes()?.to_vec(),
            });
        }
        r.finish()?;
        Ok(Self {
            head,
            signature,
            cosignatures,
        })
    }
}

/// A witness's step: cosign `head` at `time` if the log's key signed it
/// and it extends `previous`, the last head this witness cosigned for
/// the log (none the first time), by the consistency `proof`.
///
/// # Errors
///
/// [`Error::UntrustedAnchor`] for a bad log signature,
/// [`Error::Mismatch`] for a head that does not extend `previous`, or an
/// error from [`SignedHead::cosign`].
pub fn witness(
    key: &SigningKey,
    log_key: &VerifyingKey,
    policy: &Policy,
    previous: Option<&Head>,
    head: &mut SignedHead,
    proof: &[Hash],
    time: u64,
) -> Result<()> {
    head.verify(log_key, policy)?;
    if let Some(previous) = previous
        && !head.head.extends(previous, proof)?
    {
        return Err(Error::Mismatch("log head"));
    }
    head.cosign(key, time)
}

#[cfg(test)]
mod tests {
    use tang_pqc::SignatureAlg;

    use super::*;

    const T: u64 = 1_800_000_000;

    fn id() -> LogId {
        LogId::of("EXAMPLE.TEST", "ipa1.example.test").unwrap()
    }

    fn leaf(kind: Kind, n: u8) -> Leaf {
        Leaf {
            kind,
            time: T + u64::from(n),
            index: [n; 32],
            body: vec![n; 3],
        }
    }

    fn log_of(n: u8) -> (Log, Vec<Leaf>) {
        let leaves: Vec<Leaf> = (0..n).map(|i| leaf(Kind::VAULT_DEVICE, i)).collect();
        (Log::replay(id(), &leaves).unwrap(), leaves)
    }

    #[test]
    fn leaves_round_trip_and_keep_unknown_kinds() {
        for kind in [Kind::CLAIM, Kind::STATEMENT, Kind(0x1234)] {
            let l = leaf(kind, 7);
            assert_eq!(Leaf::from_bytes(&l.to_bytes()).unwrap(), l);
        }
        let mut big = leaf(Kind::CLAIM, 1);
        big.body = vec![0; MAX_BODY + 1];
        assert!(Leaf::from_bytes(&big.to_bytes()).is_err());
        let mut trailing = leaf(Kind::CLAIM, 1).to_bytes();
        trailing.push(0);
        assert!(Leaf::from_bytes(&trailing).is_err());
    }

    #[test]
    fn the_kind_is_hashed() {
        // Same body, time and index under two kinds: two different leaves.
        let a = leaf(Kind::VAULT_DEVICE, 1);
        let b = Leaf {
            kind: Kind::VAULT_POLICY,
            ..a.clone()
        };
        assert_ne!(a.hash().unwrap(), b.hash().unwrap());
    }

    #[test]
    fn indexes_are_keyed_and_log_ids_separate_servers() {
        let a = index(&[1; 32], b"vault-1").unwrap();
        assert_eq!(a, index(&[1; 32], b"vault-1").unwrap());
        assert_ne!(a, index(&[2; 32], b"vault-1").unwrap());
        assert_ne!(a, index(&[1; 32], b"vault-2").unwrap());
        assert_ne!(
            id(),
            LogId::of("EXAMPLE.TEST", "ipa2.example.test").unwrap()
        );
        // The realm is length-prefixed: no shifting bytes between fields.
        assert_ne!(LogId::of("A", "BC").unwrap(), LogId::of("AB", "C").unwrap());
    }

    #[test]
    fn tombstones_append_instead_of_restarting() {
        let (mut log, _) = log_of(3);
        let before = log.head(T).unwrap();
        let i = log.append(&Leaf::tombstone(T + 9, 1, "renewed")).unwrap();
        assert_eq!(i, 3);
        assert!(log.is_retired(1) && !log.is_retired(0));
        // The new head extends the old one.
        let after = log.head(T + 9).unwrap();
        assert!(
            after
                .extends(&before, &log.consistency(3).unwrap())
                .unwrap()
        );

        // Not twice, not a tombstone, not beyond the log.
        for target in [1, 3, 9] {
            assert!(log.append(&Leaf::tombstone(T, target, "x")).is_err());
        }
        assert_eq!(log.size(), 4);
        let garbled = Leaf {
            body: vec![1, 2, 3],
            ..Leaf::tombstone(T, 0, "x")
        };
        assert!(log.append(&garbled).is_err());

        // Replay reaches the same log, and the same refusals.
        let leaves = [
            leaf(Kind::CLAIM, 0),
            leaf(Kind::CLAIM, 1),
            Leaf::tombstone(T, 0, "dropped"),
        ];
        let replayed = Log::replay(id(), &leaves).unwrap();
        assert!(replayed.is_retired(0));
        let doubled = [leaves[0].clone(), leaves[2].clone(), leaves[2].clone()];
        assert!(Log::replay(id(), &doubled).is_err());
    }

    #[test]
    fn heads_prove_inclusion_and_consistency() {
        let (log, leaves) = log_of(9);
        let head = log.head(T).unwrap();
        assert_eq!(Head::from_bytes(&head.to_bytes()).unwrap(), head);
        for (i, l) in leaves.iter().enumerate() {
            let p = log.inclusion(i as u64).unwrap();
            assert!(head.includes(l, i as u64, &p).unwrap());
            assert!(!head.includes(&leaves[(i + 1) % 9], i as u64, &p).unwrap());
        }
        let (small, _) = log_of(4);
        let old = small.head(T - 1).unwrap();
        let proof = log.consistency(4).unwrap();
        assert!(head.extends(&old, &proof).unwrap());
        // Another log, an earlier time, a fork: refused.
        let other = Head {
            log: LogId([9; 32]),
            ..old
        };
        assert!(!head.extends(&other, &proof).unwrap());
        let later = Head { time: T + 1, ..old };
        assert!(!head.extends(&later, &proof).unwrap());
        let forked = Log::replay(id(), &[leaf(Kind::CLAIM, 0), leaf(Kind::CLAIM, 1)])
            .unwrap()
            .head(T - 1)
            .unwrap();
        assert!(!head.extends(&forked, &log.consistency(2).unwrap()).unwrap());
        assert!(Log::new(id()).head(T).is_err());
    }

    #[test]
    fn signed_heads_and_witnesses() {
        let server = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let w44 = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
        let w87 = SigningKey::generate(SignatureAlg::MlDsa87).unwrap();
        let policy = Policy::default();

        let (small, _) = log_of(4);
        let mut first = SignedHead::issue(&server, small.head(T).unwrap()).unwrap();
        witness(&w44, server.public(), &policy, None, &mut first, &[], T).unwrap();

        let (log, _) = log_of(6);
        let mut next = SignedHead::issue(&server, log.head(T + 5).unwrap()).unwrap();
        let proof = log.consistency(4).unwrap();
        for w in [&w44, &w87] {
            witness(
                w,
                server.public(),
                &policy,
                Some(&first.head),
                &mut next,
                &proof,
                T + 6,
            )
            .unwrap();
        }
        let parsed = SignedHead::from_bytes(&next.to_bytes()).unwrap();
        assert_eq!(parsed, next);
        parsed.verify(server.public(), &policy).unwrap();
        let trusted = [w44.public().clone(), w87.public().clone()];
        assert_eq!(parsed.witnesses(&trusted, &policy).len(), 2);

        // CNSA 2.0 drops the ML-DSA-44 witness and the ML-DSA-65 log key.
        let cnsa = Policy::cnsa2();
        let only87 = parsed.witnesses(&trusted, &cnsa);
        assert_eq!(only87, BTreeSet::from([*w87.public().thumbprint()]));
        assert!(parsed.verify(server.public(), &cnsa).is_err());

        // A witness refuses a fork, and a bad log signature.
        let other: Vec<Leaf> = (0..6).map(|i| leaf(Kind::CLAIM, i)).collect();
        let forked = Log::replay(id(), &other).unwrap();
        let mut fork = SignedHead::issue(&server, forked.head(T + 5).unwrap()).unwrap();
        assert!(matches!(
            witness(
                &w44,
                server.public(),
                &policy,
                Some(&first.head),
                &mut fork,
                &forked.consistency(4).unwrap(),
                T + 6
            ),
            Err(Error::Mismatch(_))
        ));
        let mut resized = next.clone();
        resized.head.size += 1;
        assert!(resized.verify(server.public(), &policy).is_err());
        assert!(matches!(
            witness(&w44, server.public(), &policy, None, &mut resized, &[], T),
            Err(Error::UntrustedAnchor)
        ));

        // A cosignature moved onto another head, or by an untrusted key,
        // does not count; re-cosigning replaces, duplicates do not parse.
        let mut moved = next.clone();
        moved.head.time += 1;
        assert!(moved.witnesses(&trusted, &policy).is_empty());
        assert_eq!(next.witnesses(&trusted[..1], &policy).len(), 1);
        next.cosign(&w44, T + 7).unwrap();
        assert_eq!(next.cosignatures.len(), 2);
        let mut dup = next.clone();
        dup.cosignatures.push(next.cosignatures[0].clone());
        assert!(SignedHead::from_bytes(&dup.to_bytes()).is_err());
    }
}
