//! Kerberos-bound signing statements (`docs/DESIGN-sign.md`).
//!
//! A principal authenticated by Kerberos asks a server to state that it
//! signed some digests for a purpose.  The server checks the realm's
//! signing policy (which principals, groups, hosts and services may
//! sign for which purposes), records the statement in its transparency
//! log (`DESIGN-tlog.md`), and signs it with its delegation-vouched
//! ML-DSA key.  Nothing is held by the client: no key to keep, no
//! certificate window.  A batch of digests is one statement over the
//! Merkle root of their leaves, and each digest's [`Bundle`] carries its
//! path.
//!
//! A bundle verifies offline against the realm's pinned anchors, with
//! the delegation checked **as of the statement's time**, as offline
//! enrollment bundles are (§8.4): a statement stays verifiable after
//! the server's key rotates, and the log entry it names shows it was
//! made while the delegation held.
//!
//! The log leaf names no principal: its index stands for the signer,
//! whose lookups list everything signed in their name.

use serde::{Deserialize, Serialize};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{Policy as CryptoPolicy, SigningKey, Thumbprint, VerifyingKey};

use crate::delegation::{Delegation, VerifiedDelegation};
use crate::error::{Error, Result};
use crate::keytab::Principal;
use crate::merkle::{self, Hash, TreeHash};
use crate::tlog::LogId;

const REQUEST_MAGIC: [u8; 4] = *b"IPGQ";
const STATEMENT_MAGIC: [u8; 4] = *b"IPGS";
const ANSWER_MAGIC: [u8; 4] = *b"IPGR";
const BUNDLE_MAGIC: [u8; 4] = *b"IPGB";
const LEAF_MAGIC: [u8; 4] = *b"IPGL";
const STATEMENT_CONTEXT: &[u8] = b"ipa-ku-sign/v1 statement";

/// Most digests one statement covers.
pub const MAX_DIGESTS: usize = 256;

/// Longest purpose name.
pub const MAX_PURPOSE: usize = 64;

/// A digest algorithm a statement may cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestAlg {
    const fn id(self) -> u8 {
        match self {
            Self::Sha256 => 1,
            Self::Sha384 => 2,
            Self::Sha512 => 3,
        }
    }

    fn from_id(id: u8) -> Result<Self> {
        Ok(match id {
            1 => Self::Sha256,
            2 => Self::Sha384,
            3 => Self::Sha512,
            _ => return Err(Error::Malformed("digest algorithm")),
        })
    }

    /// The digest a client should use where `policy` holds: SHA-256 while
    /// it allows a category 2 or 3 signer, SHA-384 when it allows only
    /// ML-DSA-87 (CNSA 2.0, which approves no SHA-256).
    #[must_use]
    pub fn for_policy(policy: &tang_pqc::Policy) -> Self {
        use tang_pqc::SignatureAlg as S;
        if policy.allows_signature(S::MlDsa44) || policy.allows_signature(S::MlDsa65) {
            Self::Sha256
        } else {
            Self::Sha384
        }
    }

    /// Whether a statement whose batch is hashed with `tree` may cover a
    /// digest of this algorithm: never one shorter than the tree hash, so
    /// a SHA-384 (CNSA) signer covers SHA-384 and SHA-512 digests only.
    #[must_use]
    pub const fn fits(self, tree: TreeHash) -> bool {
        self.output_len() >= tree.output_len()
    }

    /// The digest length.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The OpenSSL name.
    #[must_use]
    pub const fn openssl_name(self) -> &'static std::ffi::CStr {
        match self {
            Self::Sha256 => c"SHA2-256",
            Self::Sha384 => c"SHA2-384",
            Self::Sha512 => c"SHA2-512",
        }
    }
}

/// A digest of something signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest {
    /// Its algorithm.
    pub alg: DigestAlg,
    /// The value.
    pub value: Vec<u8>,
}

impl Digest {
    /// The digest of `data` under `alg`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn of(alg: DigestAlg, data: &[u8]) -> Result<Self> {
        Ok(Self {
            alg,
            value: tang_pqc::primitives::digest(alg.openssl_name(), &[data])?,
        })
    }

    /// Its leaf in a statement's batch tree of `tree`, the signing
    /// server's hash: `H(0x00 ‖ IPGL ‖ 1 ‖ alg ‖ value)`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn leaf(&self, tree: TreeHash) -> Result<Hash> {
        merkle::leaf_hash(
            tree,
            &Writer::new(LEAF_MAGIC)
                .u8(self.alg.id())
                .bytes(&self.value)
                .finish(),
        )
    }

    fn write(&self, w: &mut Writer) {
        w.u8(self.alg.id()).bytes(&self.value);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let alg = DigestAlg::from_id(r.u8()?)?;
        let value = r.bytes()?;
        if value.len() != alg.output_len() {
            return Err(Error::Malformed("digest length"));
        }
        Ok(Self {
            alg,
            value: value.to_vec(),
        })
    }
}

fn check_purpose(purpose: &str) -> Result<()> {
    if purpose.is_empty()
        || purpose.len() > MAX_PURPOSE
        || !purpose
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::Malformed("signing purpose"));
    }
    Ok(())
}

/// What a principal asks to have stated: digests, for a purpose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The purpose (`blob`, `git-commit`, …): lowercase letters, digits
    /// and `-`.
    pub purpose: String,
    /// The digests, at most [`MAX_DIGESTS`].
    pub digests: Vec<Digest>,
}

impl Request {
    /// `IPGQ ‖ 1 ‖ purpose ‖ n(u64) ‖ [alg(1) ‖ value]`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a bad purpose or batch size.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        check_purpose(&self.purpose)?;
        if self.digests.is_empty() || self.digests.len() > MAX_DIGESTS {
            return Err(Error::Malformed("signing batch size"));
        }
        let mut w = Writer::new(REQUEST_MAGIC);
        w.str(&self.purpose).u64(self.digests.len() as u64);
        for d in &self.digests {
            d.write(&mut w);
        }
        Ok(w.finish())
    }

    /// Parse a request.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, REQUEST_MAGIC, "signing request")?;
        let purpose = r.str()?.to_owned();
        check_purpose(&purpose)?;
        let n = usize::try_from(r.u64()?)
            .ok()
            .filter(|n| (1..=MAX_DIGESTS).contains(n))
            .ok_or(Error::Malformed("signing batch size"))?;
        let digests = (0..n)
            .map(|_| Digest::read(&mut r))
            .collect::<Result<_>>()?;
        r.finish()?;
        Ok(Self { purpose, digests })
    }

    /// The batch tree's leaves under `tree`, in order.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn leaves(&self, tree: TreeHash) -> Result<Vec<Hash>> {
        self.digests.iter().map(|d| d.leaf(tree)).collect()
    }
}

/// What the server states, signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// The realm.
    pub realm: String,
    /// The principal that asked, authenticated by its ticket.
    pub principal: String,
    /// The purpose.
    pub purpose: String,
    /// How many digests the batch holds.
    pub batch_size: u64,
    /// The batch tree's root.
    pub batch_root: Hash,
    /// When (Unix seconds).
    pub iat: u64,
    /// The log the statement is recorded in.
    pub log: LogId,
    /// Its leaf index there.
    pub index: u64,
}

impl Statement {
    fn write(&self, w: &mut Writer) {
        w.str(&self.realm)
            .str(&self.principal)
            .str(&self.purpose)
            .u64(self.batch_size)
            .bytes(&self.batch_root)
            .u64(self.iat)
            .bytes(&self.log.0)
            .u64(self.index);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            realm: r.str()?.to_owned(),
            principal: r.str()?.to_owned(),
            purpose: r.str()?.to_owned(),
            batch_size: r.u64()?,
            batch_root: Hash::from_slice(r.bytes()?)?,
            iat: r.u64()?,
            log: LogId(Hash::from_slice(r.bytes()?)?),
            index: r.u64()?,
        })
    }

    /// The body of its log leaf: what was stated, without who — the leaf's
    /// index stands for the principal.  `IPGS ‖ 1 ‖ purpose ‖ batch_size ‖
    /// batch_root(32) ‖ iat`.
    #[must_use]
    pub fn log_body(purpose: &str, batch_size: u64, batch_root: &Hash, iat: u64) -> Vec<u8> {
        Writer::new(STATEMENT_MAGIC)
            .str(purpose)
            .u64(batch_size)
            .fixed(batch_root)
            .u64(iat)
            .finish()
    }
}

/// A statement with the server's delegation, key and signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedStatement {
    statement: Statement,
    delegation: Vec<u8>,
    signer_key: Vec<u8>,
    signature: Vec<u8>,
}

impl SignedStatement {
    fn signed_part(statement: &Statement, delegation: &[u8], signer_key: &[u8]) -> Vec<u8> {
        let mut w = Writer::new(STATEMENT_MAGIC);
        statement.write(&mut w);
        w.bytes(delegation).bytes(signer_key);
        w.finish()
    }

    /// Sign `statement` with the server's `signing` key under `delegation`.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn sign(
        signing: &SigningKey,
        delegation: &Delegation,
        statement: Statement,
    ) -> Result<Self> {
        let delegation = delegation.to_json().into_bytes();
        let signer_key = signing.public().to_jwk_json().into_bytes();
        let signature = signing.sign_with_context(
            &Self::signed_part(&statement, &delegation, &signer_key),
            STATEMENT_CONTEXT,
        )?;
        Ok(Self {
            statement,
            delegation,
            signer_key,
            signature,
        })
    }

    /// The statement, **unverified**.
    #[must_use]
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// Verify against `anchors` for `realm`: the delegation as of the
    /// statement's own time, its key the signer's, the signature.
    ///
    /// # Errors
    ///
    /// [`Error::UntrustedAnchor`], [`Error::Expired`],
    /// [`Error::WrongRealm`], [`Error::Mismatch`] or a crypto error.
    pub fn verify(
        &self,
        realm: &str,
        anchors: &[Thumbprint],
        policy: &CryptoPolicy,
    ) -> Result<VerifiedDelegation> {
        let s = &self.statement;
        let delegation =
            Delegation::from_json(&self.delegation)?.verify_at(anchors, policy, s.iat)?;
        if delegation.realm != realm || s.realm != realm {
            return Err(Error::WrongRealm);
        }
        let key = VerifyingKey::from_jwk_json(&self.signer_key)?;
        if key.thumbprint() != &delegation.key {
            return Err(Error::Mismatch("statement signer"));
        }
        if !policy.allows_signature(key.alg()) {
            return Err(Error::UntrustedAnchor);
        }
        // The batch and the log are hashed as the signer's key decides.
        let tree = TreeHash::for_signer(key.alg());
        if s.batch_root.alg() != tree || s.log.alg() != tree {
            return Err(Error::Mismatch("statement hash"));
        }
        key.verify_with_context(
            &Self::signed_part(s, &self.delegation, &self.signer_key),
            STATEMENT_CONTEXT,
            &self.signature,
        )?;
        let principal: Principal = s.principal.parse()?;
        if principal.realm() != realm {
            return Err(Error::WrongRealm);
        }
        Ok(delegation)
    }

    fn write(&self, w: &mut Writer) {
        let mut inner = Writer::new(STATEMENT_MAGIC);
        self.statement.write(&mut inner);
        w.bytes(&inner.finish())
            .bytes(&self.delegation)
            .bytes(&self.signer_key)
            .bytes(&self.signature);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let statement = {
            let bytes = r.bytes()?;
            let mut inner = Reader::new(bytes, STATEMENT_MAGIC, "signing statement")?;
            let s = Statement::read(&mut inner)?;
            inner.finish()?;
            s
        };
        Ok(Self {
            statement,
            delegation: r.bytes()?.to_vec(),
            signer_key: r.bytes()?.to_vec(),
            signature: r.bytes()?.to_vec(),
        })
    }
}

/// What a signing request answers: the signed statement, and each
/// digest's path in the batch tree, in request order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The statement.
    pub statement: SignedStatement,
    /// The paths.
    pub paths: Vec<Vec<Hash>>,
}

impl Answer {
    /// Answer `request` with `statement`, over `request`'s leaves.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn new(request: &Request, statement: SignedStatement) -> Result<Self> {
        let leaves = request.leaves(statement.statement.batch_root.alg())?;
        let paths = (0..leaves.len())
            .map(|i| merkle::path(&leaves, i))
            .collect::<Result<_>>()?;
        Ok(Self { statement, paths })
    }

    /// `IPGR ‖ 1 ‖ statement ‖ n(u64) ‖ [m(1) ‖ hash·m]`, each hash length
    /// prefixed.
    ///
    /// # Panics
    ///
    /// Never for paths of fewer than 256 hashes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(ANSWER_MAGIC);
        self.statement.write(&mut w);
        w.u64(self.paths.len() as u64);
        for p in &self.paths {
            w.u8(u8::try_from(p.len()).expect("short paths"));
            for h in p {
                w.bytes(h);
            }
        }
        w.finish()
    }

    /// Parse an answer, **unverified**.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, ANSWER_MAGIC, "signing answer")?;
        let statement = SignedStatement::read(&mut r)?;
        let n = usize::try_from(r.u64()?)
            .ok()
            .filter(|n| *n <= MAX_DIGESTS)
            .ok_or(Error::Malformed("signing answer"))?;
        let paths = (0..n)
            .map(|_| -> Result<Vec<Hash>> {
                (0..r.u8()?)
                    .map(|_| Hash::from_slice(r.bytes()?))
                    .collect::<Result<_>>()
            })
            .collect::<Result<_>>()?;
        r.finish()?;
        Ok(Self { statement, paths })
    }

    /// The bundle for the `i`th digest of `request`, checked against the
    /// statement's batch.
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] when the answer does not cover the request.
    pub fn bundle(&self, request: &Request, i: usize) -> Result<Bundle> {
        let digest = request
            .digests
            .get(i)
            .ok_or(Error::Mismatch("signing answer"))?
            .clone();
        let bundle = Bundle {
            statement: self.statement.clone(),
            digest,
            index: i as u64,
            path: self
                .paths
                .get(i)
                .ok_or(Error::Mismatch("signing answer"))?
                .clone(),
        };
        if !bundle.in_batch()? || self.statement.statement.purpose != request.purpose {
            return Err(Error::Mismatch("signing answer"));
        }
        Ok(bundle)
    }
}

/// One signed digest: what travels with the thing signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    statement: SignedStatement,
    digest: Digest,
    index: u64,
    path: Vec<Hash>,
}

/// What a verified bundle states.
#[derive(Clone, Debug)]
pub struct Verified {
    /// Who signed: the principal the server authenticated.
    pub principal: Principal,
    /// For what.
    pub purpose: String,
    /// When (Unix seconds).
    pub iat: u64,
    /// The server that stated it.
    pub server: String,
    /// Where the statement is logged.
    pub log: LogId,
    /// Its index there.
    pub index: u64,
}

impl Bundle {
    fn in_batch(&self) -> Result<bool> {
        let s = &self.statement.statement;
        merkle::verify(
            &self.digest.leaf(s.batch_root.alg())?,
            self.index,
            s.batch_size,
            &self.path,
            &s.batch_root,
        )
    }

    /// The signed digest.
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Verify that `data` is what the bundle signs, for `realm` against
    /// `anchors`: the digest is `data`'s, it is in the statement's batch,
    /// and the statement verifies.
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] for other data or a digest outside the batch,
    /// or an error from [`SignedStatement::verify`].
    pub fn verify(
        &self,
        data: &[u8],
        realm: &str,
        anchors: &[Thumbprint],
        policy: &CryptoPolicy,
    ) -> Result<Verified> {
        if Digest::of(self.digest.alg, data)? != self.digest {
            return Err(Error::Mismatch("signed data"));
        }
        if !self.in_batch()? {
            return Err(Error::Mismatch("signing batch"));
        }
        let delegation = self.statement.verify(realm, anchors, policy)?;
        // The statement verified, so the batch is hashed as its key
        // decides; the digest may not be weaker.
        if !self
            .digest
            .alg
            .fits(self.statement.statement.batch_root.alg())
        {
            return Err(Error::Policy(format!(
                "a {:?} digest is weaker than the signer's hash",
                self.digest.alg
            )));
        }
        let s = &self.statement.statement;
        Ok(Verified {
            principal: s.principal.parse()?,
            purpose: s.purpose.clone(),
            iat: s.iat,
            server: delegation.server,
            log: s.log,
            index: s.index,
        })
    }

    /// `IPGB ‖ 1 ‖ statement ‖ digest ‖ index ‖ m(1) ‖ [hash]`, each hash
    /// length prefixed.
    ///
    /// # Panics
    ///
    /// Never for paths of fewer than 256 hashes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(BUNDLE_MAGIC);
        self.statement.write(&mut w);
        self.digest.write(&mut w);
        w.u64(self.index)
            .u8(u8::try_from(self.path.len()).expect("short paths"));
        for h in &self.path {
            w.bytes(h);
        }
        w.finish()
    }

    /// Parse a bundle, **unverified**.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, BUNDLE_MAGIC, "signature bundle")?;
        let statement = SignedStatement::read(&mut r)?;
        let digest = Digest::read(&mut r)?;
        let index = r.u64()?;
        let path = (0..r.u8()?)
            .map(|_| Hash::from_slice(r.bytes()?))
            .collect::<Result<_>>()?;
        r.finish()?;
        Ok(Self {
            statement,
            digest,
            index,
            path,
        })
    }
}

/// Who may sign for one purpose.  A principal qualifies by its name, or
/// by a group (user groups and host groups alike: the directory's
/// `memberOf`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signers {
    /// User principals (`alice` or `alice@REALM`).
    #[serde(default)]
    pub users: Vec<String>,
    /// Groups whose members may sign (user groups or host groups).
    #[serde(default)]
    pub groups: Vec<String>,
    /// Host FQDNs.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Service principals (`HTTP/ci.example.test`).
    #[serde(default)]
    pub services: Vec<String>,
}

/// The realm's signing policy: who may sign for which purpose.  No
/// purpose, no signing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignPolicy {
    /// Purposes by name.
    #[serde(default)]
    pub purposes: std::collections::BTreeMap<String, Signers>,
}

impl SignPolicy {
    /// Whether `principal`, a member of `groups`, may sign for `purpose`.
    ///
    /// # Errors
    ///
    /// [`Error::Policy`] naming why not.
    pub fn check(&self, principal: &Principal, groups: &[String], purpose: &str) -> Result<()> {
        let signers = self
            .purposes
            .get(purpose)
            .ok_or_else(|| Error::Policy(format!("no signing purpose {purpose:?}")))?;
        let name = principal.to_string();
        let allowed = match principal.components() {
            [user] => signers.users.iter().any(|u| u == user || *u == name),
            [service, host] if service == "host" => {
                signers.hosts.iter().any(|h| h.eq_ignore_ascii_case(host))
            }
            [_, _] => {
                let service = principal.components().join("/");
                signers.services.iter().any(|s| *s == service || *s == name)
            }
            _ => false,
        } || groups.iter().any(|g| signers.groups.contains(g));
        if allowed {
            Ok(())
        } else {
            Err(Error::Policy(format!(
                "{name} may not sign for {purpose:?}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use tang_pqc::{Policy, SignatureAlg};

    use super::*;

    const REALM: &str = "EXAMPLE.TEST";
    const NOW: u64 = 1_800_000_000;

    fn setup() -> (SigningKey, SigningKey, Delegation) {
        setup_with(SignatureAlg::MlDsa65)
    }

    fn setup_with(alg: SignatureAlg) -> (SigningKey, SigningKey, Delegation) {
        let anchor = SigningKey::generate(alg).unwrap();
        let server = SigningKey::generate(alg).unwrap();
        let delegation = Delegation::issue(
            &anchor,
            REALM,
            "ipa1.example.test",
            server.public(),
            NOW - 60,
            NOW + 86_400,
        )
        .unwrap();
        (anchor, server, delegation)
    }

    fn request(n: u8) -> Request {
        Request {
            purpose: "blob".into(),
            digests: (0..n)
                .map(|i| Digest::of(DigestAlg::Sha256, &[i]).unwrap())
                .collect(),
        }
    }

    fn statement(r: &Request) -> Statement {
        statement_in(r, TreeHash::Sha256)
    }

    fn statement_in(r: &Request, tree: TreeHash) -> Statement {
        let leaves = r.leaves(tree).unwrap();
        Statement {
            realm: REALM.into(),
            principal: "alice@EXAMPLE.TEST".into(),
            purpose: r.purpose.clone(),
            batch_size: leaves.len() as u64,
            batch_root: merkle::root(&leaves).unwrap(),
            iat: NOW,
            log: LogId::of(REALM, "ipa1.example.test", tree).unwrap(),
            index: 7,
        }
    }

    #[test]
    fn a_batch_signs_each_digest_and_only_it() {
        let (anchor, server, delegation) = setup();
        let anchors = [*anchor.public().thumbprint()];
        let req = Request::from_bytes(&request(5).to_bytes().unwrap()).unwrap();
        let signed = SignedStatement::sign(&server, &delegation, statement(&req)).unwrap();
        let answer = Answer::from_bytes(&Answer::new(&req, signed).unwrap().to_bytes()).unwrap();
        for i in 0..5u8 {
            let bundle =
                Bundle::from_bytes(&answer.bundle(&req, usize::from(i)).unwrap().to_bytes())
                    .unwrap();
            let v = bundle
                .verify(&[i], REALM, &anchors, &Policy::default())
                .unwrap();
            assert_eq!(v.principal.to_string(), "alice@EXAMPLE.TEST");
            assert_eq!((v.purpose.as_str(), v.iat, v.index), ("blob", NOW, 7));
            assert_eq!(v.server, "ipa1.example.test");
            // Other data, another realm, unrelated anchors: refused.
            assert!(
                bundle
                    .verify(&[i, 0], REALM, &anchors, &Policy::default())
                    .is_err()
            );
            assert!(
                bundle
                    .verify(&[i], "OTHER.TEST", &anchors, &Policy::default())
                    .is_err()
            );
            let stranger = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
            assert!(
                bundle
                    .verify(
                        &[i],
                        REALM,
                        &[*stranger.public().thumbprint()],
                        &Policy::default()
                    )
                    .is_err()
            );
        }
        // A bundle moved to another index, or a tampered statement, fails.
        let mut moved = answer.bundle(&req, 1).unwrap();
        moved.index = 2;
        assert!(
            moved
                .verify(&[1], REALM, &anchors, &Policy::default())
                .is_err()
        );
        let mut forged = answer.bundle(&req, 0).unwrap();
        forged.statement.statement.principal = "bob@EXAMPLE.TEST".into();
        assert!(
            forged
                .verify(&[0], REALM, &anchors, &Policy::default())
                .is_err()
        );
        // An answer for another request does not make bundles for it:
        // other data, or the same data for another purpose.
        let other = Request {
            purpose: "blob".into(),
            digests: vec![Digest::of(DigestAlg::Sha256, b"other").unwrap()],
        };
        assert!(answer.bundle(&other, 0).is_err());
        let repurposed = Request {
            purpose: "git-commit".into(),
            ..req.clone()
        };
        assert!(answer.bundle(&repurposed, 0).is_err());
        assert!(answer.bundle(&req, 5).is_err());
        // CNSA 2.0 refuses the ML-DSA-65 signer.
        let b = answer.bundle(&req, 0).unwrap();
        assert!(b.verify(&[0], REALM, &anchors, &Policy::cnsa2()).is_err());
    }

    #[test]
    fn a_cnsa_statement_hashes_its_batch_with_sha_384() {
        // An ML-DSA-87 server under CNSA 2.0: SHA-384 batch tree and log,
        // SHA-384 digests of the data; a SHA-256 batch from that key is
        // refused even with a valid signature.
        let (anchor, server, delegation) = setup_with(SignatureAlg::MlDsa87);
        let anchors = [*anchor.public().thumbprint()];
        let req = Request {
            purpose: "blob".into(),
            digests: (0..3u8)
                .map(|i| Digest::of(DigestAlg::Sha384, &[i]).unwrap())
                .collect(),
        };
        let s = statement_in(&req, TreeHash::Sha384);
        assert_eq!(s.batch_root.len(), 48);
        let signed = SignedStatement::sign(&server, &delegation, s).unwrap();
        let answer = Answer::from_bytes(&Answer::new(&req, signed).unwrap().to_bytes()).unwrap();
        for i in 0..3u8 {
            let bundle =
                Bundle::from_bytes(&answer.bundle(&req, usize::from(i)).unwrap().to_bytes())
                    .unwrap();
            bundle
                .verify(&[i], REALM, &anchors, &Policy::cnsa2())
                .unwrap();
        }
        let weak = SignedStatement::sign(&server, &delegation, statement(&req)).unwrap();
        assert!(weak.verify(REALM, &anchors, &Policy::cnsa2()).is_err());

        // A SHA-256 digest under that signer is refused, though the
        // statement and the batch verify; the client picks SHA-384.
        let short = request(2);
        let signed =
            SignedStatement::sign(&server, &delegation, statement_in(&short, TreeHash::Sha384))
                .unwrap();
        let bundle = Answer::new(&short, signed)
            .unwrap()
            .bundle(&short, 0)
            .unwrap();
        assert!(
            bundle
                .verify(&[0], REALM, &anchors, &Policy::cnsa2())
                .is_err()
        );
        assert_eq!(DigestAlg::for_policy(&Policy::cnsa2()), DigestAlg::Sha384);
        assert_eq!(DigestAlg::for_policy(&Policy::default()), DigestAlg::Sha256);
        assert!(DigestAlg::Sha512.fits(TreeHash::Sha384));
        assert!(!DigestAlg::Sha256.fits(TreeHash::Sha384));
    }

    #[test]
    fn statements_verify_as_of_their_time() {
        // After the delegation ends, a statement made while it held still
        // verifies: the check is as of the statement's iat.
        let (anchor, server, delegation) = setup();
        let anchors = [*anchor.public().thumbprint()];
        let req = request(1);
        let mut s = statement(&req);
        s.iat = NOW + 100;
        let signed = SignedStatement::sign(&server, &delegation, s.clone()).unwrap();
        signed.verify(REALM, &anchors, &Policy::default()).unwrap();
        s.iat = NOW + 200_000;
        let late = SignedStatement::sign(&server, &delegation, s).unwrap();
        assert!(late.verify(REALM, &anchors, &Policy::default()).is_err());
    }

    #[test]
    fn requests_are_bounded_and_purposes_plain() {
        for purpose in ["", "Blob", "a b", &"x".repeat(MAX_PURPOSE + 1)] {
            let r = Request {
                purpose: purpose.into(),
                ..request(1)
            };
            assert!(r.to_bytes().is_err(), "{purpose:?}");
        }
        assert!(request(0).to_bytes().is_err());
        let too_many = Request {
            purpose: "blob".into(),
            digests: vec![Digest::of(DigestAlg::Sha256, b"x").unwrap(); MAX_DIGESTS + 1],
        };
        assert!(too_many.to_bytes().is_err());
        let mut short = request(1).to_bytes().unwrap();
        short.truncate(short.len() - 1);
        assert!(Request::from_bytes(&short).is_err());
    }

    #[test]
    fn the_policy_names_who_signs_what() {
        let mut policy = SignPolicy::default();
        policy.purposes.insert(
            "blob".into(),
            Signers {
                users: vec!["alice".into()],
                groups: vec!["release".into()],
                hosts: vec!["ci.example.test".into()],
                services: vec!["HTTP/build.example.test".into()],
            },
        );
        let p = |s: &str| s.parse::<Principal>().unwrap();
        policy.check(&p("alice@EXAMPLE.TEST"), &[], "blob").unwrap();
        policy
            .check(&p("bob@EXAMPLE.TEST"), &["release".into()], "blob")
            .unwrap();
        policy
            .check(&p("host/ci.example.test@EXAMPLE.TEST"), &[], "blob")
            .unwrap();
        policy
            .check(&p("HTTP/build.example.test@EXAMPLE.TEST"), &[], "blob")
            .unwrap();
        for (who, groups) in [
            ("bob@EXAMPLE.TEST", vec![]),
            ("host/web1.example.test@EXAMPLE.TEST", vec![]),
            (
                "HTTP/other.example.test@EXAMPLE.TEST",
                vec!["admins".to_owned()],
            ),
            // A service named like a user does not pass as the user.
            ("alice/admin@EXAMPLE.TEST", vec![]),
        ] {
            assert!(policy.check(&p(who), &groups, "blob").is_err(), "{who}");
        }
        assert!(
            policy
                .check(&p("alice@EXAMPLE.TEST"), &[], "git-commit")
                .is_err()
        );
    }
}
