//! A synthetic anchor-state ledger, sized independently of a realm.
//!
//! The trust exchange in [`crate::realm`] produces a ledger as big as the
//! realm.  Anchor costs scale with the *log* — claims per anchor, leaves per
//! vouch — which a deployment grows over years, so benches that measure
//! anchor work build their ledger here: `claims` claims, `anchors` anchor
//! keys, each anchor's vouch covering `leaves` leaves.
//!
//! Servers past the anchor count have `anchor: None`, which the protocol
//! allows: they are admitted on the strength of other anchors' vouches
//! (§4.3), exactly as a deployment's later servers are.

use std::collections::BTreeSet;

use crate::dir::REALM;
use crate::prng::SplitMix64;
use crate::realm::{now, server_name};
use agirru_crdt::GenerationClock;
use kuipa_enroll::anchors::{AnchorState, Entry};
use kuipa_enroll::delegation::{Claim, SignedVouch, VOUCH_VALIDITY};
use kuipa_enroll::merkle::{Hash, TreeHash};
use tang_pqc::{Policy, SignatureAlg, SigningKey, Thumbprint, VerifyingKey};

/// A ledger: anchor keys, the claims they vouch for, the state to compute
/// trust from.
pub struct Ledger {
    /// The anchor keys, first is the ledger's own server's.
    pub anchors: Vec<SigningKey>,
    /// Every claim in the ledger, in leaf order.
    pub claims: Vec<Claim>,
    /// The ledger built and admitted.
    pub state: AnchorState,
    /// The servers in the deployment.
    pub members: BTreeSet<String>,
    /// Deterministic filler leaves, so vouch size is independent of claims.
    pub filler: Vec<Hash>,
    /// The tree hash the ledger's anchors sign under.
    pub alg: TreeHash,
    /// The clock the state was built with.
    pub clock: GenerationClock,
    /// The policy the fixtures check under.
    pub policy: Policy,
}

impl Ledger {
    /// This ledger's own server's claim.
    #[must_use]
    pub fn own(&self) -> &Claim {
        &self.claims[0]
    }

    /// An anchor's verifying key.
    #[must_use]
    pub fn key(&self, i: usize) -> &VerifyingKey {
        self.anchors[i].public()
    }

    /// Every anchor's thumbprint.
    #[must_use]
    pub fn thumbs(&self) -> Vec<Thumbprint> {
        self.anchors
            .iter()
            .map(|a| *a.public().thumbprint())
            .collect()
    }

    /// The leaves the anchors vouch for: every claim, then `filler` so vouch
    /// size can exceed the claim count.
    ///
    /// # Panics
    ///
    /// If a claim's leaf hash fails — fixture setup, not protocol.
    #[must_use]
    pub fn leaves(&self) -> Vec<Hash> {
        self.claims
            .iter()
            .map(|c| c.leaf(self.alg).unwrap_or_else(|e| panic!("leaf: {e}")))
            .chain(self.filler.iter().copied())
            .collect()
    }

    /// A vouch by anchor `i` over [`leaves`](Self::leaves), issued now.
    ///
    /// # Panics
    ///
    /// If signing fails — fixture setup, not protocol.
    #[must_use]
    pub fn vouch(&self, i: usize) -> SignedVouch {
        SignedVouch::issue(
            &self.anchors[i],
            REALM,
            self.leaves(),
            now() - 60,
            now() + VOUCH_VALIDITY,
            None,
        )
        .unwrap_or_else(|e| panic!("vouch: {e}"))
    }
}

/// Build a ledger of `claims` claims and `anchors` anchor keys, each vouch
/// covering `leaves` leaves (`leaves` at least `claims`).
///
/// # Panics
///
/// If keygen, signing, or admission fails — fixture setup, not protocol.
#[must_use]
pub fn ledger(claims: usize, anchors: usize, leaves: usize) -> Ledger {
    let n = claims.max(1);
    let anchors = anchors.max(1).min(n);
    let leaves = leaves.max(n);
    let anchors: Vec<SigningKey> = (0..anchors)
        .map(|_| {
            SigningKey::generate(SignatureAlg::MlDsa65)
                .unwrap_or_else(|e| panic!("anchor keygen: {e}"))
        })
        .collect();
    let mut rng = SplitMix64::new(0xa11ce);
    let claims: Vec<Claim> = (0..n)
        .map(|i| Claim {
            realm: REALM.to_owned(),
            server: server_name(i),
            anchor: anchors.get(i).map(|a| *a.public().thumbprint()),
            key: Thumbprint::from_bytes(rng.bytes(32).try_into().expect("32 bytes")),
            iat: now() - 60,
            exp: now() + 30 * 86400,
        })
        .collect();
    let alg = TreeHash::for_signer(anchors[0].public().alg());
    let filler: Vec<Hash> = (n..leaves)
        .map(|_| Hash::from_slice(&rng.bytes(32)).expect("tree hash"))
        .collect();
    let policy = Policy::default();
    let clock = GenerationClock::new();
    let mut state = AnchorState::default();
    for anchor in &anchors {
        state
            .put(
                Entry::Key(anchor.public().to_jwk_json()),
                REALM,
                &policy,
                now(),
                &clock,
            )
            .expect("admit key");
    }
    for claim in &claims {
        state
            .put(Entry::Claim(claim.clone()), REALM, &policy, now(), &clock)
            .expect("admit claim");
    }
    let leaf_set: Vec<Hash> = claims
        .iter()
        .map(|c| c.leaf(alg).unwrap_or_else(|e| panic!("leaf: {e}")))
        .chain(filler.iter().copied())
        .collect();
    for anchor in &anchors {
        let vouch = SignedVouch::issue(
            anchor,
            REALM,
            leaf_set.iter().copied(),
            now() - 60,
            now() + VOUCH_VALIDITY,
            None,
        )
        .unwrap_or_else(|e| panic!("vouch: {e}"));
        state
            .put(Entry::Vouch(vouch), REALM, &policy, now(), &clock)
            .expect("admit vouch");
    }
    Ledger {
        anchors,
        claims,
        state,
        members: (0..n).map(server_name).collect(),
        filler,
        alg,
        clock,
        policy,
    }
}

#[cfg(test)]
mod tests {
    use kuipa_enroll::anchors::Trust;

    use super::ledger;

    #[test]
    fn every_server_is_trusted() {
        let l = ledger(4, 2, 4);
        let t = Trust::compute(&l.state, l.own(), &[], &l.members, &l.policy, super::now())
            .expect("trust");
        assert_eq!(t.servers().count(), 4);
        assert_eq!(t.anchors().len(), 2);
    }

    #[test]
    fn vouch_size_is_independent_of_claims() {
        let l = ledger(2, 2, 9);
        assert_eq!(l.leaves().len(), 9);
        assert!(l.vouch(0).covers(&l.claims[1]).expect("covers"));
    }
}
