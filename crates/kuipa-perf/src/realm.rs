//! Fixture realms: servers that have run the anchor exchange, sized by a
//! profile, over a real CA and an in-memory directory.
//!
//! This mirrors the end-to-end test's `Realm` — each server has its own
//! anchor, every anchor vouches for every server's claim, and each server
//! publishes its delegation carrying all anchors' proofs — but with
//! `servers`, CA count, and vouch size taken from a [`Profile`].

use std::collections::{BTreeSet, HashMap};
use std::time::SystemTime;

use agirru_crdt::GenerationClock;
use kuipa_enroll::EnrollServer;
use kuipa_enroll::anchors::{AnchorState, Entry, Trust};
use kuipa_enroll::delegation::{Claim, Delegation, SignedVouch, VOUCH_VALIDITY};
use kuipa_enroll::join::{AuthType, Operation, PendingJoin, Prepared, Request, Response};
use kuipa_enroll::keytab::{Enctype, Keytab};
use kuipa_enroll::merkle::TreeHash;
use kuipa_enroll::realm::{RealmInfo, ServerKeys, VerifiedRealm};
use kuipa_enroll::server::Directory;
use tang_pqc::{
    ExchangeKeyPair, KemAlg, Policy, SignatureAlg, SignedAdvertisement, SigningKey, Thumbprint,
    unix_seconds,
};

use crate::certs;
use crate::dir::{ADMIN, BenchDirectory, HOST, REALM, fake_binding, gss_token};
use crate::profile::{CaKind, Profile};

/// The domain the fixture realm uses.
pub const DOMAIN: &str = "example.test";

/// Seconds since the epoch, as the protocol clocks use.
#[must_use]
pub fn now() -> u64 {
    unix_seconds(SystemTime::now())
}

/// The FQDN of fixture server `i`.
#[must_use]
pub fn server_name(i: usize) -> String {
    format!("ipa{}.example.test", i + 1)
}

/// A fixture realm: anchors, servers that have exchanged trust, a directory.
pub struct Realm {
    /// Each server's own anchor key.
    pub anchors: Vec<SigningKey>,
    /// The servers, published.
    pub servers: Vec<EnrollServer>,
    /// The directory they consult.
    pub dir: BenchDirectory,
    /// The profile that sized this realm.
    pub profile: Profile,
    /// The CA certificates, DER.
    pub cas: Vec<Vec<u8>>,
}

/// Build a realm sized by `profile`, with `profile`'s CA kind.
///
/// # Panics
///
/// If keygen, certificate generation, or the trust exchange fails — fixture
/// setup, not protocol behavior.
#[must_use]
pub fn realm(profile: &Profile) -> Realm {
    realm_with(profile, profile.ca)
}

/// [`realm`] with a specific CA kind (for CA sweeps).
///
/// # Panics
///
/// As [`realm`].
#[must_use]
pub fn realm_with(profile: &Profile, ca: CaKind) -> Realm {
    let cas = certs::chain(ca, profile.ca_certs).expect("CA certificates");
    let servers: Vec<String> = (0..profile.servers).map(server_name).collect();
    let anchors: Vec<SigningKey> = (0..profile.servers)
        .map(|_| {
            SigningKey::generate(SignatureAlg::MlDsa65)
                .unwrap_or_else(|e| panic!("anchor keygen: {e}"))
        })
        .collect();
    let signing: Vec<SigningKey> = anchors
        .iter()
        .map(|_| SigningKey::generate(SignatureAlg::MlDsa65).expect("signing key"))
        .collect();
    let own: Vec<Delegation> = anchors
        .iter()
        .zip(&signing)
        .zip(&servers)
        .map(|((anchor, key), fqdn)| {
            Delegation::issue(
                anchor,
                REALM,
                fqdn,
                key.public(),
                now() - 60,
                now() + 30 * 86400,
            )
            .unwrap_or_else(|e| panic!("delegation: {e}"))
        })
        .collect();
    let enroll: Vec<EnrollServer> = signing
        .into_iter()
        .zip(&servers)
        .map(|(key, fqdn)| {
            let i = servers.iter().position(|s| s == fqdn).unwrap();
            EnrollServer::new(
                server_keys(key),
                info(&anchors[i], fqdn, &servers, &cas),
                own[i].clone(),
            )
        })
        .collect();
    exchange(&anchors, &enroll, &own, profile.attested);
    let dir = BenchDirectory::new(profile.keytab_entries, cas.clone(), servers.clone());
    dir.set_otp(HOST, b"Secret123");
    Realm {
        anchors,
        servers: enroll,
        dir,
        profile: profile.clone(),
        cas,
    }
}

fn server_keys(signing: SigningKey) -> ServerKeys {
    ServerKeys {
        signing,
        join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).expect("join key")],
        escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).expect("escrow key")],
        trust: Vec::new(),
        vouchers: Vec::new(),
        retired: Vec::new(),
    }
}

fn info(anchor: &SigningKey, fqdn: &str, servers: &[String], cas: &[Vec<u8>]) -> RealmInfo {
    RealmInfo {
        realm: REALM.into(),
        domain: DOMAIN.into(),
        basedn: "dc=example,dc=test".into(),
        server: fqdn.into(),
        servers: servers.to_vec(),
        ca_certs: cas.to_vec(),
        pkinit_anchors: cas.to_vec(),
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
        kdc_proxy: None,
    }
}

/// Run the anchor exchange: each anchor admits every claim and vouches for
/// the tree, and each server publishes with all anchors' proofs.
///
/// With `attested` fewer than `servers - 1`, a server's delegation attests
/// only the first `attested` peers — enough for verification, cheaper to
/// sign.
fn exchange(anchors: &[SigningKey], servers: &[EnrollServer], own: &[Delegation], attested: usize) {
    let clock = GenerationClock::new();
    let policy = Policy::default();
    let members: BTreeSet<String> = servers.iter().map(|s| s.info().server.clone()).collect();
    let claims: Vec<Claim> = own.iter().map(|d| d.claim().expect("claim")).collect();
    let mut state = AnchorState::default();
    for (anchor, claim) in anchors.iter().zip(&claims) {
        state
            .put(
                Entry::Key(anchor.public().to_jwk_json()),
                REALM,
                &policy,
                now(),
                &clock,
            )
            .expect("admit anchor key");
        state
            .put(Entry::Claim(claim.clone()), REALM, &policy, now(), &clock)
            .expect("admit claim");
    }
    let trust = |state: &AnchorState, i: usize| -> Trust {
        let attested_delegations: Vec<Delegation> = own
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .take(attested)
            .map(|(_, d)| d.clone())
            .collect();
        Trust::compute(
            state,
            &claims[i],
            &attested_delegations,
            &members,
            &policy,
            now(),
        )
        .expect("trust")
    };
    for anchor in anchors {
        let leaves = trust(&state, 0)
            .leaves(TreeHash::for_signer(anchor.public().alg()))
            .expect("leaves");
        let vouch = SignedVouch::issue(
            anchor,
            REALM,
            leaves,
            now() - 60,
            now() + VOUCH_VALIDITY,
            None,
        )
        .expect("vouch");
        state
            .put(Entry::Vouch(vouch), REALM, &policy, now(), &clock)
            .expect("admit vouch");
    }
    for (i, server) in servers.iter().enumerate() {
        let t = trust(&state, i);
        let vouches: HashMap<Thumbprint, SignedVouch> = state
            .vouches()
            .map(|v| (v.vouch().anchor, v.clone()))
            .collect();
        server.publish(
            t.own_delegation(&state).expect("own delegation"),
            t.anchors(),
            vouches,
        );
    }
}

impl Realm {
    /// The anchors a client pins: the first server's, which every
    /// delegation carries after the exchange.
    #[must_use]
    pub fn pinned(&self) -> Vec<Thumbprint> {
        vec![*self.anchors[0].public().thumbprint()]
    }

    /// Every server's anchor.
    #[must_use]
    pub fn all_anchors(&self) -> Vec<Thumbprint> {
        self.anchors
            .iter()
            .map(|a| *a.public().thumbprint())
            .collect()
    }

    /// Server `i`'s advertisement, as served.
    ///
    /// # Panics
    ///
    /// If the advertisement cannot be built (fixture setup, not protocol).
    #[must_use]
    pub fn advertisement(&self, i: usize) -> SignedAdvertisement {
        self.servers[i]
            .advertisement(&self.pinned())
            .expect("advertisement")
    }

    /// What a client does with `GET /adv`: serve, encode, parse, verify.
    ///
    /// # Panics
    ///
    /// If the fixture's own advertisement fails to encode, parse, or verify.
    #[must_use]
    pub fn verify(&self, i: usize) -> VerifiedRealm {
        let json = self.advertisement(i).to_json();
        let adv = SignedAdvertisement::from_json(json.as_bytes()).expect("parse");
        VerifiedRealm::verify(
            &adv,
            REALM,
            &self.pinned(),
            &Policy::default(),
            SystemTime::now(),
        )
        .expect("verify")
    }

    /// Send `request` over the wire to server `i`.
    ///
    /// # Panics
    ///
    /// If the fixture's request/response cannot be (re)encoded, or the
    /// server refuses it.
    #[must_use]
    pub fn send(&self, i: usize, op: Operation, request: &Request) -> Response {
        let request = Request::from_bytes(op, &request.to_bytes()).expect("parse request");
        let response = self.servers[i]
            .handle(&request, &self.dir)
            .unwrap_or_else(|e| panic!("handle: {e:?}"));
        Response::from_bytes(&response.to_bytes()).expect("parse response")
    }

    /// A joined keytab from server `i`, via OTP.
    ///
    /// # Panics
    ///
    /// If the fixture join flow fails.
    #[must_use]
    pub fn join(&self, i: usize, otp: &[u8]) -> Keytab {
        let adv = self.verify(i);
        let (request, pending) = self.otp_request(&adv, otp);
        let response = self.send(i, Operation::Join, &request);
        pending.finish(&response, &adv).expect("finish").keytab
    }

    /// An OTP join request for [`HOST`].
    ///
    /// # Panics
    ///
    /// If the fixture request cannot be prepared or sealed.
    pub fn otp_request(&self, adv: &VerifiedRealm, otp: &[u8]) -> (Request, PendingJoin) {
        Prepared::new(adv, Operation::Join, HOST, AuthType::Otp, &Enctype::DEFAULT)
            .expect("prepare")
            .seal(otp, &[], &[])
            .expect("seal")
    }

    /// A Kerberos-authenticated join request for [`HOST`], with the fake
    /// token the directory accepts.
    ///
    /// # Panics
    ///
    /// If the fixture request cannot be prepared or sealed.
    pub fn gss_request(&self, adv: &VerifiedRealm) -> (Request, PendingJoin, Vec<u8>, [u8; 32]) {
        let prepared = Prepared::new(
            adv,
            Operation::Join,
            HOST,
            AuthType::Kerberos,
            &Enctype::DEFAULT,
        )
        .expect("prepare");
        let cb = prepared.channel_binding().expect("channel binding");
        let token = gss_token(ADMIN, &cb);
        let prepared = prepared.with_kerberos(fake_binding(ADMIN, &cb));
        let (request, pending) = prepared.seal(&token, &[], &[]).expect("seal");
        (request, pending, token, cb)
    }

    /// The signing-key thumbprint a client would use to verify server `i`'s
    /// advertisement signature itself.
    #[must_use]
    pub fn signer(&self, i: usize) -> Thumbprint {
        *self.servers[i].keys().signing.public().thumbprint()
    }

    /// The directory, as `&dyn Directory`.
    #[must_use]
    pub fn directory(&self) -> &dyn Directory {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::{HOST, REALM, realm, server_name};
    use kuipa_enroll::Directory;
    use kuipa_enroll::join::Operation;
    use kuipa_enroll::keytab::Principal;
    use tang_pqc::{Policy, SignedAdvertisement};

    fn smoke() -> super::Profile {
        super::Profile::named("smoke").expect("smoke")
    }

    #[test]
    fn realm_verifies_and_joins() {
        let r = realm(&smoke());
        assert_eq!(r.verify(0).info().realm, REALM);
        let kt = r.join(0, b"Secret123");
        assert_eq!(kt.principal(), &Principal::host(HOST, REALM));
    }

    #[test]
    fn advertisement_signature_verifies_under_its_own_signer() {
        let r = realm(&smoke());
        let adv = SignedAdvertisement::from_json(r.advertisement(0).to_json().as_bytes()).unwrap();
        assert!(SignedAdvertisement::verify_with(&adv, &r.signer(0), &Policy::default()).is_ok());
    }

    #[test]
    fn server_names_are_distinct() {
        assert_ne!(server_name(0), server_name(1));
    }

    #[test]
    fn pq_realm_carries_ml_dsa_ca() {
        let r = realm(&super::Profile::named("pqproduction").expect("pqproduction"));
        assert!(r.cas[0].len() > 4000, "ML-DSA CA should be large");
        assert_eq!(r.dir.ca_certificates().unwrap()[0].len(), r.cas[0].len());
    }

    #[test]
    fn gss_join_round_trips() {
        let r = realm(&smoke());
        let adv = r.verify(0);
        let (request, pending, _token, _cb) = r.gss_request(&adv);
        // The directory accepts ADMIN's fabricated ticket; no ticket store needed.
        let response = r.send(0, Operation::Join, &request);
        assert!(pending.finish(&response, &adv).is_ok());
    }

    #[test]
    fn every_server_verifies_after_escrow_scaling() {
        // Escrow slots are the advertisement's servers: sweeping them must
        // grow the realm and keep every server attested, or `verify` on a
        // later index refuses with an untrusted anchor.
        let p = smoke().with_escrow_servers(5);
        assert_eq!(p.servers, 5);
        let r = realm(&p);
        for i in 0..5 {
            assert_eq!(r.verify(i).info().server, server_name(i));
        }
    }
}
