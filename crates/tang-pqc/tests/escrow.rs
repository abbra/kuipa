//! End-to-end tests for provisioning, recovery, trust and rotation.

use tang_pqc::{
    Binding, Error, ExchangeKey, ExchangeKeyPair, KemAlg, Policy, RecoveryRequest,
    RecoveryResponse, Server, SignatureAlg, SignedAdvertisement, SigningKey, Thumbprint,
};

struct Setup {
    server: Server,
    trusted: Thumbprint,
}

fn setup(kem: KemAlg, sig: SignatureAlg) -> Setup {
    let signing = SigningKey::generate(sig).unwrap();
    let trusted = *signing.public().thumbprint();
    let server = Server::new(vec![signing], vec![ExchangeKeyPair::generate(kem).unwrap()]).unwrap();
    Setup { server, trusted }
}

/// `GET /key/{kid}`, through the wire encoding.
fn fetch_key(server: &Server, kid: &Thumbprint) -> Result<ExchangeKey, Error> {
    ExchangeKey::from_jwk_json(server.exchange_key(kid)?.to_jwk_json().as_bytes())
}

/// One recovery round trip, through the wire encodings.
fn recover(server: &Server, binding: &Binding) -> Result<tang_pqc::Key, Error> {
    let key = fetch_key(server, binding.kid())?;
    let (request, pending) = binding.recovery_request(&key)?;
    let request = RecoveryRequest::from_bytes(&request.to_bytes())?;
    let response = server.recover(&request)?;
    pending.finish(&RecoveryResponse::from_bytes(&response.to_bytes())?)
}

#[test]
fn provision_and_recover_all_algorithms() {
    for kem in KemAlg::ALL {
        for sig in SignatureAlg::ALL {
            let s = setup(kem, sig);
            let wire = s.server.advertisement().unwrap().to_json();
            let adv = SignedAdvertisement::from_json(wire.as_bytes()).unwrap();
            // Every suite; the default policy accepts all of them.
            let policy = Policy::default();
            let (binding, key) = adv
                .verify_with(&s.trusted, &policy)
                .unwrap()
                .provision(None)
                .unwrap();
            let binding = Binding::from_bytes(&binding.to_bytes()).unwrap();

            let recovered = recover(&s.server, &binding).unwrap();
            assert_eq!(key.as_ref(), recovered.as_ref(), "{kem:?}/{sig:?}");
            assert_eq!(key.as_ref().len(), tang_pqc::KEY_LEN);
            // The binding's identity is the suite hash: SHA-384 for
            // ML-KEM-1024 (CNSA 2.0), SHA-256 for ML-KEM-768.
            assert_eq!(
                Some(binding.ciphertext_hash().unwrap().len()),
                tang_pqc::primitives::digest_len(kem.hash()),
                "{kem:?}"
            );
        }
    }
}

#[test]
fn recovery_is_repeatable_and_bindings_independent() {
    let s = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let adv = s
        .server
        .advertisement()
        .unwrap()
        .verify(&s.trusted)
        .unwrap();
    let (b1, k1) = adv.provision(None).unwrap();
    let (b2, k2) = adv.provision(None).unwrap();
    assert_ne!(k1.as_ref(), k2.as_ref());

    let ek = fetch_key(&s.server, b1.kid()).unwrap();
    let (r1, _) = b1.recovery_request(&ek).unwrap();
    let (r2, _) = b1.recovery_request(&ek).unwrap();
    assert_ne!(r1, r2, "fresh transport encapsulation per attempt");

    for _ in 0..3 {
        assert_eq!(recover(&s.server, &b1).unwrap().as_ref(), k1.as_ref());
        assert_eq!(recover(&s.server, &b2).unwrap().as_ref(), k2.as_ref());
    }
}

#[test]
fn advertisement_requires_the_pinned_key() {
    let s = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let adv = s.server.advertisement().unwrap();
    let stranger = *SigningKey::generate(SignatureAlg::MlDsa65)
        .unwrap()
        .public()
        .thumbprint();
    assert!(matches!(
        adv.verify(&stranger),
        Err(Error::UntrustedAdvertisement)
    ));
    assert_eq!(adv.advertised_signing_keys().unwrap(), vec![s.trusted]);
}

#[test]
fn multiple_signing_keys_each_verify() {
    let a = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let b = SigningKey::generate(SignatureAlg::MlDsa87).unwrap();
    let (ta, tb) = (*a.public().thumbprint(), *b.public().thumbprint());
    let server = Server::new(
        vec![a, b],
        vec![ExchangeKeyPair::generate(KemAlg::MlKem1024).unwrap()],
    )
    .unwrap();
    let adv = server.advertisement().unwrap();
    assert_eq!(adv.verify(&ta).unwrap().signing_keys().len(), 2);
    let (binding, _) = adv.verify(&tb).unwrap().provision(None).unwrap();
    assert_eq!(binding.signing_thumbprint(), &tb);
}

#[test]
fn responses_are_bound_to_their_request() {
    let s = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let adv = s
        .server
        .advertisement()
        .unwrap()
        .verify(&s.trusted)
        .unwrap();
    let (binding, _) = adv.provision(None).unwrap();
    let ek = adv.exchange_key(binding.kid()).unwrap();

    // Replay: a response to an earlier request does not open a new one.
    let (old_request, _) = binding.recovery_request(ek).unwrap();
    let old_response = s.server.recover(&old_request).unwrap();
    let (_, pending) = binding.recovery_request(ek).unwrap();
    assert!(matches!(
        pending.finish(&old_response),
        Err(Error::RecoveryFailed)
    ));

    // Tampering with the sealed secret is detected.
    let (request, pending) = binding.recovery_request(ek).unwrap();
    let mut wire = s.server.recover(&request).unwrap().to_bytes();
    let last = wire.len() - 1;
    wire[last] ^= 1;
    let tampered = RecoveryResponse::from_bytes(&wire).unwrap();
    assert!(matches!(
        pending.finish(&tampered),
        Err(Error::RecoveryFailed)
    ));
}

#[test]
fn tampered_binding_fails_cleanly() {
    let s = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let adv = s
        .server
        .advertisement()
        .unwrap()
        .verify(&s.trusted)
        .unwrap();
    let (binding, _) = adv.provision(None).unwrap();
    let good = binding.to_bytes();

    // Layout: magic(4) ver(1) alg(1) kid(32) thp(32) len(4) ct(1088) r(32) confirm(32)
    let thp_at = 4 + 1 + 1 + 32;
    let ct_at = thp_at + 32 + 4;
    let share_at = ct_at + 1088;
    for idx in [thp_at + 5, ct_at + 10, share_at + 3] {
        let mut bad = good.clone();
        bad[idx] ^= 1;
        let bad = Binding::from_bytes(&bad).unwrap();
        // A changed ciphertext decapsulates to a pseudorandom secret (FIPS 203
        // implicit rejection); a changed share or trust anchor (bound into
        // the KDF) derives a different key.  The confirmation tag catches
        // all of them.
        assert!(matches!(
            recover(&s.server, &bad),
            Err(Error::RecoveryFailed)
        ));
    }
    assert!(Binding::from_bytes(&good[..good.len() - 1]).is_err());
}

#[test]
fn rotation_keeps_old_bindings_recoverable() {
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let trusted = *signing.public().thumbprint();
    let signing_pem = signing.to_pem().unwrap();
    let old = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let old_pem = old.to_pem().unwrap();
    let old_kid = *old.public().kid();

    let server = Server::new(vec![signing], vec![old]).unwrap();
    let (binding, key) = server
        .advertisement()
        .unwrap()
        .verify(&trusted)
        .unwrap()
        .provision(None)
        .unwrap();
    assert_eq!(binding.kid(), &old_kid);

    // Restart with a new exchange key; the old one becomes hidden.
    let signing = SigningKey::from_pem(&signing_pem).unwrap();
    let rotated = Server::new(
        vec![signing],
        vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
    )
    .unwrap()
    .with_retired_keys(vec![ExchangeKeyPair::from_pem(&old_pem).unwrap()]);
    let adv = rotated.advertisement().unwrap().verify(&trusted).unwrap();
    assert!(
        adv.exchange_key(&old_kid).is_none(),
        "retired key not advertised"
    );
    assert_eq!(recover(&rotated, &binding).unwrap().as_ref(), key.as_ref());

    // Once the old key is deleted, the binding is dead.
    let signing = SigningKey::from_pem(&signing_pem).unwrap();
    let purged = Server::new(
        vec![signing],
        vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
    )
    .unwrap();
    assert!(matches!(recover(&purged, &binding), Err(Error::UnknownKey(k)) if k == old_kid));
}

#[test]
fn provision_with_explicit_kid() {
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let trusted = *signing.public().thumbprint();
    let k768 = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let k1024 = ExchangeKeyPair::generate(KemAlg::MlKem1024).unwrap();
    let kid1024 = *k1024.public().kid();
    let server = Server::new(vec![signing], vec![k768, k1024]).unwrap();
    let adv = server.advertisement().unwrap().verify(&trusted).unwrap();

    let (binding, key) = adv.provision(Some(&kid1024)).unwrap();
    assert_eq!(binding.kid(), &kid1024);
    assert_eq!(recover(&server, &binding).unwrap().as_ref(), key.as_ref());

    let bogus = Thumbprint::from_bytes([0; 32]);
    assert!(matches!(
        adv.provision(Some(&bogus)),
        Err(Error::UnknownKey(_))
    ));
}

#[test]
fn malformed_wire_messages_are_rejected() {
    assert!(SignedAdvertisement::from_json(b"").is_err());
    assert!(
        SignedAdvertisement::from_json(br#"{"payload":"!!","signatures":[]}"#)
            .unwrap()
            .advertised_signing_keys()
            .is_err()
    );
    assert!(RecoveryRequest::from_bytes(b"TQRQ\x01").is_err());
    assert!(RecoveryResponse::from_bytes(b"TQRS\x02").is_err());
    assert!(Binding::from_bytes(b"TQBD\x01\x7f").is_err());
}

/// Server keys persisted as JWK files (Tang's key directory) keep serving
/// existing bindings, and the advertised thumbprints are stable.
#[test]
fn server_keys_survive_jwk_storage() {
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let exchange = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let thp = *signing.public().thumbprint();
    let (signing_jwk, exchange_jwk) = (signing.to_jwk().unwrap(), exchange.to_jwk().unwrap());

    let server = Server::new(vec![signing], vec![exchange]).unwrap();
    let (binding, key) = server
        .advertisement()
        .unwrap()
        .verify(&thp)
        .unwrap()
        .provision(None)
        .unwrap();

    let restarted = Server::new(
        vec![SigningKey::from_jwk(signing_jwk.as_ref()).unwrap()],
        vec![ExchangeKeyPair::from_jwk(exchange_jwk.as_ref()).unwrap()],
    )
    .unwrap();
    restarted.advertisement().unwrap().verify(&thp).unwrap();
    assert_eq!(
        recover(&restarted, &binding).unwrap().as_ref(),
        key.as_ref()
    );
}

/// The server stamps `iat`/`exp`, clients reject replays after expiry, and
/// the server re-signs once half the validity has passed.
#[test]
fn advertisements_expire_and_refresh() {
    use std::time::{Duration, SystemTime};

    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let thp = *signing.public().thumbprint();
    let server = Server::with_validity(
        vec![signing],
        vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        Duration::from_secs(2),
    )
    .unwrap();

    let first = server.advertisement().unwrap();
    first.verify(&thp).unwrap();
    let policy = Policy::default().with_clock_skew(Duration::ZERO);
    let later = SystemTime::now() + Duration::from_secs(5);
    assert!(matches!(
        first.verify_at(&thp, &policy, later),
        Err(Error::StaleAdvertisement)
    ));

    std::thread::sleep(Duration::from_millis(1100));
    let second = server.advertisement().unwrap();
    assert_ne!(first, second, "re-signed after half the validity");
    second.verify(&thp).unwrap();
}

/// With a binding that never changes, the requests on the wire neither
/// contain its ciphertext nor repeat, so an observer cannot link unlocks.
#[test]
fn static_binding_requests_are_unlinkable_on_the_wire() {
    let s = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let adv = s
        .server
        .advertisement()
        .unwrap()
        .verify(&s.trusted)
        .unwrap();
    let (binding, key) = adv.provision(None).unwrap();
    let stored = binding.to_bytes();
    // Binding layout: magic(4) ver(1) alg(1) kid(32) thp(32) len(4) ct(1088) …
    let ct = &stored[4 + 1 + 1 + 32 + 32 + 4..][..1088];
    let ek = fetch_key(&s.server, binding.kid()).unwrap();

    let mut seen: Vec<Vec<u8>> = Vec::new();
    for _ in 0..3 {
        let (request, pending) = binding.recovery_request(&ek).unwrap();
        let wire = request.to_bytes();
        assert!(!wire.windows(32).any(|w| ct.windows(32).any(|c| c == w)));
        // Everything after magic, version, alg and kid is fresh.
        let body = wire[4 + 1 + 1 + 32..].to_vec();
        assert!(!seen.contains(&body));
        seen.push(body);
        let recovered = pending
            .finish(&s.server.recover(&request).unwrap())
            .unwrap();
        assert_eq!(recovered.as_ref(), key.as_ref());
    }
}

/// The client must use the binding's own exchange key, and the server
/// refuses a request that does not open under its key.
#[test]
fn requests_need_the_right_key_and_are_authenticated() {
    let s = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let adv = s
        .server
        .advertisement()
        .unwrap()
        .verify(&s.trusted)
        .unwrap();
    let (binding, _) = adv.provision(None).unwrap();

    let stranger = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    assert!(matches!(
        binding.recovery_request(stranger.public()),
        Err(Error::KeyMismatch)
    ));
    assert!(matches!(
        fetch_key(&s.server, &Thumbprint::from_bytes([0; 32])),
        Err(Error::UnknownKey(_))
    ));

    let ek = fetch_key(&s.server, binding.kid()).unwrap();
    let (request, _) = binding.recovery_request(&ek).unwrap();
    let good = request.to_bytes();
    // Flip a bit in the transport ciphertext, then in the sealed ciphertext.
    for idx in [4 + 1 + 1 + 32 + 4 + 7, good.len() - 20] {
        let mut bad = good.clone();
        bad[idx] ^= 1;
        let bad = RecoveryRequest::from_bytes(&bad).unwrap();
        assert!(matches!(
            s.server.recover(&bad),
            Err(Error::Malformed("recovery request"))
        ));
    }
}

/// Optional one-time bindings: rebinding after an unlock yields a new key
/// on the same exchange key.
#[test]
fn rebinding_after_an_unlock() {
    let s = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let adv = s
        .server
        .advertisement()
        .unwrap()
        .verify(&s.trusted)
        .unwrap();
    let (mut binding, mut key) = adv.provision(None).unwrap();

    for _ in 0..3 {
        assert_eq!(recover(&s.server, &binding).unwrap().as_ref(), key.as_ref());
        let fresh = s
            .server
            .advertisement()
            .unwrap()
            .verify(&s.trusted)
            .unwrap();
        let (next, next_key) = binding.rebind(&fresh).unwrap();
        assert_eq!(
            next.kid(),
            binding.kid(),
            "same exchange key while advertised"
        );
        assert_ne!(next_key.as_ref(), key.as_ref());
        (binding, key) = (next, next_key);
    }
}

#[test]
fn rebinding_refuses_a_different_trust_anchor_and_migrates_rotated_keys() {
    let s = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let (binding, _) = s
        .server
        .advertisement()
        .unwrap()
        .verify(&s.trusted)
        .unwrap()
        .provision(None)
        .unwrap();

    // Another server, another signing key: refused.
    let other = setup(KemAlg::MlKem768, SignatureAlg::MlDsa65);
    let foreign = other
        .server
        .advertisement()
        .unwrap()
        .verify(&other.trusted)
        .unwrap();
    assert!(matches!(
        binding.rebind(&foreign),
        Err(Error::UntrustedAdvertisement)
    ));

    // Same signing key, rotated exchange key: the new binding moves to it.
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let thp = *signing.public().thumbprint();
    let signing_jwk = signing.to_jwk().unwrap();
    let old = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let server = Server::new(vec![signing], vec![old]).unwrap();
    let (binding, _) = server
        .advertisement()
        .unwrap()
        .verify(&thp)
        .unwrap()
        .provision(None)
        .unwrap();
    let rotated = Server::new(
        vec![SigningKey::from_jwk(signing_jwk.as_ref()).unwrap()],
        vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
    )
    .unwrap();
    let adv = rotated.advertisement().unwrap().verify(&thp).unwrap();
    let (moved, key) = binding.rebind(&adv).unwrap();
    assert_ne!(moved.kid(), binding.kid());
    assert_eq!(recover(&rotated, &moved).unwrap().as_ref(), key.as_ref());
}
