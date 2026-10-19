//! The extension points used by protocols built on tang-pqc: protocol
//! domains, binding context, role-tagged exchange keys and signed members.

use tang_pqc::primitives::Domain;
use tang_pqc::{
    AdvertisementBuilder, Binding, BindingContext, Error, ExchangeKeyPair, KemAlg, Policy,
    SignatureAlg, SignedAdvertisement, SigningKey,
};

const ESCROW: Domain = Domain::new("test-escrow/v1");

struct Setup {
    signing: SigningKey,
    plain: ExchangeKeyPair,
    escrow: ExchangeKeyPair,
}

fn setup() -> Setup {
    Setup {
        signing: SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
        plain: ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap(),
        escrow: ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap(),
    }
}

fn now() -> u64 {
    tang_pqc::unix_seconds(std::time::SystemTime::now())
}

fn signed(s: &Setup) -> SignedAdvertisement {
    AdvertisementBuilder::new(&[&s.signing])
        .exchange_key(s.plain.public())
        .exchange_key_with(s.escrow.public(), "role", "escrow")
        .member("realm", "EXAMPLE.TEST".into())
        .validity(now() - 10, now() + 3600)
        .sign()
        .unwrap()
}

#[test]
fn tagged_keys_are_invisible_to_plain_tang() {
    let s = setup();
    let adv = SignedAdvertisement::from_json(signed(&s).to_json().as_bytes())
        .unwrap()
        .verify(s.signing.public().thumbprint())
        .unwrap();
    assert_eq!(adv.exchange_keys().len(), 1);
    assert_eq!(adv.exchange_keys()[0].kid(), s.plain.public().kid());

    let escrow: Vec<_> = adv.exchange_keys_where("role", "escrow").collect();
    assert_eq!(escrow.len(), 1);
    assert_eq!(escrow[0].kid(), s.escrow.public().kid());
    assert_eq!(adv.exchange_keys_where("role", "join").count(), 0);
    assert!(adv.exchange_key(s.escrow.public().kid()).is_some());

    assert_eq!(
        adv.member("realm").and_then(|v| v.as_str()),
        Some("EXAMPLE.TEST")
    );
    assert!(adv.member("keys").is_none());
}

#[test]
fn members_are_signed() {
    let s = setup();
    let json = signed(&s).to_json();
    let mut jws: serde_json::Value = serde_json::from_str(&json).unwrap();
    let payload = tang_pqc::b64::decode(jws["payload"].as_str().unwrap()).unwrap();
    let mut set: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    set["realm"] = "EVIL.TEST".into();
    jws["payload"] = tang_pqc::b64::encode(set.to_string().as_bytes()).into();
    let forged = SignedAdvertisement::from_json(jws.to_string().as_bytes()).unwrap();
    assert!(matches!(
        forged.verify(s.signing.public().thumbprint()),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn context_binds_domain_and_info() {
    let s = setup();
    let adv = signed(&s)
        .verify_with(s.signing.public().thumbprint(), &Policy::default())
        .unwrap();
    let ctx = BindingContext::new(ESCROW, b"host/a.example.test@EXAMPLE.TEST");
    let (binding, key) = adv
        .provision_with(&ctx, Some(s.escrow.public().kid()))
        .unwrap();
    let stored = binding.to_bytes();
    assert_eq!(
        binding.ciphertext_hash().unwrap(),
        Binding::from_bytes_with(&ctx, &stored)
            .unwrap()
            .ciphertext_hash()
            .unwrap()
    );

    // Recovery in the same context yields the key, and the opened request
    // identifies the binding for server-side registration checks.
    let binding = Binding::from_bytes_with(&ctx, &stored).unwrap();
    let ek = s.escrow.public();
    let (request, pending) = binding.recovery_request(ek).unwrap();
    let opened = request.open(&s.escrow, ESCROW).unwrap();
    assert_eq!(
        opened.ciphertext_hash().unwrap(),
        binding.ciphertext_hash().unwrap()
    );
    let response = opened.respond().unwrap();
    assert_eq!(pending.finish(&response).unwrap().as_ref(), key.as_ref());

    // Another principal (info) or the Tang domain does not.
    for other in [
        BindingContext::new(ESCROW, b"host/b.example.test@EXAMPLE.TEST"),
        BindingContext::default(),
    ] {
        let binding = Binding::from_bytes_with(&other, &stored).unwrap();
        let (request, pending) = binding.recovery_request(ek).unwrap();
        let response = request.respond(&s.escrow, other.domain()).unwrap();
        assert!(matches!(
            pending.finish(&response),
            Err(Error::RecoveryFailed)
        ));
    }

    // A server in the wrong domain cannot open the request.
    let (request, _pending) = binding.recovery_request(ek).unwrap();
    assert!(matches!(
        request.respond(&s.escrow, Domain::TANG),
        Err(Error::Malformed("recovery request"))
    ));

    // The request names one key; another key cannot answer it, and the
    // client refuses to seal to a key other than the binding's.
    assert!(matches!(
        request.respond(&s.plain, ESCROW),
        Err(Error::UnknownKey(_))
    ));
    assert!(matches!(
        binding.recovery_request(s.plain.public()),
        Err(Error::KeyMismatch)
    ));
}

#[test]
fn default_context_matches_tang() {
    let s = setup();
    let adv = signed(&s).verify(s.signing.public().thumbprint()).unwrap();
    let (binding, key) = adv.provision(None).unwrap();
    let binding = Binding::from_bytes(&binding.to_bytes()).unwrap();
    let server = tang_pqc::Server::new(
        vec![SigningKey::from_jwk(s.signing.to_jwk().unwrap().as_ref()).unwrap()],
        vec![ExchangeKeyPair::from_jwk(s.plain.to_jwk().unwrap().as_ref()).unwrap()],
    )
    .unwrap();
    let (request, pending) = binding
        .recovery_request(server.exchange_key(binding.kid()).unwrap())
        .unwrap();
    let response = server.recover(&request).unwrap();
    assert_eq!(pending.finish(&response).unwrap().as_ref(), key.as_ref());
}
