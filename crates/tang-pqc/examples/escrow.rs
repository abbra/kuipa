//! Provision and recover a key in-process, printing what crosses the wire.
//!
//! ```sh
//! cargo run -p tang-pqc --example escrow [768|1024] [adv.json]
//! ```
//!
//! With a second argument, the signed advertisement (JWS JSON) is also
//! written to that file, e.g. for checking with other JOSE tooling.

use tang_pqc::{
    Binding, ExchangeKey, ExchangeKeyPair, KemAlg, RecoveryRequest, RecoveryResponse, Server,
    SignatureAlg, SignedAdvertisement, SigningKey,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (kem, sig) = match std::env::args().nth(1).as_deref() {
        Some("1024") => (KemAlg::MlKem1024, SignatureAlg::MlDsa87),
        _ => (KemAlg::MlKem768, SignatureAlg::MlDsa65),
    };
    println!("{kem:?} + {sig:?}\n");

    // ── Server (tangd) ──
    let signing_key = SigningKey::generate(sig)?;
    let thp = *signing_key.public().thumbprint();
    let server = Server::new(vec![signing_key], vec![ExchangeKeyPair::generate(kem)?])?;
    println!("server signing key thp : {thp}");

    // ── clevis encrypt: GET /adv, verify against the pinned thp, bind ──
    let adv_wire = server.advertisement()?.to_json();
    println!(
        "GET  /adv              : {:5} bytes (JWS JSON)",
        adv_wire.len()
    );
    if let Some(path) = std::env::args().nth(2) {
        std::fs::write(path, &adv_wire)?;
    }
    let adv = SignedAdvertisement::from_json(adv_wire.as_bytes())?.verify(&thp)?;
    let (binding, key) = adv.provision(None)?;
    let stored = binding.to_bytes();
    println!(
        "binding metadata       : {:5} bytes (stored with the volume)",
        stored.len()
    );

    // ── clevis decrypt: GET /key/{kid}, then POST /rec/{kid} ──
    let binding = Binding::from_bytes(&stored)?;
    let key_wire = server.exchange_key(binding.kid())?.to_jwk_json();
    println!(
        "GET  /key/{}… : {:5} bytes (public JWK)",
        &binding.kid().to_string()[..8],
        key_wire.len()
    );
    let exchange_key = ExchangeKey::from_jwk_json(key_wire.as_bytes())?;
    let (request, pending) = binding.recovery_request(&exchange_key)?;
    let request_wire = request.to_bytes();
    let response_wire = server
        .recover(&RecoveryRequest::from_bytes(&request_wire)?)?
        .to_bytes();
    println!(
        "POST /rec/{}… : {:5} bytes request, {} bytes response",
        &request.kid().to_string()[..8],
        request_wire.len(),
        response_wire.len()
    );
    let recovered = pending.finish(&RecoveryResponse::from_bytes(&response_wire)?)?;

    assert_eq!(key.as_ref(), recovered.as_ref());
    println!("\nrecovered the {}-byte key", recovered.as_ref().len());
    Ok(())
}
