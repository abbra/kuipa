//! Run the full protocol, then write files a stock `openssl` CLI can verify.
//!
//! ```sh
//! cargo run --example demo -- /tmp/blind
//! openssl pkeyutl -verify -pubin -inkey /tmp/blind/pk.pem -rawin \
//!     -in /tmp/blind/signed-message.bin -sigfile /tmp/blind/sig.bin
//! ```

use std::path::PathBuf;

use ml_dsa_blind::{BlindRequest, BlindResponse, Context, ParameterSet, Requester, SigningKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "blind-demo".into()),
    );
    std::fs::create_dir_all(&out)?;

    // Signer setup: a dedicated key; publish the public key.
    let signer = SigningKey::generate(ParameterSet::MlDsa65)?;
    let public_key = signer.verifying_key().clone();

    // Requester: blind the message.
    let message = b"document the signer must not read";
    let requester = Requester::new(public_key.clone());
    let (request, pending) = requester.blind(message)?;
    let request_wire = request.as_bytes().to_vec();
    println!("requester -> signer : {} bytes (mu)", request_wire.len());

    // Signer: sees only 64 opaque bytes.
    let response_wire = signer
        .blind_sign(&BlindRequest::from_bytes(&request_wire)?)?
        .as_bytes()
        .to_vec();
    println!(
        "signer -> requester : {} bytes (ML-DSA signature)",
        response_wire.len()
    );

    // Requester: verify the response and unblind.
    let signature = pending.finalize(&BlindResponse::from(response_wire))?;
    public_key.verify(&Context::default(), message, &signature)?;
    println!(
        "blind signature     : {} bytes (salt || signature), verified",
        signature.to_bytes().len()
    );

    std::fs::write(out.join("pk.pem"), public_key.to_pem()?)?;
    std::fs::write(
        out.join("signed-message.bin"),
        signature.signed_message(message),
    )?;
    std::fs::write(out.join("sig.bin"), signature.ml_dsa_signature())?;
    println!(
        "\nverify with stock OpenSSL:\n  openssl pkeyutl -verify -pubin -inkey {0}/pk.pem -rawin \\\n      -in {0}/signed-message.bin -sigfile {0}/sig.bin",
        out.display()
    );
    Ok(())
}
