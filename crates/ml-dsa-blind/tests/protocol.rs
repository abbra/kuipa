//! End-to-end tests, including interoperability with stock OpenSSL ML-DSA.

#![allow(unsafe_code)] // only for the ML-DSA-MU cross-check below

use ml_dsa_blind::{
    BlindRequest, BlindResponse, BlindSignature, Context, Error, ParameterSet, Requester,
    SigningKey, VerifyingKey,
};
use native_ossl::digest::DigestAlg;
use native_ossl::params::ParamBuilder;
use native_ossl::pkey::{MessageVerifier, SigAlg};
use native_ossl::typed_params::sig::CONTEXT_STRING;

const MSG: &[u8] = b"attack at dawn";

fn issue(
    sk: &SigningKey,
    ctx: &Context,
    msg: &[u8],
) -> (BlindRequest, BlindResponse, BlindSignature) {
    let requester = Requester::with_context(sk.verifying_key().clone(), ctx.clone());
    let (request, pending) = requester.blind(msg).unwrap();
    let response = sk.blind_sign(&request).unwrap();
    let signature = pending.finalize(&response).unwrap();
    (request, response, signature)
}

/// Verify with plain OpenSSL pure ML-DSA, with no knowledge of this crate.
fn openssl_pure_verify(pk: &VerifyingKey, ctx: &Context, msg: &[u8], sig: &[u8]) -> bool {
    let params = ParamBuilder::new()
        .unwrap()
        .set(CONTEXT_STRING, ctx.as_bytes())
        .unwrap()
        .build()
        .unwrap();
    let alg = SigAlg::fetch(pk.parameter_set().algorithm_name(), None).unwrap();
    let mut verifier = MessageVerifier::new(pk.pkey(), &alg, Some(&params)).unwrap();
    verifier.verify(msg, sig).unwrap()
}

/// μ computed by OpenSSL's own `ML-DSA-MU` digest (see EVP_MD-ML-DSA-MU(7)),
/// or `None` where OpenSSL does not provide that digest (3.5 has the `mu`
/// signing parameter this crate needs, but not the digest).
fn openssl_mu(pk: &VerifyingKey, ctx: &Context, message: &[u8]) -> Option<[u8; 64]> {
    let alg = DigestAlg::fetch(c"ML-DSA-MU", None).ok()?;
    let params = ParamBuilder::new()
        .unwrap()
        .push_octet_slice(c"pub", pk.as_bytes())
        .unwrap()
        .push_octet_slice(c"context-string", ctx.as_bytes())
        .unwrap()
        .build()
        .unwrap();
    let mut md = alg.new_context().unwrap();
    // native-ossl cannot pass init params to a digest yet, so re-initialise
    // the context with them.
    // SAFETY: all three pointers are valid for the duration of the call.
    let rc =
        unsafe { native_ossl_sys::EVP_DigestInit_ex2(md.as_ptr(), alg.as_ptr(), params.as_ptr()) };
    assert_eq!(rc, 1, "EVP_DigestInit_ex2(ML-DSA-MU) failed");
    md.update(message).unwrap();
    let mut mu = [0u8; 64];
    md.finish_xof(&mut mu).unwrap();
    Some(mu)
}

#[test]
fn round_trip_all_parameter_sets() {
    for ps in ParameterSet::ALL {
        let sk = SigningKey::generate(ps).unwrap();
        for ctx in [
            Context::default(),
            Context::new(b"app/v1".to_vec()).unwrap(),
        ] {
            let (_, _, sig) = issue(&sk, &ctx, MSG);
            assert_eq!(sig.ml_dsa_signature().len(), ps.signature_len());
            sk.verifying_key().verify(&ctx, MSG, &sig).unwrap();
        }
    }
}

#[test]
fn output_is_a_standard_ml_dsa_signature() {
    for ps in ParameterSet::ALL {
        let sk = SigningKey::generate(ps).unwrap();
        let pk = sk.verifying_key();
        let ctx = Context::new(b"interop".to_vec()).unwrap();
        let (_, _, sig) = issue(&sk, &ctx, MSG);

        assert!(openssl_pure_verify(
            pk,
            &ctx,
            &sig.signed_message(MSG),
            sig.ml_dsa_signature()
        ));
        // The bare message (without the salt) is *not* what was signed.
        assert!(!openssl_pure_verify(pk, &ctx, MSG, sig.ml_dsa_signature()));
    }
}

#[test]
fn request_matches_openssl_ml_dsa_mu() {
    for ps in ParameterSet::ALL {
        let sk = SigningKey::generate(ps).unwrap();
        let pk = sk.verifying_key();
        for ctx in [Context::default(), Context::new(vec![0xa5; 255]).unwrap()] {
            let (request, _, sig) = issue(&sk, &ctx, MSG);
            let Some(expected) = openssl_mu(pk, &ctx, &sig.signed_message(MSG)) else {
                // The signatures still verify with OpenSSL's pure ML-DSA
                // (output_is_a_standard_ml_dsa_signature), which needs
                // the same μ.
                eprintln!("skipped: this OpenSSL has no ML-DSA-MU digest");
                return;
            };
            assert_eq!(request.as_bytes(), &expected);
        }
    }
}

#[test]
fn rejects_wrong_message_context_or_key() {
    let sk = SigningKey::generate(ParameterSet::MlDsa44).unwrap();
    let other = SigningKey::generate(ParameterSet::MlDsa44).unwrap();
    let ctx = Context::new(b"ctx".to_vec()).unwrap();
    let (_, _, sig) = issue(&sk, &ctx, MSG);

    let pk = sk.verifying_key();
    assert!(matches!(
        pk.verify(&ctx, b"attack at dusk", &sig),
        Err(Error::InvalidSignature)
    ));
    assert!(matches!(
        pk.verify(&Context::default(), MSG, &sig),
        Err(Error::InvalidSignature)
    ));
    assert!(matches!(
        other.verifying_key().verify(&ctx, MSG, &sig),
        Err(Error::InvalidSignature)
    ));

    let mut bytes = sig.to_bytes();
    bytes[0] ^= 1; // flip a salt bit
    let tampered = BlindSignature::from_bytes(ParameterSet::MlDsa44, &bytes).unwrap();
    assert!(matches!(
        pk.verify(&ctx, MSG, &tampered),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn finalize_rejects_bad_responses() {
    let sk = SigningKey::generate(ParameterSet::MlDsa65).unwrap();
    let requester = Requester::new(sk.verifying_key().clone());

    // A valid signature, but on somebody else's request.
    let (other_request, _) = requester.blind(b"other").unwrap();
    let wrong = sk.blind_sign(&other_request).unwrap();
    let (_, pending) = requester.blind(MSG).unwrap();
    assert!(matches!(
        pending.finalize(&wrong),
        Err(Error::InvalidSignature)
    ));

    // A signature from a different key.
    let impostor = SigningKey::generate(ParameterSet::MlDsa65).unwrap();
    let (request, pending) = requester.blind(MSG).unwrap();
    let forged = impostor.blind_sign(&request).unwrap();
    assert!(matches!(
        pending.finalize(&forged),
        Err(Error::InvalidSignature)
    ));

    // Truncated and garbage responses.
    let (request, pending) = requester.blind(MSG).unwrap();
    let good = sk.blind_sign(&request).unwrap();
    let truncated = BlindResponse::from(&good.as_bytes()[..100]);
    assert!(matches!(
        pending.finalize(&truncated),
        Err(Error::InvalidLength { .. })
    ));
    let (_, pending) = requester.blind(MSG).unwrap();
    let garbage = BlindResponse::from(vec![0u8; ParameterSet::MlDsa65.signature_len()]);
    assert!(pending.finalize(&garbage).is_err());
}

#[test]
fn requests_hide_the_message() {
    let sk = SigningKey::generate(ParameterSet::MlDsa44).unwrap();
    let requester = Requester::new(sk.verifying_key().clone());
    let (a, _) = requester.blind(MSG).unwrap();
    let (b, _) = requester.blind(MSG).unwrap();
    // Fresh salt per request: the same message gives unrelated requests.
    assert_ne!(a, b);
    assert!(BlindRequest::from_bytes(&[0u8; 63]).is_err());
}

/// Executable statement of the documented limitation: the final signature
/// contains the very bytes the signer returned, so the signer can link it.
#[test]
fn signer_can_link_final_signature_to_its_response() {
    let sk = SigningKey::generate(ParameterSet::MlDsa44).unwrap();
    let (_, response, sig) = issue(&sk, &Context::default(), MSG);
    assert_eq!(response.as_bytes(), sig.ml_dsa_signature());
}

#[test]
fn key_encodings_round_trip() {
    let sk = SigningKey::generate(ParameterSet::MlDsa87).unwrap();
    let pk = sk.verifying_key();

    let sk2 = SigningKey::from_pkcs8_der(&sk.to_pkcs8_der().unwrap()).unwrap();
    let sk3 = SigningKey::from_pem(&sk.to_pem().unwrap()).unwrap();
    assert_eq!(sk2.verifying_key(), pk);
    assert_eq!(sk3.verifying_key(), pk);

    assert_eq!(&VerifyingKey::from_der(&pk.to_der().unwrap()).unwrap(), pk);
    assert_eq!(&VerifyingKey::from_pem(&pk.to_pem().unwrap()).unwrap(), pk);
    assert_eq!(
        &VerifyingKey::from_bytes(ParameterSet::MlDsa87, pk.as_bytes()).unwrap(),
        pk
    );
    assert!(VerifyingKey::from_bytes(ParameterSet::MlDsa65, pk.as_bytes()).is_err());

    // A signature issued under the reloaded key verifies under the original.
    let (_, _, sig) = issue(&sk2, &Context::default(), MSG);
    pk.verify(&Context::default(), MSG, &sig).unwrap();
}

#[test]
fn rejects_non_ml_dsa_keys() {
    let ed = native_ossl::pkey::KeygenCtx::new(c"ED25519")
        .unwrap()
        .generate()
        .unwrap();
    assert!(matches!(
        SigningKey::from_pkey(ed),
        Err(Error::UnsupportedKey)
    ));
}

/// The signer is hedged: answering the same request twice yields different,
/// equally valid signatures.  A deterministic signer would repeat itself,
/// which is what differential fault attacks exploit.
#[test]
fn signing_is_hedged() {
    let sk = SigningKey::generate(ParameterSet::MlDsa44).unwrap();
    let pk = sk.verifying_key();
    let (request, pending) = Requester::new(pk.clone()).blind(MSG).unwrap();
    let a = sk.blind_sign(&request).unwrap();
    let b = sk.blind_sign(&request).unwrap();
    assert_ne!(a, b);

    // Both are valid ML-DSA signatures on the same mu.
    let params = ParamBuilder::new()
        .unwrap()
        .push_int(c"mu", 1)
        .unwrap()
        .build()
        .unwrap();
    let alg = SigAlg::fetch(c"ML-DSA-44", None).unwrap();
    let mut verifier = MessageVerifier::new(pk.pkey(), &alg, Some(&params)).unwrap();
    assert!(verifier.verify(request.as_bytes(), b.as_bytes()).unwrap());
    pending.finalize(&a).unwrap();
}
