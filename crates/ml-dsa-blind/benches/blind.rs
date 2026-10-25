//! Blind signing: the message-hiding flow the voucher path runs.
//!
//! Each parameter set pays for the `ML-DSA-MU` digest twice on the requester
//! side (once when the salt is picked, once when the signature is finalized),
//! one blinded signing on the signer, and one ordinary ML-DSA verification on
//! the verifier. Sizes sweep the payloads a voucher actually carries.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kuipa_perf::{Profile, SplitMix64};
use ml_dsa_blind::{BlindRequest, Context, ParameterSet, Requester, SigningKey, VerifyingKey};
use std::hint::black_box;

/// Message sizes: a voucher claim body, an enrollment request, and the
/// largest thing the flow is likely to hide.
fn sizes() -> Vec<usize> {
    if Profile::from_env().name == "smoke" {
        vec![64, 1024]
    } else {
        vec![64, 1024, 8192]
    }
}

/// The parameter set's name, for bench ids.
fn label(ps: ParameterSet) -> &'static str {
    match ps {
        ParameterSet::MlDsa44 => "ML-DSA-44",
        ParameterSet::MlDsa65 => "ML-DSA-65",
        ParameterSet::MlDsa87 => "ML-DSA-87",
    }
}

fn message(len: usize) -> Vec<u8> {
    let mut rng = SplitMix64::new(0xb1ad);
    rng.bytes(len)
}

/// Deterministic keys per parameter set: the blind signer's identity is fixed
/// for the whole bench, so the measured work is the protocol, not keygen.
fn keys(ps: ParameterSet) -> (SigningKey, VerifyingKey) {
    let key = SigningKey::generate(ps).expect("generate");
    let public = key.verifying_key().clone();
    (key, public)
}

fn request(c: &mut Criterion) {
    let mut g = c.benchmark_group("blind/request");
    for ps in ParameterSet::ALL {
        let (_, public) = keys(ps);
        let requester = Requester::new(public);
        for len in sizes() {
            let msg = message(len);
            g.throughput(Throughput::Bytes(len as u64));
            g.bench_function(format!("{}-{len}", label(ps)), |b| {
                b.iter(|| requester.blind(black_box(&msg)).expect("blind"));
            });
        }
    }
    g.finish();
}

fn sign(c: &mut Criterion) {
    let mut g = c.benchmark_group("blind/sign");
    for ps in ParameterSet::ALL {
        let (key, public) = keys(ps);
        let msg = message(1024);
        let (req, _) = Requester::new(public).blind(&msg).expect("blind");
        g.throughput(Throughput::Elements(1));
        g.bench_with_input(
            BenchmarkId::from_parameter(label(ps)),
            &key,
            &mut |b: &mut criterion::Bencher<'_>, key: &SigningKey| {
                b.iter(|| key.blind_sign(black_box(&req)).expect("blind_sign"));
            },
        );
    }
    g.finish();
}

/// Finalizing a blinded response. `resume` recomputes `mu` from the message
/// and salt — which is exactly what a client that has been offline does — so
/// this measures the client's whole post-signature cost.
fn finalize(c: &mut Criterion) {
    let mut g = c.benchmark_group("blind/finalize");
    for ps in ParameterSet::ALL {
        let (key, public) = keys(ps);
        let requester = Requester::new(public);
        let msg = message(1024);
        let (req, pending) = requester.blind(&msg).expect("blind");
        let salt = pending.salt().to_vec();
        let response = key.blind_sign(&req).expect("blind_sign");
        g.throughput(Throughput::Elements(1));
        g.bench_function(label(ps), |b| {
            b.iter(|| {
                requester
                    .resume(black_box(&msg), black_box(&salt))
                    .expect("resume")
                    .finalize(black_box(&response))
                    .expect("finalize")
            });
        });
    }
    g.finish();
}

fn verify(c: &mut Criterion) {
    let mut g = c.benchmark_group("blind/verify");
    for ps in ParameterSet::ALL {
        let (key, public) = keys(ps);
        let ctx = Context::new(b"ipa-ku-enroll/v1 voucher").expect("context");
        let requester = Requester::with_context(public.clone(), ctx.clone());
        let msg = message(1024);
        let (req, pending) = requester.blind(&msg).expect("blind");
        let response = key.blind_sign(&req).expect("blind_sign");
        let sig = pending.finalize(&response).expect("finalize");
        g.throughput(Throughput::Bytes(sig.ml_dsa_signature().len() as u64));
        g.bench_with_input(
            BenchmarkId::from_parameter(label(ps)),
            &public,
            &mut |b: &mut criterion::Bencher<'_>, public: &VerifyingKey| {
                b.iter(|| {
                    public
                        .verify(black_box(&ctx), black_box(&msg), black_box(&sig))
                        .expect("verify");
                });
            },
        );
    }
    g.finish();
}

/// The client's end-to-end cost: pick a salt, digest to `mu`, finalize,
/// verify. The signer's work is excluded because it is a different machine —
/// except here, where the point is the full round trip's wall time.
fn round_trip(c: &mut Criterion) {
    let mut g = c.benchmark_group("blind/round-trip");
    for ps in ParameterSet::ALL {
        let (key, public) = keys(ps);
        let ctx = Context::new(b"ipa-ku-enroll/v1 voucher").expect("context");
        let requester = Requester::with_context(public.clone(), ctx.clone());
        for len in sizes() {
            let msg = message(len);
            g.throughput(Throughput::Bytes(len as u64));
            g.bench_function(format!("{}-{len}", label(ps)), |b| {
                b.iter(|| {
                    let (req, pending) = requester.blind(black_box(&msg)).expect("blind");
                    let response = key.blind_sign(&req).expect("blind_sign");
                    let sig = pending.finalize(&response).expect("finalize");
                    public.verify(&ctx, &msg, &sig).expect("verify");
                    sig.ml_dsa_signature().len()
                });
            });
        }
    }
    g.finish();
}

/// Wire encoding: a blinded request is one `mu`, and a blind signature is a
/// salt plus an ML-DSA signature. Servers parse the former, clients the
/// latter out of vouchers.
fn encode(c: &mut Criterion) {
    let mut g = c.benchmark_group("blind/encode");
    for ps in ParameterSet::ALL {
        let (key, public) = keys(ps);
        let requester = Requester::new(public);
        let msg = message(1024);
        let (req, pending) = requester.blind(&msg).expect("blind");
        let response = key.blind_sign(&req).expect("blind_sign");
        let sig = pending.finalize(&response).expect("finalize");
        let req_bytes = req.as_bytes().to_vec();
        g.throughput(Throughput::Bytes(sig.to_bytes().len() as u64));
        g.bench_function(format!("request/parse-{}", label(ps)), |b| {
            b.iter(|| BlindRequest::from_bytes(black_box(&req_bytes)).is_ok());
        });
        g.bench_function(format!("signature/encode-{}", label(ps)), |b| {
            b.iter(|| black_box(&sig).to_bytes().len());
        });
        // The signed message a voucher carries is salt ‖ message: the salt is
        // prepended on every enrollment response.
        g.throughput(Throughput::Bytes(msg.len() as u64));
        g.bench_function(format!("signed-message-{}", label(ps)), |b| {
            b.iter(|| black_box(&sig).signed_message(black_box(&msg)).len());
        });
    }
    g.finish();
}

/// Context construction: domain separation strings are copied and truncated
/// to `MAX_LEN`, which every sign/verify path repeats.
fn context(c: &mut Criterion) {
    let mut g = c.benchmark_group("context");
    let mut rng = SplitMix64::new(0xc0fe);
    let short = rng.bytes(32);
    let long = rng.bytes(1024);
    g.throughput(Throughput::Bytes(short.len() as u64));
    g.bench_function("new-32", |b| {
        b.iter(|| Context::new(black_box(short.clone())).is_ok());
    });
    g.throughput(Throughput::Bytes(long.len() as u64));
    g.bench_function("new-truncated", |b| {
        b.iter(|| Context::new(black_box(long.clone())).is_ok());
    });
    g.finish();
}

criterion_group!(benches, request, sign, finalize, verify, round_trip, encode, context);
criterion_main!(benches);
