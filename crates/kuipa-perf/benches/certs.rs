//! Certificate-authority costs: what a deployment pays to mint the CA
//! certificates it pins, per kind, including the post-quantum CA that
//! `pqproduction` uses.
//!
//! Key generation is nondeterministic for RSA and EC (OpenSSL draws its own
//! randomness) and deterministic for ML-DSA-65 from a fixed seed, so sizes
//! are stable and timings comparable across runs.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use kuipa_perf::CaKind;
use kuipa_perf::certs::{chain, generate, key, self_signed};
use std::hint::black_box;

fn kinds() -> [CaKind; 3] {
    [CaKind::Rsa2048, CaKind::EcP256, CaKind::MlDsa65]
}

fn keygen(c: &mut Criterion) {
    let mut g = c.benchmark_group("ca/keygen");
    for kind in kinds() {
        g.bench_with_input(BenchmarkId::new(kind.name(), 1), &kind, |b, kind| {
            b.iter(|| key(black_box(*kind)).expect("keygen"));
        });
    }
    g.finish();
}

fn signing(c: &mut Criterion) {
    let mut g = c.benchmark_group("ca/self-sign");
    for kind in kinds() {
        let k = key(kind).expect("keygen");
        let der = generate(kind, "ipa-ca.example.test").expect("cert").der;
        g.throughput(Throughput::Bytes(der.len() as u64));
        g.bench_with_input(BenchmarkId::new(kind.name(), 1), &k, |b, k| {
            b.iter(|| {
                self_signed(black_box(k), black_box(kind), "ipa-ca.example.test").expect("sign");
            });
        });
    }
    g.finish();
}

fn chain_cost(c: &mut Criterion) {
    let mut g = c.benchmark_group("ca/chain");
    for kind in kinds() {
        for count in [1usize, 4] {
            let der = generate(kind, "ipa-ca.example.test").expect("cert").der;
            g.throughput(Throughput::Bytes(der.len() as u64 * count as u64));
            g.bench_with_input(BenchmarkId::new(kind.name(), count), &kind, |b, kind| {
                b.iter(|| chain(black_box(*kind), black_box(count)).expect("chain"));
            });
        }
    }
    g.finish();
}

criterion_group!(benches, keygen, signing, chain_cost);
criterion_main!(benches);
