//! Anchor-state costs: the ledger a server carries and the trust it computes
//! from it.
//!
//! These scale with the deployment's *history* — claims admitted, leaves a
//! vouch covers, proofs a delegation carries — so they use the synthetic
//! [`Ledger`] fixture rather than a realm, and sweep on ledger size.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use kuipa_enroll::anchors::{AnchorState, Entry, Trust};
use kuipa_enroll::delegation::{Claim, Delegation, SignedVouch, VOUCH_VALIDITY};
use kuipa_perf::ledger::ledger;
use kuipa_perf::{Profile, SplitMix64, now, server_name};
use std::collections::BTreeSet;
use std::hint::black_box;
use tang_pqc::Thumbprint;

fn profile() -> Profile {
    Profile::from_env()
}

fn sweep(
    c: &mut Criterion,
    group: &str,
    sizes: &[usize],
    mut f: impl FnMut(&mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>, usize),
) {
    let mut g = c.benchmark_group(group);
    for size in sizes {
        f(&mut g, *size);
    }
    g.finish();
}

/// Issuing a vouch, verifying one, and extracting a claim's proof, as the
/// leaf count of the anchor's tree grows.
fn vouch(c: &mut Criterion) {
    let p = profile();
    sweep(c, "vouch/issue", &p.sweep(p.leaves), |g, leaves| {
        let l = ledger(p.leaves.min(leaves), 1, leaves);
        g.throughput(Throughput::Bytes(32 * leaves as u64));
        g.bench_function(format!("issue/{leaves}"), |b| {
            b.iter(|| {
                SignedVouch::issue(
                    black_box(&l.anchors[0]),
                    black_box(kuipa_perf::REALM),
                    l.leaves(),
                    black_box(now() - 60),
                    black_box(now() + VOUCH_VALIDITY),
                    black_box(None),
                )
                .expect("issue")
            });
        });
    });

    sweep(c, "vouch/verify", &p.sweep(p.leaves), |g, leaves| {
        let l = ledger(p.leaves.min(leaves), 1, leaves);
        let v = l.vouch(0);
        let key = l.key(0).clone();
        let policy = l.policy.clone();
        g.throughput(Throughput::Bytes(v.to_bytes().len() as u64));
        g.bench_function(format!("verify/{leaves}"), |b| {
            b.iter(|| {
                v.verify(black_box(&key), black_box(&policy))
                    .expect("verify");
            });
        });
    });

    sweep(c, "vouch/proof", &p.sweep(p.leaves), |g, leaves| {
        let l = ledger(p.leaves.min(leaves), 1, leaves);
        let v = l.vouch(0);
        let claim = l.own().clone();
        let key = l.key(0).clone();
        g.bench_function(format!("proof/{leaves}"), |b| {
            b.iter(|| v.proof(black_box(&claim), black_box(&key)).expect("proof"));
        });
    });
}

/// Admitting claims to a state, and the state's wire encoding.
fn state(c: &mut Criterion) {
    let p = profile();
    sweep(c, "anchor-state/put", &p.sweep(p.leaves), |g, claims| {
        let l = ledger(claims, 1, claims);
        let mut rng = SplitMix64::new(0xfeed);
        let fresh: Vec<Claim> = (0..claims)
            .map(|i| Claim {
                realm: kuipa_perf::REALM.to_owned(),
                server: server_name(1_000 + i),
                anchor: Some(*l.anchors[0].public().thumbprint()),
                key: Thumbprint::from_bytes(rng.bytes(32).try_into().expect("32 bytes")),
                iat: now() - 60,
                exp: now() + 30 * 86400,
            })
            .collect();
        g.bench_function(format!("put/{claims}"), |b| {
            b.iter(|| {
                let mut s = l.state.clone();
                for claim in &fresh {
                    s.put(
                        Entry::Claim(claim.clone()),
                        black_box(kuipa_perf::REALM),
                        black_box(&l.policy),
                        black_box(now()),
                        black_box(&l.clock),
                    )
                    .expect("put");
                }
                s.len()
            });
        });
    });

    sweep(c, "anchor-state/wire", &p.sweep(p.leaves), |g, claims| {
        let l = ledger(claims, 1, claims);
        let bytes = l.state.to_bytes();
        g.throughput(Throughput::Bytes(bytes.len() as u64));
        g.bench_function(format!("encode/{claims}"), |b| {
            b.iter(|| black_box(&l.state).to_bytes());
        });
        g.bench_function(format!("decode/{claims}"), |b| {
            b.iter(|| AnchorState::from_bytes(black_box(&bytes)).expect("decode"));
        });
    });
}

/// Computing trust over a ledger whose claim count grows.
fn trust(c: &mut Criterion) {
    let p = profile();
    sweep(c, "trust/compute", &p.sweep(p.leaves), |g, claims| {
        let l = ledger(claims, 1, claims);
        let own = l.own().clone();
        let attested: Vec<Delegation> = l
            .claims
            .iter()
            .skip(1)
            .take(p.attested)
            .map(Delegation::new)
            .collect();
        let members: BTreeSet<String> = l.members.clone();
        g.bench_function(format!("compute/{claims}"), |b| {
            b.iter(|| {
                Trust::compute(
                    black_box(&l.state),
                    black_box(&own),
                    black_box(&attested),
                    black_box(&members),
                    black_box(&l.policy),
                    black_box(now()),
                )
                .expect("compute")
            });
        });
    });
}

/// Verifying a delegation that carries one proof per trusted anchor.
fn delegation_verify(c: &mut Criterion) {
    let p = profile();
    sweep(c, "delegation/verify", &p.sweep(2), |g, anchors| {
        let l = ledger(p.leaves.max(anchors), anchors, p.leaves.max(anchors));
        let mut d = Delegation::new(l.own());
        for i in 0..anchors {
            d.add(l.vouch(i).proof(l.own(), l.key(i)).expect("proof"));
        }
        let thumbs = l.thumbs();
        let policy = l.policy.clone();
        g.throughput(Throughput::Bytes(d.to_json().len() as u64));
        g.bench_function(format!("verify_at/{anchors}"), |b| {
            b.iter(|| {
                d.verify_at(black_box(&thumbs), black_box(&policy), black_box(now()))
                    .expect("verify")
            });
        });
    });
}

criterion_group!(benches, vouch, state, trust, delegation_verify);
criterion_main!(benches);
