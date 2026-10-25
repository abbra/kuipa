//! Sealed keytabs: the escrow costs a host pays to protect its keytab, and
//! a recovery operator pays to get it back.
//!
//! The scaling axis is the number of escrow servers — each one costs the
//! host a KEM encapsulation at seal time, and one server's recovery attempt
//! at unseal time.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use kuipa_enroll::escrow::{BindingHash, EscrowRequest, Kind, Sealed, Sealer};
use kuipa_enroll::join::Operation;
use kuipa_enroll::keytab::{Keytab, Principal};
use kuipa_enroll::realm::VerifiedRealm;
use kuipa_enroll::server::Directory;
use kuipa_enroll::vault::Recovered;
use kuipa_perf::realm::realm;
use kuipa_perf::{HOST, Profile, REALM, Realm, SplitMix64, server_name};
use std::hint::black_box;

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

/// Fan-out to sweep.  Each slot is a whole server realm — keygen, trust
/// exchange, advertisement — so the axis stops at 32 instead of following
/// `Profile::sweep` into the hundreds.
fn fan_out(p: &Profile) -> Vec<usize> {
    p.sweep(p.escrow_servers)
        .into_iter()
        .filter(|n| *n <= 32)
        .collect()
}
/// Verified realms plus a keytab the host just joined with.
fn escrow_fixture(r: &Realm, servers: usize) -> (Vec<VerifiedRealm>, Keytab) {
    let advs: Vec<VerifiedRealm> = (0..servers).map(|i| r.verify(i)).collect();
    let mut rng = SplitMix64::new(0x5c0e0);
    let otp = rng.bytes(8);
    r.dir.set_otp(HOST, &otp);
    let (request, pending) = r.otp_request(&advs[0], &otp);
    let keytab = pending
        .finish(&r.send(0, Operation::Join, &request), &advs[0])
        .expect("join")
        .keytab;
    (advs, keytab)
}

/// Sealing across `servers` escrow servers: one encapsulation each.
fn seal(c: &mut Criterion) {
    let p = profile();
    sweep(c, "escrow/seal", &fan_out(&p), |g, servers| {
        let r = realm(&p.clone().with_escrow_servers(servers));
        let (advs, keytab) = escrow_fixture(&r, servers);
        let refs: Vec<&VerifiedRealm> = advs.iter().collect();
        let (sealed, _) = Sealed::seal(&keytab, &refs).expect("seal");
        g.throughput(Throughput::Bytes(sealed.to_bytes().len() as u64));
        g.bench_function(format!("seal/{servers}"), |b| {
            b.iter(|| {
                let (prepared, _) = Sealer::prepare(
                    black_box(&Principal::host(HOST, REALM)),
                    black_box(Kind::Keytab),
                    black_box(&refs),
                )
                .expect("prepare");
                prepared.seal(black_box(&keytab)).expect("seal")
            });
        });
    });
}

/// Recovering a sealed keytab.  Recovery answers only from the *last*
/// server, so every slot is tried first: the honest worst case.
fn unseal(c: &mut Criterion) {
    let p = profile();
    sweep(c, "escrow/unseal", &fan_out(&p), |g, servers| {
        let r = realm(&p.clone().with_escrow_servers(servers));
        let (advs, keytab) = escrow_fixture(&r, servers);
        let refs: Vec<&VerifiedRealm> = advs.iter().collect();
        let (sealed, registrations) = Sealed::seal(&keytab, &refs).expect("seal");
        let bindings: Vec<BindingHash> = registrations.iter().map(|reg| reg.binding).collect();
        r.dir
            .register_escrow(&Principal::host(HOST, REALM), &bindings)
            .expect("register");
        let last = servers - 1;
        g.throughput(Throughput::Bytes(sealed.to_bytes().len() as u64));
        g.bench_function(format!("unseal/{servers}"), |b| {
            b.iter(|| {
                sealed
                    .unseal(|name, request| {
                        if name != server_name(last) {
                            return None;
                        }
                        let request =
                            EscrowRequest::from_bytes(&request.to_bytes()).expect("parse request");
                        r.servers[last]
                            .recover(black_box(&request), r.directory())
                            .ok()
                            .and_then(Recovered::into_plain)
                    })
                    .expect("unseal")
            });
        });
    });
}

/// The sealed-blob encoding.
fn wire(c: &mut Criterion) {
    let p = profile();
    let r = realm(&p);
    let (advs, keytab) = escrow_fixture(&r, p.escrow_servers.min(r.servers.len()));
    let refs: Vec<&VerifiedRealm> = advs.iter().collect();
    let (sealed, _) = Sealed::seal(&keytab, &refs).expect("seal");
    let bytes = sealed.to_bytes();

    let mut g = c.benchmark_group("escrow/wire");
    g.throughput(Throughput::Bytes(bytes.len() as u64));
    g.bench_function("encode", |b| b.iter(|| black_box(&sealed).to_bytes()));
    g.bench_function("decode", |b| {
        b.iter(|| Sealed::from_bytes(black_box(&bytes)).expect("decode"));
    });
    g.finish();
}

criterion_group!(benches, seal, unseal, wire);
criterion_main!(benches);
