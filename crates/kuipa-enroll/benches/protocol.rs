//! The client and server halves of the enrollment flows: advertisement
//! serve/verify, OTP and Kerberos joins, rekey.
//!
//! Each round-trip bench measures the whole exchange a host pays for: seal a
//! request, encode/decode it, have the server answer through the directory,
//! open the response.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use kuipa_enroll::join::{AuthType, Operation, Prepared, Request, Response};
use kuipa_enroll::keytab::Enctype;
use kuipa_enroll::keytab::Principal;
use kuipa_enroll::realm::VerifiedRealm;
use kuipa_perf::realm::{realm, realm_with};
use kuipa_perf::{HOST, Profile, SplitMix64, fake_binding, gss_token, now};
use std::hint::black_box;
use std::time::SystemTime;
use tang_pqc::{Policy, SignedAdvertisement};

fn profile() -> Profile {
    Profile::from_env()
}

/// CA certificates to sweep.  An ML-DSA-65 certificate is ~20 KiB, and
/// `tang-pqc` refuses to parse an advertisement over 256 KiB, so 8 is as
/// deep as a post-quantum chain can go; a deeper sweep would measure a
/// refusal, not verification.
fn ca_axis(p: &Profile) -> Vec<usize> {
    p.sweep(p.ca_certs)
        .into_iter()
        .filter(|n| *n <= 8)
        .collect()
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

/// Serving an advertisement: sign it fresh, serve it from the cache.
fn advertisement(c: &mut Criterion) {
    let p = profile();
    let r = realm(&p);
    let pinned = r.pinned();
    let server = &r.servers[0];
    let delegation = server.delegation();
    let adv = r.advertisement(0);

    let mut g = c.benchmark_group("advertisement/build");
    g.throughput(Throughput::Bytes(adv.to_json().len() as u64));
    g.bench_function("sign", |b| {
        b.iter(|| {
            server
                .keys()
                .advertisement(
                    server.info(),
                    &delegation,
                    now(),
                    now() + 3600,
                    server.epoch_head(),
                )
                .expect("advertise")
        });
    });
    g.bench_function("cached", |b| {
        b.iter(|| server.advertisement(black_box(&pinned)).expect("advertise"));
    });
    g.finish();

    let json = adv.to_json();
    let mut g = c.benchmark_group("advertisement/wire");
    g.throughput(Throughput::Bytes(json.len() as u64));
    g.bench_function("encode", |b| b.iter(|| black_box(&adv).to_json()));
    g.bench_function("parse", |b| {
        b.iter(|| SignedAdvertisement::from_json(black_box(json.as_bytes())).expect("parse"));
    });
    g.finish();
}

/// What a client does with `GET /adv`, scaling with the CA certificates the
/// advertisement carries and the directory hands out.
fn verify(c: &mut Criterion) {
    let p = profile();
    let policy = Policy::default();

    sweep(c, "realm/verify", &ca_axis(&p), |g, ca_certs| {
        let r = realm_with(&p.clone().with_ca_certs(ca_certs), p.ca);
        let json = r.advertisement(0).to_json();
        let adv = SignedAdvertisement::from_json(json.as_bytes()).expect("parse");
        let pinned = r.pinned();
        g.throughput(Throughput::Bytes(json.len() as u64));
        g.bench_function(format!("verify/{ca_certs}"), |b| {
            b.iter(|| {
                VerifiedRealm::verify(
                    black_box(&adv),
                    black_box(kuipa_perf::REALM),
                    black_box(&pinned),
                    black_box(&policy),
                    black_box(SystemTime::now()),
                )
                .expect("verify")
            });
        });
    });
}

/// An OTP join, end to end.
fn join_otp(c: &mut Criterion) {
    let p = profile();
    let r = realm(&p);
    let adv = r.verify(0);
    let mut rng = SplitMix64::new(0x070_500);
    let otp = rng.bytes(8);

    let mut g = c.benchmark_group("join/otp");
    g.bench_function("round-trip", |b| {
        b.iter(|| {
            r.dir.set_otp(HOST, &otp);
            let (request, pending) = r.otp_request(&adv, &otp);
            let response = r.send(0, Operation::Join, &request);
            pending.finish(&response, &adv).expect("finish").keytab
        });
    });
    g.finish();
}

/// A Kerberos-authenticated join, end to end: the directory does acceptor
/// work per request.
fn join_gss(c: &mut Criterion) {
    let p = profile();
    let r = realm(&p);
    let adv = r.verify(0);

    let mut g = c.benchmark_group("join/gss");
    g.bench_function("round-trip", |b| {
        b.iter(|| {
            let (request, pending, _, _) = r.gss_request(&adv);
            let response = r.send(0, Operation::Join, &request);
            pending.finish(&response, &adv).expect("finish").keytab
        });
    });
    g.finish();
}

/// The request/response wire encoding alone, at join size.
fn join_wire(c: &mut Criterion) {
    let p = profile();
    let r = realm(&p);
    let adv = r.verify(0);
    let (request, _) = r.otp_request(&adv, b"Secret123");
    let request_bytes = request.to_bytes();
    let response = r.send(0, Operation::Join, &request);
    let response_bytes = response.to_bytes();

    let mut g = c.benchmark_group("join/wire");
    g.throughput(Throughput::Bytes(request_bytes.len() as u64));
    g.bench_function("request/encode", |b| {
        b.iter(|| black_box(&request).to_bytes());
    });
    g.bench_function("request/decode", |b| {
        b.iter(|| {
            Request::from_bytes(Operation::Join, black_box(&request_bytes)).expect("parse request")
        });
    });
    g.throughput(Throughput::Bytes(response_bytes.len() as u64));
    g.bench_function("response/encode", |b| {
        b.iter(|| black_box(&response).to_bytes());
    });
    g.bench_function("response/decode", |b| {
        b.iter(|| Response::from_bytes(black_box(&response_bytes)).expect("parse response"));
    });
    g.finish();
}

/// A host rekeying itself, end to end.
fn rekey(c: &mut Criterion) {
    let p = profile();
    let r = realm(&p);
    let adv = r.verify(0);
    let host = Principal::host(HOST, kuipa_perf::REALM).to_string();

    let mut g = c.benchmark_group("rekey/gss");
    g.bench_function("round-trip", |b| {
        b.iter(|| {
            let prepared = Prepared::new(
                &adv,
                Operation::Rekey,
                HOST,
                AuthType::Kerberos,
                &Enctype::DEFAULT,
            )
            .expect("prepare");
            let cb = prepared.channel_binding().expect("channel binding");
            let prepared = prepared.with_kerberos(fake_binding(&host, &cb));
            let (request, pending) = prepared
                .seal(&gss_token(&host, &cb), &[], &[])
                .expect("seal");
            let response = r.send(0, Operation::Rekey, &request);
            pending.finish(&response, &adv).expect("finish").keytab
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    advertisement,
    verify,
    join_otp,
    join_gss,
    join_wire,
    rekey
);
criterion_main!(benches);
