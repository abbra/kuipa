//! Cryptographic primitives: the per-operation costs every protocol flow is
//! built from.
//!
//! These run directly against `tang-pqc`, voucher signing and OpenSSL, so
//! they measure the provider's own work — signing, verification,
//! encapsulation, tree hashing — at the parameter sets `kuipa` negotiates.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use kuipa_enroll::keytab::{Enctype, Keytab, KeytabEntry, Principal};
use kuipa_enroll::merkle;
use kuipa_enroll::voucher::{Claims, SIGN_CONTEXT, Voucher, alg_name, binding as voucher_binding};
use kuipa_perf::realm::realm;
use kuipa_perf::{CaKind, HOST, Profile, REALM, SplitMix64, certs, chain};
use native_ossl::util::SecretBuf;
use native_ossl::x509::X509;
use std::hint::black_box;
use tang_pqc::primitives::{digest, open, seal, sha256};
use tang_pqc::{ExchangeKeyPair, KemAlg, Policy, SignatureAlg, SigningKey};

fn profile() -> Profile {
    Profile::from_env()
}

fn name(kind: CaKind) -> &'static str {
    kind.name()
}
/// The KEM parameter set's name, for bench ids.
fn kem_name(alg: KemAlg) -> &'static str {
    alg.jose_name()
}

/// A keytab of `entries` entries for the fixture host.
fn keytab(entries: usize) -> Keytab {
    let mut rng = SplitMix64::new(0x6e7a);
    Keytab::new(
        Principal::host(HOST, REALM),
        (0..entries)
            .map(|i| KeytabEntry {
                kvno: u32::try_from(i % 10).expect("kvno fits") + 1,
                enctype: Enctype::DEFAULT[i % Enctype::DEFAULT.len()],
                key: SecretBuf::new(rng.bytes(32)),
                timestamp: 0,
            })
            .collect(),
    )
}

fn signing(c: &mut Criterion) {
    let message = {
        let mut rng = SplitMix64::new(0xbeef);
        rng.bytes(1024)
    };

    let mut g = c.benchmark_group("ml-dsa/sign");
    for alg in SignatureAlg::ALL {
        let key = SigningKey::generate(alg).expect("generate");
        g.throughput(Throughput::Elements(1));
        g.bench_function(alg_name(alg), |b| {
            b.iter(|| key.sign(black_box(&message)).expect("sign"));
        });
    }
    g.finish();

    let mut g = c.benchmark_group("ml-dsa/verify");
    for alg in SignatureAlg::ALL {
        let key = SigningKey::generate(alg).expect("generate");
        let signature = key.sign(&message).expect("sign");
        let public = key.public().clone();
        g.bench_function(alg_name(alg), |b| {
            b.iter(|| {
                public
                    .verify(black_box(&message), black_box(&signature))
                    .expect("verify");
            });
        });
    }
    g.finish();

    // A delegation body is what a server signs per advertisement: a few
    // hundred bytes of JSON, not a synthetic blob.
    let p = profile();
    let r = realm(&p);
    let delegation = r.servers[0].delegation().to_json().into_bytes();
    let mut g = c.benchmark_group("ml-dsa/sign-delegation");
    for alg in SignatureAlg::ALL {
        let key = SigningKey::generate(alg).expect("generate");
        g.throughput(Throughput::Bytes(delegation.len() as u64));
        g.bench_function(alg_name(alg), |b| {
            b.iter(|| key.sign(black_box(&delegation)).expect("sign"));
        });
    }
    g.finish();
}

fn kem(c: &mut Criterion) {
    let mut g = c.benchmark_group("ml-kem/encapsulate");
    for alg in KemAlg::ALL {
        let pair = ExchangeKeyPair::generate(alg).expect("generate");
        let public = pair.public().clone();
        g.bench_function(kem_name(alg), |b| {
            b.iter(|| public.encapsulate().expect("encapsulate"));
        });
    }
    g.finish();

    let mut g = c.benchmark_group("ml-kem/decapsulate");
    for alg in KemAlg::ALL {
        let pair = ExchangeKeyPair::generate(alg).expect("generate");
        let (ct, _) = pair.public().encapsulate().expect("encapsulate");
        g.bench_function(kem_name(alg), |b| {
            b.iter(|| pair.decapsulate(black_box(&ct)).expect("decapsulate"));
        });
    }
    g.finish();

    // Keygen is fixture setup in the protocol benches, but it is the cost of
    // a new enrollment or a key rotation, so it earns its own number.
    let mut g = c.benchmark_group("keygen");
    for alg in SignatureAlg::ALL {
        let label = alg_name(alg);
        g.bench_function(format!("signing/{label}"), |b| {
            b.iter(|| SigningKey::generate(black_box(alg)).expect("generate"));
        });
    }
    for alg in KemAlg::ALL {
        let label = kem_name(alg);
        g.bench_function(format!("exchange/{label}"), |b| {
            b.iter(|| ExchangeKeyPair::generate(black_box(alg)).expect("generate"));
        });
    }
    g.finish();
}

fn trees(c: &mut Criterion) {
    let p = profile();
    let mut g = c.benchmark_group("merkle");
    // SHA-256: the tree the ML-DSA-44/65 anchors sign under, which is what a
    // realm's vouches carry (§4.3).
    let alg = merkle::TreeHash::Sha256;
    for leaves in p.sweep(p.leaves) {
        let claims: Vec<Vec<u8>> = (0..leaves)
            .map(|i| format!("claim for ipa{}.example.test", i + 1).into_bytes())
            .collect();
        let leaf_hashes: Vec<merkle::Hash> = claims
            .iter()
            .map(|c| merkle::leaf_hash(alg, c).expect("leaf"))
            .collect();
        let root = merkle::root(&leaf_hashes).expect("root");
        let path = merkle::path(&leaf_hashes, leaves - 1).expect("path");
        let last = leaf_hashes[leaves - 1];
        g.throughput(Throughput::Elements(leaves as u64));
        g.bench_function(format!("leaf/{leaves}"), |b| {
            b.iter(|| {
                claims
                    .iter()
                    .map(|c| merkle::leaf_hash(alg, black_box(c)).expect("leaf"))
                    .collect::<Vec<_>>()
            });
        });
        g.bench_function(format!("root/{leaves}"), |b| {
            b.iter(|| merkle::root(black_box(&leaf_hashes)).expect("root"));
        });
        g.bench_function(format!("path/{leaves}"), |b| {
            b.iter(|| merkle::path(black_box(&leaf_hashes), leaves - 1).expect("path"));
        });
        g.bench_function(format!("verify/{leaves}"), |b| {
            b.iter(|| {
                merkle::verify(
                    black_box(&last),
                    black_box(leaves as u64 - 1),
                    black_box(leaves as u64),
                    black_box(&path),
                    black_box(&root),
                )
                .expect("verify")
            });
        });
    }
    g.finish();
}

fn symmetric(c: &mut Criterion) {
    let mut rng = SplitMix64::new(0xcafe);
    let key = rng.bytes(32);
    let plaintext = rng.bytes(1024);
    let sealed = seal(&key, &plaintext).expect("seal");
    let big = rng.bytes(8192);
    let sealed_big = seal(&key, &big).expect("seal");
    let ephemeral = rng.bytes(KemAlg::MlKem768.encapsulation_key_len());

    let mut g = c.benchmark_group("aead/1KiB");
    g.throughput(Throughput::Bytes(plaintext.len() as u64));
    g.bench_function("seal", |b| {
        b.iter(|| seal(black_box(&key), black_box(&plaintext)).expect("seal"));
    });
    g.bench_function("open", |b| {
        b.iter(|| open(black_box(&key), black_box(&sealed)).expect("open"));
    });
    g.finish();

    // Enrollment responses are a few KiB of wrapped keytab plus proofs.
    let mut g = c.benchmark_group("aead/8KiB");
    g.throughput(Throughput::Bytes(big.len() as u64));
    g.bench_function("seal", |b| {
        b.iter(|| seal(black_box(&key), black_box(&big)).expect("seal"));
    });
    g.bench_function("open", |b| {
        b.iter(|| open(black_box(&key), black_box(&sealed_big)).expect("open"));
    });
    g.finish();

    let mut g = c.benchmark_group("hash");
    g.throughput(Throughput::Bytes(plaintext.len() as u64));
    g.bench_function("sha256-1KiB", |b| {
        b.iter(|| sha256(black_box(&[&plaintext[..]])).expect("sha256"));
    });
    g.bench_function("digest-sha256-1KiB", |b| {
        b.iter(|| {
            digest(
                c"sha256",
                &[black_box(&plaintext[..]), b"domain separation"],
            )
            .expect("digest")
        });
    });
    g.throughput(Throughput::Elements(1));
    g.bench_function("voucher-binding", |b| {
        b.iter(|| voucher_binding(black_box(&ephemeral)).expect("binding"));
    });
    g.finish();
}

/// Voucher signing and verification: the per-enrollment cost of the voucher
/// flow, at each signature parameter set.
fn vouchers(c: &mut Criterion) {
    // A bound voucher: the claims carry the digest of the host's ephemeral
    // KEM key, which `verify` compares against what the request proves.
    // The validity window is an hour around `at`, as an issuer would set
    // it, so `verify` checks a window that can actually close.
    let ephemeral = voucher_binding(&[3u8; 1184]).expect("binding");
    let at = 1_700_000_000;
    let claims = Claims {
        realm: REALM.into(),
        fqdn: HOST.into(),
        hostgroup: "web".into(),
        not_before: at - 60,
        not_after: at + 3600,
        binding: ephemeral.clone(),
    };
    let message = claims.message();

    let mut g = c.benchmark_group("voucher");
    for alg in SignatureAlg::ALL {
        let key = SigningKey::generate(alg).expect("generate");
        let label = alg_name(alg);
        let salted = {
            let salt = [7u8; 32];
            let signed = [&salt[..], &message[..]].concat();
            let sig = key.sign_with_context(&signed, SIGN_CONTEXT).expect("sign");
            [&salt[..], &sig[..]].concat()
        };
        let v = Voucher::new(key.public().thumbprint(), claims.clone(), &salted).expect("voucher");
        let encoded = v.encode();
        let public = key.public().clone();
        g.throughput(Throughput::Elements(1));
        g.bench_function(format!("sign/{label}"), |b| {
            b.iter(|| {
                key.sign_with_context(black_box(&message), SIGN_CONTEXT)
                    .expect("sign")
            });
        });
        g.bench_function(format!("verify/{label}"), |b| {
            b.iter(|| {
                v.verify(&public, REALM, HOST, &ephemeral, at)
                    .map(|c| c.fqdn.clone())
                    .expect("verify")
            });
        });
        g.throughput(Throughput::Bytes(encoded.len() as u64));
        g.bench_function(format!("parse/{label}"), |b| {
            b.iter(|| Voucher::parse(black_box(encoded.as_ref())).expect("parse"));
        });
    }
    g.finish();
}

/// X.509 chain generation: the per-CA cost of a deployment bootstrap, and
/// the wire size each CA kind carries in an advertisement.
fn certificates(c: &mut Criterion) {
    let kinds = [CaKind::Rsa2048, CaKind::EcP256, CaKind::MlDsa65];

    let mut g = c.benchmark_group("cert/sign");
    for kind in kinds {
        let key = certs::key(kind).expect("CA key");
        let der = certs::self_signed(&key, kind, "Benchmark CA").expect("CA cert");
        g.throughput(Throughput::Bytes(der.len() as u64));
        g.bench_function(name(kind), |b| {
            b.iter(|| {
                certs::self_signed(black_box(&key), black_box(kind), "Benchmark CA").expect("cert")
            });
        });
    }
    g.finish();

    // Parsing a CA certificate is what kinit and the TLS stack do with the
    // bundle an enrollment writes (kuipa itself carries the DER as-is);
    // ML-DSA CAs are an order of magnitude larger than EC ones.
    let mut g = c.benchmark_group("cert/parse");
    for kind in kinds {
        let cas = chain(kind, 1).expect("CA chain");
        g.throughput(Throughput::Bytes(cas[0].len() as u64));
        g.bench_function(name(kind), |b| {
            b.iter(|| X509::from_der(black_box(&cas[0])).expect("parse"));
        });
    }
    g.finish();
}

/// Keytab round-trips: enrollment writes one, `ktgrab` reads it back.
fn keytabs(c: &mut Criterion) {
    let p = profile();
    let mut g = c.benchmark_group("keytab/mit");
    for entries in p.sweep(p.keytab_entries) {
        let kt = keytab(entries);
        let mit = kt.to_mit().expect("to_mit");
        g.throughput(Throughput::Elements(entries as u64));
        g.bench_function(format!("encode/{entries}"), |b| {
            b.iter(|| black_box(&kt).to_mit().expect("to_mit"));
        });
        g.bench_function(format!("decode/{entries}"), |b| {
            b.iter(|| Keytab::from_mit(black_box(mit.as_ref())).expect("from_mit"));
        });
    }
    g.finish();
}

/// Delegation JSON: the advertisement's largest member, and what clients and
/// servers re-parse on every fetch and every attestation.
fn delegation_json(c: &mut Criterion) {
    let p = profile();
    let r = realm(&p);
    let delegation = r.servers[0].delegation().clone();
    let json = delegation.to_json();
    let mut group = c.benchmark_group("delegation/json");
    group.throughput(Throughput::Bytes(json.len() as u64));
    group.bench_function("encode", |b| b.iter(|| black_box(&delegation).to_json()));
    group.bench_function("decode", |b| {
        b.iter(|| {
            kuipa_enroll::delegation::Delegation::from_json(black_box(json.as_bytes()))
                .expect("decode")
        });
    });
    group.finish();
}

/// Policy construction: the work of pinning a deployment's admitted
/// algorithm set.
fn policy(c: &mut Criterion) {
    let mut g = c.benchmark_group("policy");
    g.bench_function("with-signature-algs", |b| {
        b.iter(|| {
            let mut policy = Policy::default();
            for alg in SignatureAlg::ALL {
                policy = policy.with_signature_algs(&[alg]);
                black_box(policy.allows_signature(alg));
            }
            policy
        });
    });
    g.bench_function("with-kems", |b| {
        b.iter(|| {
            let mut policy = Policy::default();
            for alg in KemAlg::ALL {
                policy = policy.with_kems(&[alg]);
                black_box(policy.allows_kem(alg));
            }
            policy
        });
    });
    g.finish();
}

criterion_group!(
    benches,
    signing,
    kem,
    trees,
    symmetric,
    vouchers,
    certificates,
    keytabs,
    delegation_json,
    policy
);
criterion_main!(benches);
