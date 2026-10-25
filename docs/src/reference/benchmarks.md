# Benchmarks

The measured cost of enrollment, escrow, vouchers and the cryptography under
them, and how to run them so that two runs can be compared.

## Where the benchmarks live

Criterion targets sit in the crate whose code they measure, so a bench breaks
with the code it benches:

| Target | Crate | Measures |
| --- | --- | --- |
| `crypto` | `kuipa-enroll` | ML-DSA sign/verify/keygen per parameter set, ML-KEM encapsulate/decapsulate, Merkle roots and paths, AEAD seal/open, hashing, voucher sign/verify, keytab MIT encode/decode, delegation JSON, policy construction |
| `protocol` | `kuipa-enroll` | Advertisement build/cache/wire, realm verification (CA count scaling), OTP and Kerberos join round trips, request/response wire codec, rekey |
| `anchors` | `kuipa-enroll` | Voucher issuance, verification and Merkle proofs versus leaf count, anchor-state insert and wire, `Trust::compute` versus servers and claims, delegation verification |
| `escrow` | `kuipa-enroll` | Sealing across N servers, unsealing with N recovery round trips, escrow wire codec |
| `blind` | `ml-dsa-blind` | Blinded request, blind signing, finalization, verification, round trip, wire encode, context construction, per parameter set |
| `certs` | `kuipa-perf` | CA keygen, self-signing, chain construction — RSA-2048, EC P-256 and ML-DSA-65 |

`kuipa-perf` is the fixture crate: it synthesizes deterministic realms,
keytabs, certificates and anchors, and is a *dev-dependency* of the crates
above rather than a bench owner itself. Its fixtures verify as they are built —
a realm that fails to verify panics during setup, so a broken fixture can never
produce a number.

## Profiles

`KUIPA_BENCH_PROFILE` selects the fixture sizes. `production` is the default.

| Profile | Servers | CA certs | Keytab entries | Escrow servers | Vouched claims | CA |
| --- | --- | --- | --- | --- | --- | --- |
| `smoke` | 2 | 1 | 1 | 2 | 3 | EC P-256 |
| `production` | 4 | 1 | 4 | 4 | 8 | EC P-256 |
| `pqproduction` | 4 | 1 | 4 | 4 | 8 | ML-DSA-65 |
| `large` | 8 | 4 | 6 | 8 | 64 | EC P-256 |

`pqproduction` is `production` with a post-quantum certificate authority: the
fixture realm's PKINIT chain is a real ML-DSA-65 self-signed CA certificate,
built through `synta-certificate`, so advertisement verification and CA parsing
are measured against the certificate sizes and signature algorithms a
post-quantum deployment actually ships.

Scaling benches sweep their own axis (leaf counts, server counts, payload
sizes) around the profile's base sizes: `smoke` sweeps shallow, `large` goes
deep, so one bench file serves both. Two axes stop short of the sweep:
escrow fan-out caps at 32 servers because every slot is a whole realm (keygen,
trust exchange, advertisement) whose quadratic setup would dominate a deeper
sweep, and CA count caps at 8 because `tang-pqc` refuses to parse an
advertisement over 256 KiB — a post-quantum chain of 16 CAs is 342 KiB, so a
deeper sweep would measure a refusal rather than a verification.

## Running

```sh
scripts/bench.sh run --profile production
scripts/bench.sh run --profile pqproduction --quick
scripts/bench.sh run --targets crypto,blind --samples 50
cargo bench -p kuipa-enroll --bench anchors          # one target, default profile
KUIPA_BENCH_PROFILE=large cargo bench -p kuipa-enroll --bench protocol
```

`--quick` is criterion's `--sample-size 10 --measurement-time 1`: fast enough
for CI, coarse enough that you should not read much into a single number.

Each run collects criterion's estimates into `results.json` and stores it with
`params.json` — git commit and dirty flag, profile, fixture sizes, criterion
flags, platform — under `~/.cache/kuipa-bench/<timestamp>/`:

```sh
scripts/bench.sh list
scripts/bench.sh compare ~/.cache/kuipa-bench/20261001T120000Z ~/.cache/kuipa-bench/20261024T090000Z
```

Comparison reads the stored files, so a baseline survives `cargo clean`.
`--baseline NAME` additionally saves a criterion baseline for per-benchmark
`--baseline NAME` comparisons inside `target/criterion`.

## CI

`local-ci.sh bench` (opt-in, like `msrv`) runs the smoke profile in quick mode
and fails if any benchmark panics — which is the fixture crate's verification
assertion firing, so the job doubles as a protocol self-check. The workflow
job runs on every PR.

## Reading the numbers

- Keygen and certificate building are *fixture setup*: they run outside timed
  loops, except in `certs`, which measures them on purpose.
- Throughput annotations are criterion's: `Bytes` for payload-shaped work
  (MB/s), `Elements` for count-shaped work.
- `join/otp` and `join/gss` measure the whole client-side round trip against
  an in-memory directory; the directory's own work (Kerberos checks simulated
  with a fixed binding) is included, because that is what the client waits on.
  LDAP and a real KDC are not in the loop — see the local CI docs for those.
