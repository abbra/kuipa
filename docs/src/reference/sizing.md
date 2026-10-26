# Sizing: storage and traffic

How much a realm's servers store, and how much travels between hosts and
servers, and between the servers themselves, for each kind of action.
Use it to size disks and links, and to see where the bytes go.

Figures are for the default crypto policy: ML-DSA-65 signatures,
ML-KEM-768, SHA-256. Under a CNSA 2.0 policy (ML-DSA-87, ML-KEM-1024,
SHA-384) multiply keys, signatures and the messages they dominate by
about 1.3: the advertisement grows from 28.2 KB to 36.0 KB.

Each figure is marked as one of:
- **measured**: from the playground session or a measurement test (see
  [How these were measured](#how-these-were-measured));
- **computed**: from the encodings and intervals in the code, for sizes
  no run exercises at scale.

## The one number to remember: the advertisement

Almost every exchange a client makes starts by fetching a server's
advertisement (`GET /ipa/ku/adv`), and verifying it against the anchors it
pins. The advertisement holds the server's keys, the realm's
configuration and CA chain, and the delegation that proves the server
belongs to the realm.

| realm | advertisement | |
|---|---|---|
| 1 server | 24.8 KB | measured |
| 2 servers | 25.1 KB | measured |
| 8 servers | 26.4 KB | measured |
| 32 servers | 30.9 KB | measured |
| the playground (2 servers, a trusted realm, a 1.5 KB CA) | 28.5 KB | measured |

It grows by about 190 bytes per server, plus the CA chain and PKINIT
anchors as they are (a classical CA certificate is about 1.5 KB, an
ML-DSA one about 5.5 KB).

**A host that pins two or more anchors fetches it twice per exchange**:
once, then again for a second anchor's proof of the same server (DESIGN
§4.4), whatever the number of anchors. So the floor of almost any client
action is **about 50–57 KB downloaded**. The second fetch only needs the
delegation member: serving that alone, or the vouch-head proofs of DESIGN
§4.9 (a few hundred bytes), would roughly halve client traffic.

## Client actions

Downloaded and uploaded bytes per action, for a host that pins two
anchors in a realm of two servers. *adv* is one advertisement fetch, about
25–29 KB. **Measured**, from the playground report.

### Hosts

| action | requests | up | down |
|---|---|---|---|
| enroll: OTP, password, ticket or voucher | 2 adv, join or rekey, 2 claim-log pages | 3.2–7.1 KB | 70 KB |
| enroll offline: the bundle, out of band | — | — | 17.9 KB bundle |
| … and its first contact | 2 adv, rekey | 3.3 KB | 50 KB |
| rotate keys (monthly timer) | 2 adv, rekey | 3.3 KB | 50 KB |
| health check (`kuipa check`) | 2 adv **per server** | — | 48 KB × servers |
| seal the keytab or a file (`kuipa protect`) | 6 adv, rekey or register, unseal check | 5.8 KB | 145 KB |
| **unseal at boot** (`kuipa-unseal`), per sealed keytab or file | recovery request only: the sealed file keeps the server's key | 2.3 KB | 57 bytes |
| install trusted realms | 3 adv | — | 74 KB |
| fetch replica secrets (`kuipa keys fetch`), per secret | 2 adv, keys | 3.3 KB | 49 KB |
| post-quantum Tang: provision / recover | `adv` 10.3 KB, then `rec` | 2.2 KB | 57 bytes |

### Users

| action | requests | up | down |
|---|---|---|---|
| a vault operation (create, policy, add device, share, approve, list…) | 2 adv, vault | 3.2–14 KB | 50–100 KB: the reply carries the signed vault descriptor, about 23 KB |
| seal a file (offline once the vault is described) | 6 adv, for the servers' escrow keys | — | 150 KB |
| **open a sealed file** | recovery request only | 3.2 KB | 1.2 KB |
| open within a session | recovery request with the session token | 23 KB | 1.2 KB |
| start a session, or an offline one | 2 adv, vault | 3.3 KB | 97–101 KB |
| watch the vault (`kuipa tlog watch`), per server | 2 adv, lookup | 3.3 KB | 53–60 KB |
| sign files or a commit (`kuipa sign`) | 2 adv, sign | 3.3 KB | 70 KB (a 21 KB signature bundle back) |

The frequent actions are cheap: unsealing at boot and opening a sealed
file make one small request each. What costs is the advertisement, on
every action that talks to a server first.

### Per host and per user, per day

Key rotation runs monthly from `kuipa-rotate.timer`, about 53 KB. A host
that also runs `kuipa check` and `kuipa trusted-realms` daily, as the docs
suggest, adds **(48 KB × servers) + 74 KB a day**, under 0.2 MB for a realm
of two servers, plus 2.3 KB per sealed keytab or file at each boot. A user
who opens 20 sealed files and runs an hourly watch against two servers
adds about 24 × 110 KB + 20 × 4.4 KB ≈ **2.7 MB a day**: the watch,
which is all advertisements, is nearly all of it.

## Between servers

### The anchor exchange

Servers gossip claims and vouches (DESIGN §4.2) over `POST
/ipa/ku/peer/sync`, authenticated with their Kerberos keys.

- **A quiet round sends nothing.** A server sends a peer only what is new
  since its last successful sync (computed, `agirru-engine`).
- **What changes.** A server's claim renews at two thirds of its 90-day
  validity, every 60 days, and every anchor then vouches again. Each
  anchor also vouches again at half of a vouch's 7-day validity, every
  3.5 days. A vouch is a 3.3 KB signature plus 32 bytes per claim it
  covers (computed).
- **Where it goes.** Every server sends what it learns to every peer, so
  a change crosses each of the N × (N − 1) peer links about once
  (computed; an upper bound, since a peer that already has an entry merges
  nothing).

| realm | exchange state per server | delta after one claim renewal, per link | |
|---|---|---|---|
| 2 servers, both anchors | 12.7 KB | — | measured (playground) |
| 10 servers, all anchors | 65 KB | 38 KB | measured (DESIGN §4.2) |
| 60 servers, all anchors | 489 KB | 321 KB | measured (DESIGN §4.2) |
| 60 servers, 6 anchors | 55 KB | 32 KB | measured (DESIGN §4.2) |

Traffic per server per day, computed from the above:

| realm | from vouches | from claim renewals | per server per day |
|---|---|---|---|
| 10 servers, all anchors | 0.9 MB realm-wide | 0.6 MB realm-wide | about 0.15 MB |
| 60 servers, all anchors | 315 MB realm-wide | 1.1 GB realm-wide | about 24 MB |
| 60 servers, 6 anchors | 31 MB realm-wide | 113 MB realm-wide | about 2.4 MB |

Large realms should give the anchor role to a few servers, as DESIGN
§4.2 says: it cuts the exchange by an order of magnitude. Hosts are not
affected either way: they still fetch two advertisements per exchange.

### Witnesses and auditors

A witness fetches each server's signed head every pass (once a minute by
default) and posts its cosignature when the head changed. A head is
about 3.4 KB plus 2.5 KB per cosignature it carries (computed). Heads
change once per `tlog_head_interval` (an hour), so a witness costs each
server about **5 MB a day**, nearly all of it fetching an unchanged
head. `kuipa-audit tlog` reads the whole log: 100 bytes per leaf.

### LDAP replication

What `kuipad` writes to the directory (below) replicates to every IPA
server through 389-ds, as any IPA data does: each write crosses each
replication agreement once.

## Server storage

### Files under the key directory

| file | size | |
|---|---|---|
| keys: signing, anchor, join, escrow, trust, Tang (each ML-DSA-65 key 2.7 KB, ML-KEM-768 key 1.7 KB as JWK) | about 15 KB, plus retired keys until pruned | measured |
| `delegation.json` | 15 KB | measured |
| `epoch.json`, the anchor epoch log | 7.3 KB, growing with each anchor rotation | measured |
| `peers.state`, the exchange state | see the table above: 12.7 KB to 489 KB | measured |
| `tlog/<log>/leaves`, the public log | **100 bytes per event**, kept for ever | measured |
| `tlog/<log>/openings/YYYY-MM` | **about 150 bytes per event**, kept 13 months (`tlog_retention_months`) | measured |

An event is a vault change, a key release, a signature or a Keys fetch,
and it is logged only on the server that handled it. A realm of 1,000
users who each open 5 sealed files a day logs 5,000 events a day: 0.5 MB
of leaves and 0.75 MB of openings a day across the realm, so about
180 MB of leaves a year and at most 300 MB of openings at any time.

### In LDAP, on every server

Estimated from what each attribute holds (base64 where LDAP stores
text), and, for sealed data, from the sealed files the playground wrote.
The playground keeps its directory in memory, so the entries themselves
are not measured.

| what | size |
|---|---|
| a sealed keytab or file's binding, per server | 43 bytes, on the principal's entry |
| a vault: policy, state, owner, sharing | about 0.5–1 KB |
| a device in a vault | about 1.8 KB, nearly all its ML-KEM public key |
| a deposit (`seal deposit put`, `escrow luks`) | the sealed file: about 6.3 KB for a small secret |
| a device key escrowed under a recovery code, or with the helpdesk | about 8 KB |
| a release request and its approvals | under 1 KB |
| a spent voucher | 43 bytes on the host entry |
| a staged host's keys (offline enrollment) | a few KB, until first contact |

A realm with 1,000 users, each with 2 vaults of 2 devices, adds about
1,000 × 2 × (0.75 + 2 × 1.8) KB ≈ **9 MB**; 10,000 hosts with a sealed
keytab and one sealed file, against 4 servers, add 10,000 × 2 × 4 × 43
bytes ≈ **3.4 MB**.

## On hosts

| file | size |
|---|---|
| `servers.json`, the cached advertisements | about 28 KB per server |
| a vault's stored descriptor (`vaults/<name>.vault`) | 21 KB, plus 1.7 KB per device |
| a device key | 1.8 KB |
| a sealed file | the plaintext plus about 6.3 KB for two servers (2.4 KB in session mode) |
| a signature bundle (`.kusig`) | 21 KB |
| an offline bundle | 17.9 KB: too big for a 16 KB cloud user-data limit |

## How these were measured

- **Client traffic**: `python3 contrib/ci/playground/sizes.py` reads a
  playground report (`./contrib/ci/local-ci.sh playground-test`) and
  prints request and response sizes per route; `--steps` adds each
  step's totals.
- **Advertisement against realm size**: `cargo test -p kuipa-perf --test
  sizes -- --ignored --nocapture`.
- **Exchange state and deltas**: `cargo test --release -p kuipa-enroll
  measure_exchange_sizes -- --ignored --nocapture` (DESIGN §4.2).
- **Server and host files**: `KUIPA_KEEP_PLAYGROUND=1
  ./contrib/ci/local-ci.sh playground-test` keeps the playground's
  directory; its `keys-<server>/` and `users/` directories hold what a
  server and a user store.
- **Tang**: `crates/tang-pqc/examples/escrow.rs` (tang-pqc DESIGN §3.4).
