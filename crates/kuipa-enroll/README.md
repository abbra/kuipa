# kuipa-enroll

The kuipa protocol for post-quantum FreeIPA enrollment and keytab
protection.

This crate implements the protocol described in
[DESIGN.md](../../docs/DESIGN.md) but does no I/O itself. On the client
side it provides the messages, key schedules and verification. On the
server side it provides a state machine, `EnrollServer`, which hands every
directory operation to a `Directory` implementation. `kuipad` supplies one
built on LDAP and GSSAPI.

## Modules

| module | covers |
|---|---|
| `delegation`, `anchors` | server delegations, successions and the anchor exchange between servers |
| `realm` | realm advertisements and their verification |
| `enrollment` | enrollment strings |
| `join` | join, rekey and stage requests |
| `voucher` | blind-signed enrollment vouchers |
| `trust` | trust establishment between realms |
| `bundle` | offline enrollment bundles |
| `escrow` | sealed keytabs |
| `keytab` | MIT keytab encoding |
| `server` | `EnrollServer` and the `Directory` trait |

The crate forbids `unsafe` code. All cryptography comes from
[`tang-pqc`](../tang-pqc) and OpenSSL (version 3.5 or later), through
[`native-ossl`](https://crates.io/crates/native-ossl).

## License

This crate is part of [kuipa](../../README.md). It is licensed under the
GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
