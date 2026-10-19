# kuipa-tools

The kuipa client programs for FreeIPA hosts.

| program | does |
|---|---|
| `kuipa` | manages the host's post-quantum identity: enrollment, key rotation, keytab protection, trusted realms and health checks |
| `kuipa-unseal` | unseals a protected keytab at boot, or acts as gssproxy's keytab loader |
| `kuipa-voucher` | issues enrollment vouchers with blind signatures, as an issuer or a provisioner |

## Usage

```text
kuipa prepare [--new]                 get ready to be enrolled offline
kuipa enroll [--server S... | --domain D] [--hostname H]
             [--enrollment-file F | --realm R]
             [--principal P [--password-file F] | --use-ccache |
              --voucher-file F [--ephemeral-key F] | --ldap-otp]
kuipa enroll --bundle F               enroll offline
kuipa voucher-key --out F             make the ephemeral key a voucher binds to
kuipa realm-info --krb5-dir D         Kerberos configuration for enrolling with a ticket
kuipa complete                        finish an offline enrollment
kuipa rotate-keys                     new host keys
kuipa protect | unprotect             seal or unseal the keytab on disk
kuipa trusted-realms                  accept users of the realms this realm trusts
kuipa status | check [--server S]     is this host healthy?
kuipa leave                           remove kuipa's state
```

Secrets are never read from the command line. The enrollment string comes
from `--enrollment-file`, from `KUIPA_ENROLLMENT_FILE` or from standard
input. All options accept `--json`. Add `--verbose` or `--trace` to trace
each step on standard error.

All paths are resolved under `KUIPA_ROOT` (default `/`), so the tools can
be tried without touching the system. See
[DESIGN.md §10](../../docs/DESIGN.md#10-client-kuipa-and-kuipa-unseal) for
the commands, files and environment variables.

The `kuipa-playground` example sets up the throwaway environment used by
`contrib/ci/local-ci.sh interactive`.

## License

This crate is part of [kuipa](../../README.md). It is licensed under the
GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
