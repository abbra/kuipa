# Files and environment

## On an enrolled host

All paths hang off `$KUIPA_ROOT` (default `/`).

| path | holds | mode |
|---|---|---|
| `/etc/krb5.keytab` | the host keytab; a link into `/run/ipa` when protected | 0600 |
| `/etc/ipa/krb5.keytab.sealed`, `/run/ipa/krb5.keytab` | the sealed host keytab, and its unsealed copy | 0600 |
| `<path>.sealed`, `/run/ipa/kuipa/<escaped path>` | another protected keytab or file, sealed and unsealed; `<path>` is a link to the latter | 0600, original mode |
| `/etc/ipa/ca.crt` | the IPA CA chain | 0644 |
| `/etc/ipa/ku-anchors` | the realm's pinned anchors (`<thumbprint> [<expiry>]` per line, and the anchor history watermark) | 0644 |
| `/etc/ipa/ku-anchors.d/<REALM>` | a trusted realm's anchors | 0644 |
| `/var/lib/ipa-client/ku/trusts/<REALM>/` | a trusted realm's PKINIT anchors and CA | 0644 |
| `/etc/krb5.conf.d/kuipa_trust_<REALM>` | a trusted realm's Kerberos configuration | 0644 |
| `/var/lib/ipa-client/ku/state.json` | realm, host name, servers, protection | 0600 |
| `/var/lib/ipa-client/ku/realm.json` | realm, host name and servers, for users | 0644 |
| `/var/lib/ipa-client/ku/krb5.conf`, `pkinit-anchors.pem` | Kerberos configuration from the enrollment | 0644 |
| `/var/lib/ipa-client/ku/recipient.jwk`, `recipient.pub.jwk` | the machine key for a mode A bundle | 0600, 0644 |
| `/var/lib/ipa-client/ku/pending.json` | steps left after an offline enrollment | 0600 |
| `/var/lib/ipa-client/ku/advertisements/` | the servers' advertisements, kept to fetch them conditionally; verified again at every use | 0644 |

## A user's own files

| path | holds |
|---|---|
| `$KUIPA_USER_DIR`, else `$XDG_DATA_HOME/kuipa`, else `~/.local/share/kuipa` (0700) | the user's kuipa directory |
| `…/device.key` | the device key under its passphrase |
| `…/device.pkcs11` | where a token device is: its module and URI |
| `…/seals/<name>.seal` | each seal's last signed description |
| `…/servers.json` | the servers' advertisements, for sealing offline |
| `…/advertisements/` | the servers' advertisements, kept to fetch them conditionally when the host's own cannot be written |
| `$KUIPA_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/kuipa`, `sessions/<seal id>` | a live session: its token, the unwrapped device key, released offline keys (memory only) |

## On an IPA server

| path | holds |
|---|---|
| `/etc/ipa/kuipad.json` | the daemon's configuration |
| `/var/lib/ipa/ku/` | its keys (see [Keys and rotation](../realm/keys.md)), the delegation it advertises, the anchor exchange's state |
| `/var/lib/ipa/ku/tang/` | the Tang service's keys |
| `/etc/httpd/conf.d/kuipa.conf` | forwards `/ipa/ku/` to the daemon |
| `/run/ipa/kuipad.sock` | the daemon's socket |

## Environment

| variable | effect |
|---|---|
| `KUIPA_ROOT` | the root for every host path above |
| `KUIPA_ENROLLMENT_FILE` | the default enrollment string file |
| `KUIPA_ENDPOINTS` | `fqdn=url,…`: reach servers at other URLs (`unix:/path` too), for tests |
| `KUIPA_DNS` | the one nameserver to ask for SRV records: `address:port` (plain), `dot://<host>[:853]` or `doh://<host>[:443][/path]` |
| `KUIPA_DNS_CA` | PEM certificates to verify `dot://` and `doh://` nameservers with, instead of the system roots |
| `KUIPA_KDC` | the one KDC for armoured exchanges, instead of the advertised ones |
| `KUIPA_TRACE` | `tracing` filter directives, e.g. `kuipa_tools=trace` |
| `KUIPA_USER_DIR`, `KUIPA_RUNTIME_DIR` | a user's kuipa directory and session directory |
| `KUIPA_PKCS11_PROVIDER` | OpenSSL's pkcs11-provider module, if not `/usr/lib64/ossl-modules/pkcs11.so` |
| `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` | the HTTP proxy `kuipa` and `kuipad` use for server requests (`NO_PROXY` lists hosts to reach directly); see [Reaching a KDC through an HTTPS proxy](../realm/trusts.md#reaching-a-kdc-through-an-https-proxy) |
| `KRB5_CONFIG`, `KRB5CCNAME` | used as given; without `KRB5_CONFIG`, `kuipa` adds the enrollment's `krb5.conf` after the system's |
