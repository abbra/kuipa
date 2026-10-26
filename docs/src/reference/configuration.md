# Configuration

## kuipad: `/etc/ipa/kuipad.json`

| key | default | meaning |
|---|---|---|
| `realm` | required | the Kerberos realm |
| `domain` | required | the DNS domain |
| `basedn` | required | the LDAP suffix |
| `server` | required | this server's FQDN |
| `ldap_uri` | required | the LDAPI URI of this server's 389-ds |
| `principal` | required | the daemon's principal, `ipa-ku/<server>@REALM` |
| `service` | required | its GSS-API service name, `ipa-ku@<server>` |
| `keytab` | required | its keytab |
| `ca_file` | required | the IPA CA chain (PEM): CA certificates only, Merkle Tree CAs included |
| `pkinit_anchors_file` | `/var/lib/ipa-client/pki/kdc-ca-bundle.pem` | the PKINIT anchors hosts need for armoured `kinit`: CA certificates only |
| `key_dir` | `/var/lib/ipa/ku` | the key directory |
| `listen` | `unix:/run/ipa/kuipad.sock` | where to listen when not socket-activated (`unix:/path` or `host:port`) |
| `peers` | `[]` | servers to exchange anchors with, besides the IPA servers in LDAP |
| `discover_peers` | `true` | find peers among the IPA servers (`cn=masters`) |
| `peer_endpoints` | `{}` | base URLs of peers by FQDN, instead of `https://<fqdn>` |
| `peer_interval` | `60` | seconds between anchor exchange rounds (at least 5) |
| `anchor` | `true` | whether this server holds an anchor and vouches for others |
| `vouch_interval` | `60` | least seconds between vouches that only add servers |
| `rate_limit` | see [Limits](../realm/limits.md) | `{"per_host": {"burst", "per_minute"}, "per_source": {…}}` |
| `trusts` | `[]` | trusted realms configured by hand: `{"realm", "domain", "servers", "anchors"}` |
| `enctypes` | `[20, 19, 18, 17]` | Kerberos enctypes to issue keys for, strongest first |
| `tlog_head_interval` | `3600` | seconds between published transparency-log heads: a head covers what was logged before its period began, so watching it says how many events a period had, not when each happened; `0` publishes every event at once (tests only) |
| `tlog_retention_months` | `13` | months of transparency-log openings kept: older events stay in the log but can no longer be looked up or tied to anyone |

Unknown keys are refused, so a typo stops the daemon instead of being
ignored.

## Realm-wide vault limits

On `cn=vault-limits,cn=kuipa,cn=etc,<suffix>`, attribute
`ipaKUVaultLimits`, as JSON; see [Limits and revocation](../realm/limits.md#limits-on-users-vaults).

## Units

| unit | runs |
|---|---|
| `kuipad.socket` / `kuipad.service` | the daemon, behind httpd |
| `kuipa-unseal.service` | `kuipa-unseal --all` at boot, before SSSD, gssproxy and certmonger; retries on 75 |
| `ipa-client-complete.service` | `kuipa complete` while an offline enrollment is pending; retries on 75 |
| `kuipa-rotate.timer` / `.service` | `kuipa rotate-keys` monthly |
