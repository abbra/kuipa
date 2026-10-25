# Limits and revocation

## Rate limits

`kuipad` limits requests before doing any cryptography or LDAP work, with
token buckets:

| bucket | default | keyed by |
|---|---|---|
| per host | a burst of 10, then 2 a minute | the host's name for joins, rekeys and staging; the principal for unseal requests |
| per address | a burst of 60, then 30 a minute | the client's address, from httpd's `X-Forwarded-For` |

Registrations and users' vault operations use only the per-address bucket:
they are always Kerberos-authenticated, so there is nothing to guess, and
the users of one host must not share that host's allowance.

```json
"rate_limit": {
  "per_host":   { "burst": 10, "per_minute": 2 },
  "per_source": { "burst": 60, "per_minute": 30 }
}
```

A limited request gets an empty `429`; clients treat it like an
unreachable server and retry later.

## Limits on users' vaults

Users create their own vaults, within limits the realm sets. The limits
live on `cn=vault-limits,cn=kuipa,cn=etc,<suffix>`, attribute
`ipaKUVaultLimits`, as JSON; without the entry, the defaults apply:

| field | default | meaning |
|---|---|---|
| `max_lifetime` | 400 days (seconds) | the longest a vault may live |
| `max_unlocks` | none | the largest unlock limit a vault may set |
| `max_vaults` | 16 | vaults per user |
| `max_devices` | 8 | devices per vault and holder: each member of a shared vault registers up to this many |
| `max_members` | 64 | managers and members of a shared vault, together; `0` keeps every vault to its owner |
| `max_reauth` | 12 hours (seconds) | the longest re-authentication session |
| `offline_sessions` | `false` | whether vaults may allow offline sessions at all |
| `without_device` | `true` | whether a vault may do without the device factor |
| `descriptor_age` | 30 days (seconds) | how long a client may seal offline with a vault's description |

Offline sessions hand a key to the user's machine for a while, after which
the servers can no longer enforce limits on it. They stay off until you
set `"offline_sessions": true`. Setting `"without_device": false` forbids
vaults that rely on a ticket alone, which a stolen password would open.

## Revoking

| to stop | do |
|---|---|
| a host's sealed keytab and files opening anywhere | `ipa host-del` (or lock the entry); `host-disable` does not lock it yet |
| a service's sealed keytab and files | `ipa service-del` (or lock the entry) |
| one sealed file of a host or service | the host retires it with `kuipa unprotect --file`; otherwise remove its binding values from `ipaKUEscrowFileBinding` on the entry |
| a user's vaults | `ipa user-disable` (locks the entry) or `ipa user-del` |
| one vault | its owner runs `kuipa seal revoke`; an administrator command is pending |
| an anchor | `kuipad rotate-anchor` on its server |
| a voucher key | delete `voucher-<thp>.jwk` and restart `kuipad` |
