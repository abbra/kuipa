# Limits and revocation

## Rate limits

`kuipad` limits requests before doing any cryptography or LDAP work, with
token buckets:

| bucket | default | keyed by |
|---|---|---|
| per host | a burst of 10, then 2 a minute | the host's name for joins, rekeys and staging; the principal for unsealing a host's or service's keytab or file; for opening a user's vault file, whoever opens it (checked once the server knows who, so each member of a shared vault has their own allowance) |
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
| `factors` | none | factor sets a policy must meet one of, e.g. `[{"device": "any"}]` |
| `groups` | none | limits for members of groups, below |

Offline sessions hand a key to the user's machine for a while, after which
the servers can no longer enforce limits on it. They stay off until you
set `"offline_sessions": true`. Setting `"without_device": false` forbids
vaults that rely on a ticket alone, which a stolen password would open.

`factors` says more precisely what a vault must ask for. A vault's policy
must include all the factors of one of the listed sets, and a device at
the set's level or higher. For example, to require either a device key
that never leaves its token, or a ticket and a passkey together:

```json
"factors": [
  { "device": "hardware-bound" },
  { "ticket": true, "passkey": true }
]
```

### Limits for groups

`groups` gives the members of IPA user groups or host groups other
limits. Each entry names a `group`, a `priority`, and any of the fields
above, which replace the realm's for that group; the fields it leaves
out stay the realm's:

```json
"groups": [
  { "group": "travellers", "priority": 10,
    "offline_sessions": true, "max_vaults": 32 },
  { "group": "contractors", "priority": 5,
    "max_lifetime": 7776000, "factors": [{ "device": "hardware-bound" }] }
]
```

Limits follow a vault's **owner**: a manager of someone else's shared
vault works within the owner's limits, not their own. When the owner is
in several of the listed groups, only the entry with the lowest priority
applies, as FreeIPA picks one password policy; nothing is merged. Here a
contractor who also travels gets the contractors' limits and no offline
sessions. `"max_unlocks": null` in an entry lifts the realm's cap for
that group.

Limits are checked whenever a vault's policy is set, a device registered
or the vault shared. A vault already outside tightened limits keeps its
policy until it is next changed, but offline sessions its owner may no
longer have are refused at once.

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
