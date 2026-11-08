# LDAP schema for kuipa (proposal)

Status: proposal. Nothing here is implemented in FreeIPA yet; the names
below are the ones the daemon already reads and writes
(`crates/kuipad/src/directory.rs`), so the schema is written to match
the code, not the other way round. See `TODO.md` ("FreeIPA server:
schema …") and §19.1 of `DESIGN.md`.

## 1. OID allocation

The proposal allocates the following arcs in the Red Hat OID registry:

* attributes: `2.16.840.1.113730.3.8.32.1` ...`.32.30` — kuipa schema
  attributes
* objectClasses: `2.16.840.1.113730.3.8.33.1` ... `.33.9` — kuipa schema
  objectClasses

Before the LDIF is cut, these two arcs must be recorded in the
registry file itself.

Naming follows the code exactly: `ipaKU` + CamelCase, objectClasses
`ipaKUSeal`, `ipaKUDeposit`, `ipaKURelease`, all paired with `top`.
The existing `ipaSeal` / `ipaSealContainer` classes (IPA v4.2, the
KRA/Custodia vaults) are deliberately not extended: kuipa seals have
a different layout (flat under `cn=seals,cn=kuipa,cn=etc`, per-device
ML-KEM escrow, add-only approvals for MMR merge), and reusing the name
`ipaSeal` would collide. `X-ORIGIN 'IPA v4.13'` (adjust to the release
that ships it).

## 2. Syntax and matching choices

Two decisions drive everything else:

* **Binary vs text.** `ipaKUEscrowBinding`, `ipaKUEscrowFileBinding`
  and `ipaKUSealBinding` hold raw 32-byte hashes `H(ct)`; the daemon
  compares them as binary values (`bin_attrs` in `directory.rs`
  `escrow_allowed`). They get syntax
  `1.3.6.1.4.1.1466.115.121.1.40` (Octet String) with `octetStringMatch`,
  like `ipaSealPublicKey`. Everything else is a string: JSON blobs and
  the space-separated `<server> <count>` / `<approver> <time>` /
  `<hex hash> <not-after>` records get `DirectoryString`
  (`1.3.6.1.4.1.1466.115.121.1.15`) with `caseExactMatch` (they are
  machine-written, never case-folded; the daemon parses them with
  `split_once(' ')` / `from_json` and compares byte-exactly).
  `ipaKULease` is an INTEGER (Unix seconds, parsed with `u64::from_str`).
* **Equality indexing.** The daemon equality-searches: `ipaKUSealOwner`
  (`seals_of`), `ipaKUSealManager`, `ipaKUSealMember`,
  `ipaKUSealDepositor`, `ipaKUSealApprover` (`seals_shared_with`,
  `seals_approved_by`), `ipaKUVoucherSpent` (spent-salt check),
  `ipaKULease` (presence for purge). `ipaKUServerEscrowKey` is searched
  by presence over `cn=masters`. TODO.md explicitly requires
  `ipaKUSealApprover` and `ipaKUSealDepositor` indexed for equality.
  All `caseExactMatch` attributes are indexable with `eq`; the index
  LDIF is §5.

Replication semantics the schema must not break: approvals
(`ipaKUReleaseApproval`, `ipaKUReleaseDenied`) are **add-only** so
389-ds MMR merges values without conflict; `ipaKUSealUnlocks` and
`ipaKUReleaseUses` are per-server `<server> <count>` values updated by
delete-own-value + add in one modify, which also merges cleanly. These
are ACI/protocol properties, but the schema keeps all four
multi-valued with no ordering and no single-value constraint.

## 3. attributeTypes

```
attributeTypes: (
  2.16.840.1.113730.3.8.32.1
  NAME 'ipaKUEscrowBinding'
  DESC 'Registered escrow binding hashes of sealed keytabs, H(ct)'
  EQUALITY octetStringMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.40
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.2
  NAME 'ipaKUEscrowFileBinding'
  DESC 'Registered escrow binding hashes of sealed files, H(ct)'
  EQUALITY octetStringMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.40
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.3
  NAME 'ipaKUStaged'
  DESC 'JSON record of a staged enrollment (not_after, recipient)'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.4
  NAME 'ipaKUVoucherSpent'
  DESC 'Hex salt of the voucher spent to create this host'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.5
  NAME 'ipaKUSealOwner'
  DESC 'Principal name of the seal owner'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.6
  NAME 'ipaKUSealName'
  DESC 'Owner-assigned seal name, unique per owner'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.7
  NAME 'ipaKUSealPolicy'
  DESC 'Seal policy, JSON'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.8
  NAME 'ipaKUSealDevice'
  DESC 'Registered seal device, JSON, one value per device'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.9
  NAME 'ipaKUSealState'
  DESC 'Seal state: enabled or revoked'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.10
  NAME 'ipaKUSealUnlocks'
  DESC 'Offline unlock count of one server: "<server fqdn> <count>", one value per server'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.11
  NAME 'ipaKUSealSessionKey'
  DESC 'Sealed offline-session key, JSON, one value per epoch'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.12
  NAME 'ipaKUSealBinding'
  DESC 'Registered binding of a seal file, hex H(ct)'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.13
  NAME 'ipaKUSealManager'
  DESC 'Seal manager, kind:name (user, group, host, service principal)'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.14
  NAME 'ipaKUSealMember'
  DESC 'Seal member, kind:name (user, group, host, service principal)'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.15
  NAME 'ipaKUSealDepositor'
  DESC 'Seal depositor, kind:name, may deposit without opening'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.16
  NAME 'ipaKUSealApprover'
  DESC 'Seal release approver, kind:name, drawn from the policy'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.17
  NAME 'ipaKUDepositData'
  DESC 'Seal deposit, JSON, including the sealed IPUF payload'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.18
  NAME 'ipaKUReleaseRequest'
  DESC 'Seal release request, JSON'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.19
  NAME 'ipaKUReleaseApproval'
  DESC 'Release approval: "<approver kind:name> <unix time>", add-only'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.20
  NAME 'ipaKUReleaseDenied'
  DESC 'Release denial: "<approver kind:name> <unix time>"'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.21
  NAME 'ipaKUReleaseUses'
  DESC 'Release use count of one server: "<server fqdn> <count>", one value per server'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.22
  NAME 'ipaKUDeviceEscrow'
  DESC 'Device-key recovery escrow, JSON, one value per device'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.23
  NAME 'ipaKURecovery'
  DESC 'Realm device-key recovery settings, JSON'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.24
  NAME 'ipaKULease'
  DESC 'End of a leased host lease, seconds since epoch'
  EQUALITY integerMatch
  ORDERING integerOrderingMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.25
  NAME 'ipaKUVouchers'
  DESC 'Realm voucher settings, JSON (max_lease)'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.26
  NAME 'ipaKUServerEscrowKey'
  DESC 'Current seal escrow key of a server: "<KEM id> <base64url key>"'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.27
  NAME 'ipaKUSealLimits'
  DESC 'Realm seal limits, JSON'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.28
  NAME 'ipaKUSignPolicy'
  DESC 'Realm signing policy, JSON'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  SINGLE-VALUE
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.29
  NAME 'ipaKUTrustInvitation'
  DESC 'Trust invitation: "<hex secret hash> <not after unix seconds>", consumed by deleting the exact value'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )

attributeTypes: (
  2.16.840.1.113730.3.8.32.30
  NAME 'ipaKUTrustedRealm'
  DESC 'Trusted partner realm, JSON, one value per realm'
  EQUALITY caseExactMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
  X-ORIGIN 'IPA v4.13' )
```

## 4. objectClasses

Three structural classes for the seal tree (seal, deposit, release
entries are created by the daemon as `top` + class, `cn` the RDN), and
one auxiliary class per place attributes land on existing entries.

```
objectClasses: (
  2.16.840.1.113730.3.8.33.1
  NAME 'ipaKUSeal'
  DESC 'kuipa seal with per-device escrow'
  SUP top STRUCTURAL
  MUST ( cn $ ipaKUSealOwner $ ipaKUSealName )
  MAY ( ipaKUSealPolicy $ ipaKUSealManager $ ipaKUSealMember $
        ipaKUSealDepositor $ ipaKUSealApprover $ ipaKUSealDevice $
        ipaKUSealState $ ipaKUSealUnlocks $ ipaKUSealSessionKey $
        ipaKUSealBinding $ description )
  X-ORIGIN 'IPA v4.13' )

objectClasses: (
  2.16.840.1.113730.3.8.33.2
  NAME 'ipaKUDeposit'
  DESC 'kuipa seal deposit'
  SUP top STRUCTURAL
  MUST ( cn $ ipaKUDepositData )
  X-ORIGIN 'IPA v4.13' )

objectClasses: (
  2.16.840.1.113730.3.8.33.3
  NAME 'ipaKURelease'
  DESC 'kuipa seal release request'
  SUP top STRUCTURAL
  MUST ( cn $ ipaKUReleaseRequest )
  MAY ( ipaKUReleaseApproval $ ipaKUReleaseDenied $ ipaKUReleaseUses )
  X-ORIGIN 'IPA v4.13' )

objectClasses: (
  2.16.840.1.113730.3.8.33.4
  NAME 'ipaKUPrincipalEscrow'
  DESC 'kuipa escrow bindings on a host, service or user entry'
  SUP top AUXILIARY
  MAY ( ipaKUEscrowBinding $ ipaKUEscrowFileBinding $ ipaKUStaged $
        ipaKUVoucherSpent $ ipaKULease $ ipaKUDeviceEscrow )
  X-ORIGIN 'IPA v4.13' )

objectClasses: (
  2.16.840.1.113730.3.8.33.5
  NAME 'ipaKUSealContainer'
  DESC 'kuipa seal container'
  SUP top STRUCTURAL
  MUST ( cn )
  X-ORIGIN 'IPA v4.13' )

objectClasses: (
  2.16.840.1.113730.3.8.33.6
  NAME 'ipaKURealmConfig'
  DESC 'kuipa realm-wide configuration entry'
  SUP top AUXILIARY
  MAY ( ipaKURecovery $ ipaKUVouchers $ ipaKUSealLimits $
        ipaKUSignPolicy )
  X-ORIGIN 'IPA v4.13' )

objectClasses: (
  2.16.840.1.113730.3.8.33.7
  NAME 'ipaKUTrust'
  DESC 'kuipa trust invitations and partners'
  SUP top AUXILIARY
  MAY ( ipaKUTrustInvitation $ ipaKUTrustedRealm )
  X-ORIGIN 'IPA v4.13' )

objectClasses: (
  2.16.840.1.113730.3.8.33.8
  NAME 'ipaKUMasterEscrow'
  DESC 'kuipa server escrow key on a master entry'
  SUP top AUXILIARY
  MAY ( ipaKUServerEscrowKey )
  X-ORIGIN 'IPA v4.13' )
```

Rationale for the classes:

* `ipaKUPrincipalEscrow` (auxiliary) collects everything the daemon
  writes on existing host/service/user entries (§7.5): the two binding
  sets, staging, the spent voucher salt, the lease, device escrow.
  Hosts and services get it at enrollment; users at first device
  escrow. One class instead of several keeps `host-add --stage`
  and the voucher join each adding a single objectClass.
* `ipaKURealmConfig` sits on the `cn=<name>,cn=kuipa,cn=etc,$SUFFIX`
  settings entries (`recovery`, `vouchers`, `seal-limits`,
  `sign-policy`) as `nsContainer` + auxiliary. `ipaKUSealOwner` is
  deliberately **not** on it: the owner search must only match seals.
* `ipaKUTrust` on `cn=trusts,cn=kuipa,cn=etc,$SUFFIX`.
* `ipaKUMasterEscrow` on `cn=<server>,cn=masters,cn=ipa,cn=etc`.
* `ipaKUSealContainer` mirrors FreeIPA's `ipaSealContainer` shape
  (STRUCTURAL, MUST cn) for the `cn=seals` root and any future
  sub-containers.
* `ipaKUSealUnlocks`/`ipaKUReleaseUses` stay MAY and multi-valued —
  the per-server counter idiom (§7.6.7) depends on per-value
  add/delete, which SINGLE-VALUE would forbid.

## 5. Entry and index layout (install-time LDIF sketch)

```
dn: cn=kuipa,cn=etc,$SUFFIX
objectClass: top
objectClass: nsContainer
cn: kuipa

dn: cn=seals,cn=kuipa,cn=etc,$SUFFIX
objectClass: top
objectClass: nsContainer
objectClass: ipaKUSealContainer
cn: seals

dn: cn=trusts,cn=kuipa,cn=etc,$SUFFIX
objectClass: top
objectClass: nsContainer
objectClass: ipaKUTrust
cn: trusts

dn: cn=recovery,cn=kuipa,cn=etc,$SUFFIX
objectClass: top
objectClass: nsContainer
objectClass: ipaKURealmConfig
cn: recovery

dn: cn=vouchers,cn=kuipa,cn=etc,$SUFFIX
objectClass: top
objectClass: nsContainer
objectClass: ipaKURealmConfig
cn: vouchers

dn: cn=seal-limits,cn=kuipa,cn=etc,$SUFFIX
objectClass: top
objectClass: nsContainer
objectClass: ipaKURealmConfig
cn: seal-limits

dn: cn=sign-policy,cn=kuipa,cn=etc,$SUFFIX
objectClass: top
objectClass: nsContainer
objectClass: ipaKURealmConfig
cn: sign-policy
```

Index entries (389-ds `cn=config` LDIF, presence+eq as noted):

```
dn: cn=ipaKUSealOwner,cn=index,cn=userRoot,cn=ldbm database,cn=plugins,cn=config
changetype: add
objectClass: top
objectClass: nsIndex
cn: ipaKUSealOwner
nsIndexType: eq

dn: cn=ipaKUSealManager,cn=index,...   nsIndexType: eq
dn: cn=ipaKUSealMember,cn=index,...    nsIndexType: eq
dn: cn=ipaKUSealDepositor,cn=index,... nsIndexType: eq
dn: cn=ipaKUSealApprover,cn=index,...  nsIndexType: eq
dn: cn=ipaKUVoucherSpent,cn=index,...   nsIndexType: eq
dn: cn=ipaKULease,cn=index,...          nsIndexType: eq,pres
dn: cn=ipaKUEscrowBinding,cn=index,...  nsIndexType: eq
dn: cn=ipaKUEscrowFileBinding,cn=index,... nsIndexType: eq
dn: cn=ipaKUServerEscrowKey,cn=index,...   nsIndexType: pres
```

The escrow-binding indexes serve `escrow_allowed`, which the daemon
answers per unlock; without them every unlock is a full entry scan of
the binding set. The lease presence index serves the purge sweep.

## 6. Attributes deliberately NOT defined

* Anchor keys, epoch log, delegation, peer state, voucher/witness keys,
  transparency-log leaves: server-local files under `/var/lib/ipa/ku`,
  never in the directory (§18, `keystore.rs`/`ledger.rs`).
* The keys operation (§18) stores nothing of its own; its policy reads
  existing `cn=masters` and `ipaConfigString` entries.
* `krbPrincipalExpiration`, `nsAccountLock`, `ipaPassKey`,
  `ipaRequireUserVerification`, `member`, `memberOf`, `fqdn`,
  `ipaUniqueID`: existing FreeIPA schema, used as-is. The daemon's
  staging writes GeneralizedTime `krbPrincipalExpiration` exactly as
  `host-add --stage` will.
* `cn=lwca,cn=kuipa,cn=etc` (secrets transport, TODO.md) needs only a
  container when that lands; no new attributeTypes today.

## 7. Sizing note

Per-value sizes the schema must tolerate (docs/src/reference/sizing.md):
binding hashes 43 bytes (binary 32), device records ~1.8 KB, deposits
~6.3 KB (sealed IPUF ≤ 16 KiB), release requests ≤ 1 KB, seal
bindings up to 4096 values. `DirectoryString` (max 2 GB in 389-ds)
covers all of these; only the 16 KiB deposits approach any practical
limit.

## 8. Access control (proposal)

### 8.1 The actor model, restated

Every operation names the identity the directory sees (DESIGN.md §18,
the table at "OTP join / Kerberos join / rekey / …"), and the ACIs
follow from it — the daemon never gets more than its operations need:

| Operation | Binds as | Writes it must be allowed |
|---|---|---|
| OTP join (`--ldap-otp`) | the host entry itself (simple bind) | none new: FreeIPA's join/`KEYTAB_GET` ACIs already apply |
| Kerberos join, rekey | the caller, via S4U2Self + S4U2Proxy (the delegation rule of `docs/src/realm/deploy.md`) | rekey deletes `ipaKUStaged`, `krbPrincipalExpiration`, `userPassword` — but as the daemon, not the caller (§18) |
| stage | the caller (an admin authorised to stage) | `ipaKUStaged`, `krbPrincipalExpiration` on the host |
| escrow bookkeeping | the daemon (`ipa-ku/<server>`) | `ipaKUEscrowBinding` replace; reads both binding attrs and `nsAccountLock` |
| registration (§7.5, `protect --keytab/--file`) | the principal itself (daemon proxies its token) | its own `ipaKUEscrowBinding` / `ipaKUEscrowFileBinding` values |
| voucher join (§9) | the daemon | add the whole host entry (as `host-add` lays out) with `ipaKUVoucherSpent` and `ipaKULease`; `member` on the voucher's host group; `krbPrincipalKey` via `KEYTAB_GET` |
| lease purge (`DESIGN-ci.md` §1) | the daemon | **delete** host entries, but only those carrying `ipaKULease` |
| seals, deposits, releases (§7.6) | the daemon, after accepting the owner's token | the whole `cn=seals,cn=kuipa,cn=etc` subtree |
| device escrow (`DESIGN-recovery.md` §2) | the daemon | `ipaKUDeviceEscrow` on the user's entry |
| server escrow key (§7.6.6) | each server's daemon | `ipaKUServerEscrowKey` on **its own** `cn=masters` entry |
| trusts (§17.4) | the daemon | add/delete exact `ipaKUTrustInvitation` values, `ipaKUTrustedRealm`; add cross-realm `krbtgt` principals and their keys |
| realm settings (`recovery`, `vouchers`, `seal-limits`, `sign-policy`) | the daemon reads; the framework writes | daemon: read only; administrators: write |
| keys operation (§18) | the daemon reads | none — reads `cn=masters` and `ipaConfigString`, both already readable |

### 8.2 The daemon group

FreeIPA's precedent for service principals with directory rights is the
Certificate Managers group (`cn=Certificate Managers`, holding the
`dogtag/*` principals). kuipa mirrors it with a group holding every
server's daemon principal:

```
dn: cn=kuipa servers,cn=groups,cn=accounts,$SUFFIX
objectClass: top
objectClass: groupOfNames
objectClass: ipausergroup
objectClass: nestedGroup
cn: kuipa servers
description: kuipad daemons (ipa-ku/<server> principals)
member: krbprincipalname=ipa-ku/ipa1.example.test@EXAMPLE.TEST,cn=services,cn=accounts,$SUFFIX
```

Every ACI below binds as this group; a new replica is added by putting
its `ipa-ku/<fqdn>` principal in the group (installer step, as
`ipa-replica-manage` does for Certificate Managers).

### 8.3 ACIs for the daemon

Raw ACIs, installed under `cn=etc` / the suffix (FreeIPA
`install/updates/*.update` style). `$SUFFIX` is the base DN; the group
DN below is abbreviated `$KUIPA_GROUP` =
`cn=kuipa servers,cn=groups,cn=accounts,$SUFFIX`.

**Escrow bindings on principal entries** (hosts by FQDN, services and
users by principal name under `cn=accounts`; §7.5). Read includes the
lock check:

```
aci: (targetfilter = "(objectClass=ipaKUPrincipalEscrow)")
  (targetattr = "ipaKUEscrowBinding || ipaKUEscrowFileBinding ||
                 ipaKUStaged || ipaKUVoucherSpent || ipaKULease ||
                 ipaKUDeviceEscrow")
  (version 3.0; acl "kuipa daemons manage escrow state on principals";
  allow (write, read, search, compare)
  groupdn = "ldap:///$KUIPA_GROUP";)
```

**First contact and staging on host entries** (the OTP as Kerberos key
is consumed by deleting `userPassword`; staging replaces
`krbPrincipalExpiration`; the TODO also wants `enrolledBy` set here):

```
aci: (target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")
  (targetattr = "userPassword || krbPrincipalExpiration || enrolledBy")
  (version 3.0; acl "kuipa daemons finish enrollment on hosts";
  allow (write, read, search, compare)
  groupdn = "ldap:///$KUIPA_GROUP";)
```

**Voucher joins** — adding hosts exactly as `host-add` lays them out,
into the voucher's host group, and creating their keys:

```
aci: (target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")
  (targetattr = "objectClass || cn || fqdn || serverHostName ||
                 ipaUniqueID || managedBy || userPassword ||
                 krbPrincipalName || krbCanonicalName ||
                 krbPrincipalExpiration || krbPrincipalKey ||
                 ipaKUVoucherSpent || ipaKULease || enrolledBy ||
                 memberOf || userClass || ipaClientVersion")
  (version 3.0; acl "kuipa daemons add hosts for voucher joins";
  allow (add, write)
  groupdn = "ldap:///$KUIPA_GROUP";)

aci: (target = "ldap:///cn=*,cn=hostgroups,cn=accounts,$SUFFIX")
  (targetattr = "member")
  (version 3.0; acl "kuipa daemons add voucher hosts to host groups";
  allow (write)
  groupdn = "ldap:///$KUIPA_GROUP";)
```

`krbPrincipalKey` write is what `KEYTAB_GET` checks, exactly as the
join extended operation does for a self-enrolling host.

**Lease purge** — the delete right is narrowed by `targetfilter` to
entries carrying the lease, which only the daemon sets
(`DESIGN-ci.md` §1):

```
aci: (target = "ldap:///fqdn=*,cn=computers,cn=accounts,$SUFFIX")
  (targetfilter = "(ipaKULease=*)")
  (version 3.0; acl "kuipa daemons purge expired leases";
  allow (delete)
  groupdn = "ldap:///$KUIPA_GROUP";)
```

**The seal subtree** — full control of seals, deposits and releases;
nothing else in `cn=kuipa` is touched by these:

```
aci: (target = "ldap:///cn=seals,cn=kuipa,cn=etc,$SUFFIX")
  (targetattr = "objectClass || cn || ipaKUSealOwner ||
                 ipaKUSealName || ipaKUSealPolicy || ipaKUSealManager ||
                 ipaKUSealMember || ipaKUSealDepositor || ipaKUSealApprover ||
                 ipaKUSealDevice || ipaKUSealState || ipaKUSealUnlocks ||
                 ipaKUSealSessionKey || ipaKUSealBinding || ipaKUDepositData ||
                 ipaKUReleaseRequest || ipaKUReleaseApproval ||
                 ipaKUReleaseDenied || ipaKUReleaseUses")
  (version 3.0; acl "kuipa daemons manage seals";
  allow (add, delete, write, read, search, compare)
  groupdn = "ldap:///$KUIPA_GROUP";)
```

**Server escrow keys** — a daemon replaces only its own key. The `cn`
of a master entry is the server's FQDN and the binding principal's
name embeds the same FQDN, but 389-ds ACI expressions cannot relate
the two, so the robust form is a per-server ACI written at
install/replica-add time; a group-wide grant with daemons
self-limiting by convention is the weaker fallback:

```
# per server, at ipa-server-install / replica add:
aci: (target = "ldap:///cn=$FQDN,cn=masters,cn=ipa,cn=etc,$SUFFIX")
  (targetattr = "ipaKUServerEscrowKey")
  (version 3.0; acl "kuipa daemon $FQDN sets its escrow key";
  allow (write, read, search, compare)
  userdn = "ldap:///krbprincipalname=ipa-ku/$FQDN@$REALM,cn=services,cn=accounts,$SUFFIX";)
```

**Trusts** — invitations are consumed by deleting one exact value, so
the group gets `write` (add + delete) on the two attributes only, and
the daemon creates the cross-realm `krbtgt` principals with keys as
`ipa-getkeytab -P` does:

```
aci: (target = "ldap:///cn=trusts,cn=kuipa,cn=etc,$SUFFIX")
  (targetattr = "ipaKUTrustInvitation || ipaKUTrustedRealm")
  (version 3.0; acl "kuipa daemons manage trust invitations and partners";
  allow (write, read, search, compare)
  groupdn = "ldap:///$KUIPA_GROUP";)

aci: (target = "ldap:///cn=*,cn=kerberos,$SUFFIX")
  (targetfilter = "(objectClass=krbPrincipal)")
  (targetattr = "objectClass || cn || krbPrincipalName || krbCanonicalName ||
                 krbPrincipalKey || krbPasswordExpiration")
  (version 3.0; acl "kuipa daemons create cross-realm krbtgt principals";
  allow (add, write)
  groupdn = "ldap:///$KUIPA_GROUP";)
```

**Realm settings — read only.** The daemon reads `ipaKURecovery`,
`ipaKUVouchers`, `ipaKUSealLimits`, `ipaKUSignPolicy`, but never
writes them (administrators do, §8.6):

```
aci: (target = "ldap:///cn=*,cn=kuipa,cn=etc,$SUFFIX")
  (targetattr = "ipaKURecovery || ipaKUVouchers || ipaKUSealLimits ||
                 ipaKUSignPolicy")
  (version 3.0; acl "kuipa daemons read realm settings";
  allow (read, search, compare)
  groupdn = "ldap:///$KUIPA_GROUP";)
```

### 8.4 Self-service ACIs

Registration (§7.5, `protect --keytab/--file`) arrives as the
principal itself, proxied by the daemon's delegated ticket, and must be
allowed on the caller's **own** entry:

```
aci: (target = "ldap:///cn=*,cn=accounts,$SUFFIX")
  (targetfilter = "(objectClass=ipaKUPrincipalEscrow)")
  (targetattr = "ipaKUEscrowBinding || ipaKUEscrowFileBinding")
  (version 3.0; acl "principals register their own escrow bindings";
  allow (write)
  userdn = "ldap:///self";)
```

Staging runs as the admin who stages (`host-add --stage`), which is
an authorisation decision, not self-service: it is a framework
permission (§8.6), not a raw ACI, so administrators can delegate it to
helpdesk without touching `cn=etc`.

### 8.5 Read posture

FreeIPA's default "Enable Anonymous access" ACI exposes a fixed list of
common attributes; none of the `ipaKU*` attributes are in it, so by
default **no one but the ACIs above can read or search any kuipa
attribute**. The proposal keeps it that way:

* **Seal subtree** (`cn=seals` and children): no read ACI for anyone
  but the daemons — seal entries carry sealed session keys and
  per-device public keys, and the owner's access path is the protocol,
  not the directory. A future framework front end (§7.6.11 TODO) would
  add an explicit permission, never a subtree-wide authenticated-read
  ACI.
* **Device escrow** (`ipaKUDeviceEscrow` on user entries): daemon-only;
  the values are sealed to device keys, but they are nobody else's
  business either.
* **Binding hashes, staging, voucher salts, leases** on principal
  entries: daemon-only reads suffice today. If the framework grows
  `host-find`-style display of escrow state, it should come as a read
  permission granted to a privilege, never as a subtree-wide
  authenticated-read ACI.

### 8.6 FreeIPA permissions (framework layer)

Administrator-facing knobs become managed permissions, so they can be
delegated through roles instead of editing ACIs:

```sh
# Realm settings: who may set the four JSON knobs. Add to a new
# privilege, e.g. "Kuipa Configuration", granted to admins by default.
ipa permission-add 'Manage kuipa realm settings' \
  --attrs={ipaKURecovery,ipaKUVouchers,ipaKUSealLimits,ipaKUSignPolicy} \
  --type=attr --bindtype=permission

# Staging: who may run host-add --stage / stage for a host.
ipa permission-add 'Stage kuipa host enrollment' \
  --attrs={ipaKUStaged,krbPrincipalExpiration} \
  --type=attr --bindtype=permission

# Seal administration front end (future): read/search on the seal
# subtree for the framework's list/revoke commands.
ipa permission-add 'Read kuipa seals' \
  --filter='(objectClass=ipaKUSeal)' \
  --subtree=cn=seals,cn=kuipa,cn=etc,$SUFFIX
```

The raw daemon ACIs of §8.3 stay out of the permission framework
deliberately: they are infrastructure, installed and upgraded by the
server packages (as Custodia's and Dogtag's are), not delegatable
administrator surface.

### 8.7 Prerequisite outside the directory

The Kerberos half of "the daemon acts for callers" is not an ACI at
all: the servicedelegation rule of `docs/src/realm/deploy.md`
(`ipa-ku/<server>` → target `kuipa-ldap` → `ldap/<fqdn>`) is what
lets the daemon obtain the proxied ticket an LDAP SASL GSSAPI bind
accepts. The ACIs in §8.4 then see the *caller's* identity. Without
the rule, Kerberos joins and registrations fail closed before any
directory check runs.
