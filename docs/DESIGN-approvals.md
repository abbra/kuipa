# kuipa release approvals: M of N before a break-glass release

A vault's policy can require **approvals**: before a server releases its
share of a file, `m` people from a named set must have approved that
release, and none of them may be the person asking. The requester still
needs every factor the policy names. Each request, approval and denial
is a transparency-log event, so the vault's members and its approvers can
see who agreed to what.

This is the control-group pattern of OpenBao and HashiCorp Vault, applied
to kuipa's server share (DESIGN.md §7.6.4). It is for emergency access to
a team's or a person's sealed secrets, which today rests on one person
holding the factors.

| piece | status |
|---|---|
| the `approvals` policy field, release requests, approvals, denials | implemented |
| the release check and the request in `IPEQ` | implemented |
| `kuipa seal request`, `pending`, `approve`, `deny`, `open --request` | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |

## 1. Policy

```json
"approvals": {
  "m": 2,
  "from": { "groups": ["security-oncall"], "users": ["carol"] },
  "window": 86400,
  "uses": 1
}
```

| field | meaning |
|---|---|
| `m` | approvals needed, at least 1 |
| `from` | who may approve, named as a shared vault's members are (DESIGN.md §7.6.12): users, groups, hosts and services, groups by `memberOf` |
| `window` | how long a request may wait for approvals and then be used, in seconds; default 1 day, at most 7 days |
| `uses` | how many releases one approved request covers, default 1 |

The policy is checked as any other (DESIGN.md §7.6.2): `m` at least 1,
`from` non-empty, and `m` no more than the number of named users when
`from` names users only (groups are counted when approvals are, §3). A
vault with approvals cannot have **offline sessions**: they release
epoch keys that open files without a server, hence without approvals.
Re-authentication sessions stay allowed: they stand in for the ticket,
not for the approvals.

## 2. A release request

The requester asks first, with their ticket, as the vault operation
`request` (`kuipa seal request VAULT FILE.sealed --reason TEXT`):

```text
request = { vault, requester, bindings: [H(ct)] of the file's server
            slots, reason (at most 512 bytes), created, not_after =
            created + window }
```

The server checks that the requester may open the vault at all (a role,
DESIGN.md §7.6.12), stores the request as a child entry
`cn=<request id>,cn=<vault id>,cn=vaults,cn=kuipa,cn=etc,<suffix>`
(class `ipaKURelease`, the request as JSON in `ipaKUReleaseRequest`; the
id is 16 random bytes in hex), logs it, and answers with the request in
the vault reply (`IPVR` version 3 carries release requests). A request names one file by its bindings: an approval is for that
file, not for the vault. A request for several files names all their
bindings.

The approvers learn of it out of band (an on-call page, a ticket) or by
asking: `kuipa seal pending` lists the open requests of every vault whose
`approvals.from` admits the caller, and of the vaults they have a part in,
with the requester, the reason and the approvals so far. To find the
first kind, a vault entry keeps its approvers beside its policy, as
`kind:name` values in `ipaKUVaultApprover`; the server names them in one
spelling each when it sets the policy, as it does a shared vault's
members.

## 3. Approving and denying

`kuipa seal approve VAULT REQUEST` and `kuipa seal deny VAULT REQUEST`
are vault operations authenticated by the approver's ticket. The server
checks that:

* the request exists, is not denied and has not passed `not_after`;
* the approver is admitted by `approvals.from` now and is not locked;
* the approver is not the requester.

It then logs the event and adds one value `<approver> <time>` to the
request's `ipaKUReleaseApproval` (or to `ipaKUReleaseDenied`). An
approver approves a request once. Values are added, never replaced, so 389-ds replication merges
approvals made on different servers as it merges unlock counts (DESIGN.md
§7.6.7). One denial ends the request on every server once replicated.

**Counting.** At release, a server counts the distinct approvers who are
still admitted by `from` (groups looked up again) and not locked, leaving
out the requester. An approver who left the group since no longer counts.
Approvals are never signed by the approvers: as for every other check of
a release, the servers are trusted to apply the policy, and the log makes
what they did visible.

## 4. The release

The recovery request gains an optional field, the release request id, in
a new version of `IPEQ` (DESIGN.md §7.6.5):

```text
IPEQ v2 = P ‖ V ‖ t_i ‖ RecoveryRequest ‖ device id ‖ [GSS-API token]
          ‖ [WebAuthn assertion] ‖ [session token] ‖ [release request id]
```

For a vault with `approvals`, after its other checks (§7.6.5 step 3, the
opener of §7.6.12), the server also requires:

1. a release request id, naming a request of this vault;
2. the opener is the request's requester;
3. the file's binding `H(ct)` is among the request's bindings;
4. now is before the request's `not_after`, and it is not denied;
5. at least `m` approvals count (§3);
6. the request's uses, summed over the servers (per-server values, as
   unlock counts), are fewer than `uses`.

It counts one use in `ipaKUReleaseUses` (one `<server> <count>` value per
server), logs the release as any other, and answers as usual. Like
`max_unlocks`, `uses` can be exceeded by the releases other servers make
within one replication delay; every other check is exact.

An approval made on one server counts on another once it has
replicated. `kuipa seal open --request ID` tries the file's servers in
turn, as every open does, so a server that has not seen the approvals yet
refuses and the next one answers.

## 5. The log

Three vault actions join DESIGN-tlog.md §6, all of kind 4 (releases):

| action | digest of |
|---|---|
| `request` | the request: id, requester, bindings, reason, `not_after` |
| `approve` | request id ‖ approver |
| `deny` | request id ‖ approver |

The release itself is logged as today, by the file's binding: together
with the request's event, whose digest covers the same bindings, it shows
which approved request a release used. `kuipa tlog watch` lists requests,
approvals and denials.

## 6. What it protects, and what not

| someone | without approvals | with approvals |
|---|---|---|
| a member with the factors, acting alone | opens | needs `m` others |
| `m` approvers, without the factors | nothing | nothing: approvals add a condition, never replace a factor |
| the requester approving their own request | — | does not count |
| a realm administrator with the servers' escrow keys | as before (DESIGN.md §7.6.10): the server share, so a vault without the device factor | the same: approvals are a server check, and the escrow keys bypass the servers |

So approvals stop one person with access from acting alone; they do not
stop the realm's administrators, who can already reach the server share.
A vault meant to resist administrators needs the device factor, as
before.

**Alternative considered: splitting the server share.** sops splits a
data key among key groups (Shamir), which also binds administrators.
Here it would mean sealing shares of `A` to approvers' devices and having
`m` of them decrypt and hand their shares to the requester. That needs
every approver's device at hand for every release, puts shares of `A` on
approvers' machines, and changes the sealed format. The server-checked
approval keeps the format and works with approvers who approve from any
host with a ticket; a split can come later as a separate policy if
resisting administrators is needed.

## 7. Decisions

* **Per vault, never a realm limit.** Approvals are a property of one
  vault's policy, chosen for that vault. The realm limits (DESIGN.md
  §7.6.2) cannot require them: a realm-wide requirement would hold up
  every release in the realm, including the ones that must happen without
  a human, and the realm would stop working.
* **Machines break glass without approvals.** A host's or service's
  sealed keytab and files are machine vaults with a fixed policy
  (DESIGN.md §7.6.8): they open at boot, unattended, so they never wait
  for approvals. Break-glass access to a machine's secrets is a vault of
  its own kind for that purpose, without approvals, rather than an
  approvals vault.
* **No notifications.** As in OpenBao, kuipa does not notify anyone;
  `kuipa seal pending` and the log are the interface. A hook for paging
  systems could come later.
