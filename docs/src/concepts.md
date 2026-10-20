# Concepts

## Anchors: how a host knows it talks to its realm

Before a host trusts anything from a server, it must know the server
belongs to its realm. kuipa does not rely on DNS or on TLS for that: both
are classical, and a host joining for the first time has no CA yet.

Instead, each IPA server holds an **anchor**: an ML-DSA key that stays on
the server. Anchors vouch for servers: every minute (by default) the servers run
an **anchor exchange**, authenticated with their own Kerberos keys, in
which each anchor signs a statement that lists the servers it trusts. A
server publishes its **advertisement** (`GET /ipa/ku/adv`): its keys, the
realm's configuration and CA, signed by the server and carrying the
anchors' vouches for it.

A host verifies an advertisement against an anchor it already **pins**:

* an **enrollment string** carries the thumbprint of the anchor of the
  server that issued it:

  ```text
  ipa-ku1:EXAMPLE.TEST:<anchor thumbprint>:<expiry>[:<OTP or secret>]
  ```

* or the anchors are pinned ahead of time in `/etc/ipa/ku-anchors`, for
  images and configuration management.

An enrolled host keeps the realm's current anchors pinned and refreshes
them at every key rotation.

* **A host that pins two anchors** demands that two different anchors
  vouch for a server. A single stolen anchor then cannot impersonate the
  realm to it.
* **Anchors rotate.** An old anchor signs a hand-over to its successor,
  so pinned hosts follow.
* **A host also keeps a watermark** of the realm's anchor history, and
  refuses a server that is behind it.

## Enrollment: joining without classical secrets on the wire

```mermaid
sequenceDiagram
    participant H as Host (kuipa)
    participant S as IPA server (kuipad)
    participant D as 389-ds / KDC
    H->>S: GET /ipa/ku/adv?anchor=<pinned>
    S-->>H: advertisement (ML-DSA signed, vouched by anchors)
    Note over H: verify against the pinned anchor
    H->>S: join request, encrypted to the advertised ML-KEM key,<br/>with the host's proof (OTP, password ticket, ticket or voucher)
    S->>D: authorise as the caller, create keys (as ipa-join does)
    D-->>S: keytab
    S-->>H: keytab, CA chain, realm configuration (ML-KEM)
```

The host proves it may join in one of these ways:

| proof | who uses it |
|---|---|
| a one-time password from `ipa host-add --random` | the classic way, now also a temporary Kerberos key of the host |
| a user's password | `ipa-client-install -p admin` habits; the password never leaves the host |
| an existing Kerberos ticket | administrators with a ticket, external IdP or passkey users |
| a voucher | autoscalers and image pipelines: single use, bound to one hostname |
| a staged bundle | hosts with no network at first boot: the keys arrive in a signed, sealed file |

When the proof is Kerberos-based, the server's answer is also bound to the
realm's Kerberos keys. Then even a server built on a stolen anchor cannot
answer.

## Keys rotate

`kuipa rotate-keys` (run monthly by `kuipa-rotate.timer`) gets the host new
keys over the same protected exchange, authenticated by its current keys.
A recording of the exchange plus the old keys does not reveal the new
ones.

## Sealed keytabs and files

A sealed keytab or file is encrypted so that opening it needs one of the
realm's servers. Each server's share is bound to a key only that server
holds, and is released only for bindings registered on the principal's
entry in IPA.

```mermaid
sequenceDiagram
    participant U as kuipa-unseal (boot)
    participant S as IPA server
    U->>S: recovery request: principal, vault, commitment,<br/>binding (encrypted to the server's escrow key)
    Note over S: check the commitment, the registered binding,<br/>and that the principal is not locked
    S-->>U: the share
    Note over U: open the keytab into /run (memory only)
```

* `kuipa protect` seals the host keytab; `--keytab` a service's keytab;
  `--file` any file. The file on disk becomes a link to an unsealed copy in
  memory, refilled at every boot.
* Removing the host (or locking it), or sealing again, makes old copies
  stop opening.

## Vaults: users' own sealed files

A **vault** is a set of rules a user keeps on the IPA servers: which
**factors** opening a file needs (a registered **device** key, the user's
**ticket**), until when, how many times, whether **sessions** are allowed.
A sealed file holds two shares:

* a **server share**, released only under the vault's rules;
* a **device share**, which only one of the user's registered devices can
  open.

Neither opens the file alone, so an IPA administrator holding the servers'
keys still cannot read users' files. See
[Sealing your own files](user/sealing.md).

## Tang

`kuipad` can also act as a post-quantum **Tang** server, and `tang-pqc` is
its Clevis pin: LUKS volumes bound to it unlock automatically wherever the
servers are reachable. Unlike sealed keytabs, Tang is stateless by design:
anyone with the volume and network access to a Tang server can unlock it.
