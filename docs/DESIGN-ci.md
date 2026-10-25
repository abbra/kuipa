# kuipa for CI runners: leased identities and pipeline secrets

CI runners are created by the hundred and destroyed after a job or a day,
and usually get their secrets from a long-lived token pasted into the CI
system. kuipa already joins machines without a password, by vouchers
(DESIGN.md §9), and opens sealed files for a host by its ticket (shared
vaults, §7.6.12). This design adds the two missing pieces:

1. a **lease**: a voucher can say how long the host it creates may live,
   and the realm ends that host on its own when the lease runs out;
2. **pipeline secrets**: files sealed to a shared vault whose members are
   the runners' host group, which open only for a leased host, with its
   ticket, while its lease lasts.

| piece | status |
|---|---|
| the voucher `lease`, leased host entries, their removal | designed |
| the `ticket.leased` policy option | designed |
| runner setup: voucher join, protected keytab in gssproxy | works today (DESIGN.md §7.4, §9) |

## 1. Leases

The voucher message (DESIGN.md §9) gains a lease, in a new version:

```text
m = "IPVN" ‖ realm ‖ fqdn ‖ hostgroup ‖ not_before ‖ not_after ‖ lease ‖ binding
```

`lease` is the host's lifetime in seconds from its join, 0 for none
(an `IPVM` voucher is a voucher with no lease). The provisioner chooses
it (`kuipa-voucher request --lease 4h`); the issuer still sees only `μ`.
The realm caps it: `max_lease` in the realm's voucher settings, default 7
days.

When the server joins a host by a voucher with a lease, the directory
also sets, as the daemon:

* `krbPrincipalExpiration` = join time + lease, so the KDC issues the
  host no ticket after it, whoever holds its keys;
* `ipaKULease` = the same time, marking the entry as leased.

A rekey (DESIGN.md §6) of a leased host keeps both: a lease cannot be
extended, only replaced by a new host with a new voucher. Each kuipad
server, in its maintenance loop, deletes the host entries whose
`ipaKULease` passed more than an hour ago (the hour lets a running job
finish logging), with their escrow bindings and host-group membership;
the deletion is logged. The daemon deletes only entries carrying
`ipaKULease`, which only it sets, so its ACI can be limited to them.

## 2. Pipeline secrets

A pipeline's secrets are files sealed to a shared vault owned by the
people who run the pipeline:

```text
vault ci-admins/deploy (owner: a CI administrator)
  members:  hostgroup ci-deploy-runners
  managers: group ci-admins
  factors:  ticket;  ticket.delegation = refuse;  ticket.leased = true
  sealing:  registered
```

* **No device factor.** A runner lives too briefly for files to be
  sealed to its device: every new runner would need every file resealed.
  The ticket alone opens, which the realm limits must allow for the
  vault's owner (DESIGN.md §7.6.2: a group entry for the CI
  administrators with `"factors": [{"ticket": true}]`).
* **`ticket.leased`**, a new policy option: the opener must be a host
  whose entry has an `ipaKULease` still in the future. Without it, any
  member of the host group opens, including a long-lived host added to
  the group by mistake, or one whose keytab was copied. With it, a
  leaked keytab is worth at most the rest of the lease, and nothing once
  the KDC stops issuing tickets for the host.
* **`ticket.delegation = refuse`**: only the runner's own ticket, never
  one obtained for it by another service.
* **`sealing = registered`**: rotating a secret (`kuipa seal reseal`)
  retires every older copy, including copies baked into old images or
  cached by old jobs.

The CI administrators seal secrets from their own hosts with their own
tickets, as managers, and commit or upload the sealed files anywhere:
without a leased runner's ticket they are useless.

## 3. A runner's life

1. The autoscaler creates a VM whose first boot runs `kuipa voucher-key`
   and reports the ephemeral public key (cloud-init, a metadata tag).
2. The CI controller, as provisioner, requests a voucher bound to that
   key for the VM's FQDN, host group `ci-deploy-runners` and a lease of,
   say, 4 hours; the issuer signs it blind.
3. The VM runs `kuipa enroll --voucher-file V --ephemeral-key K`, then
   `kuipa protect`, so its host keytab is sealed and gssproxy loads it
   through `kuipa-unseal --memfd` (DESIGN.md §7.4): a copy of the VM's
   disk holds no usable keytab.
4. A job runs `kuipa seal open deploy-key.sealed --out -` with the
   host's ticket; the server checks the vault's policy, the host group,
   the lease and the binding, and releases.
5. The VM is destroyed after its job. If it is not, its lease ends
   anyway: no tickets, and its entry is deleted an hour later.

One runner should serve one job, or jobs of one trust level: a runner
that ran another project's job holds that project's released secrets in
memory. Separate host groups per project or environment keep the vaults
apart.

## 4. What each party gets

| someone has | with `ticket.leased` |
|---|---|
| a sealed pipeline secret | nothing |
| it and a CI administrator's ticket | the secret (they are its managers) |
| it and a runner's keytab, during the lease | the secret, as the runner would |
| it and a runner's keytab, after the lease | nothing: no ticket, then no host |
| it and a long-lived host's keytab, the host in the runners' group | nothing: not leased |
| the realm's escrow keys | the secret: a vault without the device factor (DESIGN.md §7.6.10) |

## 5. Decisions

* **Leases end hosts rather than tickets only.** The KDC already stops
  tickets at `krbPrincipalExpiration`; deleting the entry as well keeps
  the directory from filling with dead runners, and frees the FQDN for
  the next VM.
* **No new factor for runners.** A lease is a property of the opener's
  host entry, checked like `nsAccountLock`, not something the runner
  presents; `ticket.leased` adds a check, not a credential.
* **Kerberos, not CI tokens.** GitHub's and GitLab's OIDC job tokens
  could be exchanged for kuipa releases instead; that would need a
  token-exchange design of its own, and gives up the one identity system
  the rest of the realm uses. It stays out of scope here.
