# kuipa — open work

What exists and how it is tested is in [docs/DESIGN.md](docs/DESIGN.md)
§19. This list holds only what remains; section numbers refer to
DESIGN.md.

Rules for new code: Rust 2024 edition, MSRV 1.88 (`clippy::incompatible_msrv`
is denied); dependencies from `native-ossl`, `synta`, the akamu/ahdapa stack
(`reqwest`, `rustls-native-ossl`, `axum`, `tokio`, `agirru-crdt`,
`agirru-engine`, `hickory-resolver`, `tracing`), `synta-mtc`, the in-tree
`tang-pqc` and `ml-dsa-blind`, and `serde`, with system
libraries only through the borrowed FFI crates. No RustCrypto crates
(the `deps` CI job checks): cryptography comes from OpenSSL.

## Verification

- [ ] Run the daemon's `LdapDirectory` against a real FreeIPA server
      (container or VM): OTP and password binds, the join and `KEYTAB_GET`
      extended operations, S4U2Self/S4U2Proxy, the escrow and staging
      attributes, staged-key expiry, replication and failover (§11.4); the
      anchor exchange between real servers, with peers from `cn=masters`
      and TLS against the IPA CA (§4.2); voucher joins (host entry, host
      group, `ipaKUVoucherSpent`); trust invitations and the cross-realm
      `krbtgt` principals created with `KEYTAB_GET` and a password, and a
      cross-realm ticket through them (§11.4, §17.4).
- [ ] Run the `tang-pqc` pin under real Clevis: `clevis luks bind` on a
      LUKS2 volume, `clevis luks unlock`, `clevis luks regen` after
      `tang-rotate`, and unlocking at boot from the dracut module (§10.7).
- [ ] Check emitted log heads and cosignatures with a C2SP
      tlog-witness implementation, once the ML-DSA note format is
      settled (`DESIGN-tlog.md` §6).
- [ ] Extend the Tamarin model (`contrib/tamarin/kuipa.spthy`) beyond the
      core exchange: user vaults and the unified recovery request (§7.6),
      vouchers (§9), trust establishment (§17.4), signing statements
      (`DESIGN-sign.md`). Re-prove whenever a modelled flow changes;
      encodings and hash choices are abstracted and need no re-proof.

## Protocol and implementation

- [ ] User vaults (`kuipa seal`) and the unified recovery request (§7.6),
      in phases:
  - [x] 1. `tang-pqc` commitments (`provision_committed`,
        `OpenedRequest::verify_commitment`).
  - [x] 2. Unified recovery request; host and service escrow as machine
        vaults carrying the commitment.
  - [x] 3. Vault model: policy, limits, devices, signed descriptor, `IPUF`
        two-share format, answers encrypted to the device, server vault
        operations and the ticket factor (with `ticket.delegation` checked
        against whatever the directory reports as transited services).
  - [x] 4. The vault container in LDAP, HTTP routes, test directories.
  - [ ] 5. Delegated tickets: PAC S4U delegation info for
        `ticket.delegation` (deferred; work in progress on branch
        `vault-pac-delegation`: generated NDR from pidl-rs, committed,
        with `samba-ndr` as the dependency). Until then kuipad reports the
        delegation as unknown, which only `allow` accepts.
  - [x] 6. `kuipa seal` with passphrase file devices and per-user state.
  - [x] 7. Re-authentication sessions; the unlock counter (per-server
        values on the vault entry).
  - [x] 8. Offline sessions.
  - [x] 9a. PKCS#11 devices: an ML-KEM key on a token through
        pkcs11-provider (no attestation yet: registered at `any`).
  - [ ] 9b. Passkeys (libfido2 FFI, relying-party verifier from ahdapa).
  - [x] Registered sealing (`sealing = registered`).
  - [x] Realm limits per group, and the factor sets a policy must meet
        (§7.6.2).
  - [x] Shared vaults (§7.6.12): managers and members by user, group,
        host or service, devices held by members, `OWNER/NAME`
        references, `kuipa seal share`/`unshare`; departed members'
        devices pruned at every vault operation; user-vault releases
        rate-limited per opener.
  - [ ] Attestation for the `hardware-wrapped` and `hardware-bound` levels.
- [ ] TPM factor for sealed keytabs and `kuipa prepare --tpm` (§7.1, §8.2).
- [x] Secrets transport (§18): the `keys` operation in `kuipa-enroll`
      (`IPKG`/`IPKR`) and its route in kuipad; handler execution with
      runas and the static namespace policy checked against `cn=masters`
      and the CA role; `kuipa keys fetch`; an audit line per operation;
      a replica-promotion scenario in the playground (web7 enrolls, is
      refused outside `cn=masters`, joins, fetches the promotion set).
- [ ] Secrets transport, remaining: run the LDAP policy check against a
      real FreeIPA server (`cn=masters`, the CA role); sealed
      lightweight-CA artifacts (an `lwca-store` handler, the
      `cn=lwca,cn=kuipa,cn=etc` container) and the Dogtag-side ML-KEM
      import. (The `keys` section is in `contrib/kuipad.json.example`.)
- [x] gssproxy as the keytab holder in `kuipa protect`, once gssproxy's
      `keytab_loader` is merged (§7.4): write the service's gssproxy
      configuration (`cred_store = keytab:MEMORY:<name>`, `keytab_loader =
      /usr/libexec/kuipa-unseal --sealed <path>.sealed --memfd`) instead of
      the tmpfs copy, and send it `SIGHUP` after a reseal.
- [ ] MTC: anchors issued as Merkle Tree Certificates and pre-distributed
      tree heads (§16).
- [x] Notice a stolen anchor where the host knows only one: done as the
      anchor epoch log (§4.8) — canonical per-sequence entries signed by
      the current anchors, a `(sequence, head)` in every advertisement,
      a public `anchor-log` route, and an `epoch` watermark line in
      `/etc/ipa/ku-anchors`.
- [ ] S4U2Proxy with the caller's evidence ticket instead of protocol
      transition (§16).
- [x] Typed transparency logs (`DESIGN-tlog.md`): typed leaves,
      tombstones, signed heads, consistency proofs, witness cosignatures
      (`kuipa-witness`, required counts on hosts), vault, escrow, Keys and
      signing events with receipts, `kuipa tlog watch`, `kuipa-audit tlog`;
      claim logs migrated onto typed leaves.
- [ ] Transparency logs, remaining: the tlog-tiles layout and a C2SP
      signed-note checkpoint with a witness endpoint (§6); logging the
      opening of machine (keytab) bindings, which only vault releases are
      today; mirroring the logs in `kuipa-mirror`; token-key epochs
      (kind 7) once tokens exist.
- [x] Kerberos-bound signing (`DESIGN-sign.md`): the `sign` operation,
      the signing policy with `memberOf` groups, batches, offline bundles,
      `kuipa sign`, `kuipa-gitsign`.
- [ ] Signing, remaining: per-principal rate limits in the signing
      policy; PAC groups in place of `memberOf` (with the PAC work above).
      RPM and OCI keep their OpenPGP signing and are out of scope.
- [x] Hashes and proof levels follow the system crypto policy
      (`DESIGN.md` §4.1.1): signer-bound data by the key's category,
      KEM-bound data by the KEM, keyless values SHA-384; `ml-dsa-zk` at
      λ = 256 under CNSA 2.0. RFC 7638 thumbprints stay SHA-256 by
      decision (Clevis).
- [ ] Unlinkable tokens (`ml-dsa-blind/DESIGN.md` §6,
      `ml-dsa-zk/DESIGN.md` §4), in order:
  - [x] 1. VOLE-in-the-head proofs over boolean circuits, a Keccak-f
        gadget, AES-256/SHA-512 only, λ by the crypto policy.
  - [ ] 2. VOLE over an extension of `F_q` for `Z_q` arithmetic
        (Baum–Beckmann, ePrint 2026/2473).
  - [ ] 3. Conversions between committed bits and `Z_q` values.
  - [ ] 4. The ML-DSA verification circuit, ML-DSA-87 first.
  - [ ] 5. `BlindSignature::anonymize()` behind a `zk` feature; the token
        protocol (`IPNQ`/`IPNR`/`IPNT`, per-principal quotas, spent sets,
        token keys logged as kind 7).
  - [ ] 6. Proof-of-work grinding on Δ, a soundness bound for the
        parameters, constant-time review, and review by someone else.

## Planned use cases

From the book's [What kuipa is for](docs/src/use-cases.md); each needs a
design first.

- [ ] Offline logins without a crackable SSSD cache: a Kerberos-bound
      operation arms a host while online with a signed offline grant (one
      user, one host, a window) and a per-user TPM-sealed object; needs the
      TPM factor.
- [ ] Recovery after losing every device and deposits of LUKS and
      backup recovery keys (`docs/DESIGN-recovery.md`):
  - [x] Recovery codes (`kuipa seal recovery-code`, `recover code`,
        `recover finish`).
  - [x] Depositors and deposits (`kuipa seal deposit put|list|fetch|retire`).
  - [x] `kuipa escrow luks`, `kuipa escrow file` for hosts, and services
        or users by their keytabs; **not yet run** against a real LUKS
        volume.
  - [x] Device-key deposits in a helpdesk vault, and their delivery
        (`kuipa seal recover helpdesk|deliver|fetch`).
- [x] M-of-N approvals for break-glass releases, recorded in the
      transparency log (`docs/DESIGN-approvals.md`).
- [ ] Short-lived CI runner identities (voucher leases, `ticket.leased`)
      and pipeline secrets in shared vaults: designed in
      `docs/DESIGN-ci.md`.
- [ ] Recipes in the book: Ansible vault passwords, `systemd-creds` and
      container secrets, `tang-pqc` file encryption, `realm-info` for
      unenrolled machines.

## Outside this workspace

- [ ] FreeIPA: adopt the secrets transport (§18) — the design is
      `doc/designs/kuipa-secrets-transport.md` in the FreeIPA tree.
      `CustodiaInstance` grows a kuipa branch gated on peer capability
      (a service entry for kuipad in `cn=masters`); `ipa-pki-retrieve-key`
      shells out to `kuipa keys fetch`; the LWCA artifact producer; the
      `cn=lwca,cn=kuipa,cn=etc` container and ACIs; retirement of
      `ipa-custodia`, the vendored server, the `cn=custodia` tree and
      `_wait_keys`.
- [ ] FreeIPA server: schema (`ipaKUEscrowBinding`, `ipaKUEscrowFileBinding`,
      the `ipaKUVault` class with `ipaKUVaultOwner`, `ipaKUVaultName`,
      `ipaKUVaultPolicy`, `ipaKUVaultDevice`, `ipaKUVaultState`,
      `ipaKUVaultUnlocks`, `ipaKUVaultSessionKey`, `ipaKUVaultBinding`,
      `ipaKUVaultManager`, `ipaKUVaultMember`, `ipaKUVaultApprover`
      (indexed for equality), the `ipaKURelease` class for release
      requests under a vault (`ipaKUReleaseRequest`,
      `ipaKUReleaseApproval`, `ipaKUReleaseDenied`, `ipaKUReleaseUses`),
      `ipaKUDeviceEscrow` on user entries (written by the daemon),
      `ipaKUVaultDepositor` (indexed for equality), the `ipaKUDeposit`
      class for deposits under a vault (`ipaKUDepositData`), `ipaKURecovery`
      on a `cn=recovery,cn=kuipa,cn=etc` entry,
      `ipaKUServerEscrowKey` on
      `cn=masters` entries,
      `ipaKUVaultLimits`, the `cn=vaults,cn=kuipa,cn=etc` container, `ipaKUStaged`, `ipaKUVoucherSpent`, `ipaKUTrustInvitation`,
      `ipaKUTrustedRealm`) and
      the `cn=trusts,cn=kuipa,cn=etc` entry; ACIs for the daemon's identity
      (including adding hosts and host-group members for vouchers, and
      cross-realm `krbtgt` principals and their keys for trusts, and the
      escrow attributes on service and user entries as well as hosts, §7.5);
      framework commands (`pq-anchor-show`,
      `host-add/host-mod --pq-stage`, enrollment strings from `--random`,
      `--clear-pq-escrow`, also for services and users); `host-disable` and
      `service-disable` must also set `nsAccountLock`, so a disabled
      principal is locked out of PKINIT and its sealed keytabs and files
      stop opening (§7.2); installers and
      upgrade (`kuipad generate-keys` on every server and replica, the `ipa-ku/<server>`
      principal, keytab and delegation rule), httpd snippet, SELinux module
      (`kuipa_unseal_t`). Enrollment strings use the issuing server's
      anchor and expire (`kuipad enrollment-string --days N`, §4.4);
      `pq-anchor-show` lists the realm's anchors from the advertisement.
      `host-add --random` also sets the OTP as the host's Kerberos key, with
      `krbPrincipalExpiration` at the string's expiry, so OTP joins get a
      Kerberos root (§5.3; until then `kuipa enroll --ldap-otp`); the
      daemon's first-contact rekey should also set `enrolledBy`, as the join
      extended operation does. A `rotate-anchor` workflow for replicas
      (§4.7): reissue strings and image pins, and check that every host has
      rekeyed within the succession's lifetime.
- [ ] FreeIPA client: `ipa-client-install --pq-enroll`, `--pq-bundle`,
      `--no-pq`; for `-p` with external IdP or passkeys: `kuipa realm-info`,
      temporary `KRB5_CONFIG` and ccache, `kinit -n`, armoured `kinit -T`,
      `kuipa enroll --use-ccache`; for password users `--principal` (an
      armoured `kinit` in `kuipa`, §5.3); the units in `contrib/`.
- [ ] gssproxy: release upstream version with per-service `keytab_loader`
- [ ] FreeIPA trusts: a `trust-add --type=ipa` front end for
      `trust-invitation` / `establish-trust`, and the trust objects next to
      the recorded partners; run
      `kuipa trusted-realms` after enrollment and from a timer; SSSD
      reading `/etc/krb5.conf.d` (Fedora's `krb5.conf` already has
      `includedir`).
- [ ] SSSD: LDAP TGT and ticket validation through GSS-API and gssproxy,
      anonymous-PKINIT armour, so `host/<fqdn>` can move to gssproxy (§7.4).
- [ ] Fedora packaging of the crates and their missing dependencies.
