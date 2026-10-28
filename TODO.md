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
- [ ] Extend the Tamarin model (`contrib/tamarin/kuipa.spthy`) beyond
      the core exchange. Done so far: pins and advertisement
      verification, the join/rekey key schedule, OTP and Kerberos
      authenticators, sealed-keytab escrow (§7.2), user seals and the
      unified recovery request (§7.6.4–7.6.5), vouchers (§9). Each item
      below adds rules and lemmas in the model's established idioms
      (decryption-by-fact, shallow `In()` patterns, attack lemmas as
      events carrying the compromised material); re-prove the whole file
      after each item, since new rules can break old lemmas (the voucher
      rules made `SealedNoOffline` harder). Encodings and hash choices
      are abstracted and need no re-proof.
  - [ ] 1. Trust establishment (§17.4, closes the last named TODO
        item): the invitation, the trust request, the trust secret,
        cross-realm `krbtgt` key creation, the partner refresh, and a
        cross-realm ticket through them. Lemmas: an accepted trust maps
        to an administrator-authenticated invitation on both sides
        (agreement); a forged trust needs a stolen anchor or the trust
        secret; the cross-realm ticket authenticates the partner realm
        to the one that trusts it. Attack lemma: a leaked trust secret
        lets the attacker mint the cross-realm keys.
  - [ ] 2. Signing statements (`DESIGN-sign.md`): the `sign`
        operation's policy check (user, group, host, service), the
        signed statement, and offline verification of bundles as of
        their time. Lemmas: a verified statement implies an authorized
        signer under a policy the realm pinned at that time (no
        retroactive policy tampering); offline bundle verification
        binds the statement to its delegation window. Attack lemma:
        a statement signed outside the policy verifies only with a
        compromised signing key.
  - [ ] 3. Offline enrollment bundles (§8): staging, modes A (machine
        key), B (secret `S`) and C (signed only), opening, first
        contact, re-staging key replacement. Lemmas: a mode A/B bundle
        copied off the wire opens nothing without `dk_m`/`S`; tampering
        needs a delegated server key (the signature covers the
        ciphertext); a replayed bundle after re-staging is refused
        (KDC keys replaced). Attack lemmas, §8's own table: mode C
        copied yields the host identity until first contact or
        `not_after`; a mode B bundle plus the enrollment string's `S`
        yields the identity. `not_after` is a clock property -- model
        it as the KDC's `!ValidHostKey` retiring staged keys, which is
        how the design enforces it.
  - [ ] 4. Secrets transport (§18): the `keys` operation, the
        runas handler, the `cn=masters`/CA-role policy. Lemmas: a key
        fetched by a host implies an authorized handler ran for a
        caller the policy admits (no confused-deputy); sealing to the
        request's key. Attack lemma: a fetch outside the policy
        succeeds only with a compromised server.
  - [ ] 5. Machine seals on the unified path (§7.6.8): migrate the
        §7.2 model (`SealedFile`/`recover`) onto the IPEQ recovery
        request with the fixed machine policy, so host and service
        escrow share the seal lemmas. Mostly a refactor of the
        existing rules; re-prove `SealedNoOffline` and
        `Attack_EscrowKeyOpensDisk` on the new shape.
  - [ ] 6. Sessions (§7.6.6–7.6.7): re-authentication sessions, the
        unlock counter, offline sessions, and the session-key epoch of
        session-mode files. Lemmas: a session token acts only within
        its epoch; revoked users/devices stop new releases (the
        `nsAccountLock`/unlock-count checks); a released
        offline-session key opens only that epoch's session-mode
        files. Attack lemma: the §7.6.10 row -- the released key plus
        a copied session-mode file opens that epoch's files for as
        long as the holder keeps the key; a resealed (new-epoch) file
        stays closed.
  - [ ] 7. Shared seals (§7.6.12): managers and members by user,
        group, host or service. Lemma: a shared-seal release implies
        the opener is a current member or manager (departed members'
        devices pruned at every seal operation). Attack lemma: a
        departed member with an old descriptor and a copied file gets
        nothing without a current member's release.
  - [ ] 8. Vouch heads and claim-log selection (§4.9,
        `DESIGN-claim-logs.md`): `?head=` proofs, retirement, and
        frozen-trust pins. This touches the core `!Server`/`!Adv`
        abstraction (a vouch is currently a plain signature), so it is
        the most invasive item: model heads as selectable vouch
        versions and retirement as a tombstone. Lemmas: a claim
        retired before the pin's head proves nothing for a host
        pinning that head; a frozen pin never accepts a shorter log
        (fork refusal). Attack lemma: a host pinning only an old head
        accepts a server whose claim was later retired (the design
        accepts this -- expiring pins bound it).
  - [ ] 9. Anchor epochs and rotation (§4.7–4.8): epoch numbers, key
        rotation, failover (§4.6). Model rotation as a chain of
        `!Server` facts and the two-anchor refusal
        (S13's "knows two anchors" row). Lemmas: a rotated-out anchor
        cannot vouch new servers to hosts that learned the rotation;
        a host with two pins skips a stolen-anchor server. Attack
        lemma: a host knowing only the stolen anchor still accepts it
        (the S13 row; `Attack_StolenAnchorLearnsOtp` is the join-side
        instance of this -- generalize rather than duplicate).
  - [ ] 10. Break-glass approvals (`DESIGN-approvals.md`): M-of-N
        approvals recorded in the transparency log. Lemma: a
        break-glass release implies M distinct approvals by
        authorized approvers. Attack lemma: fewer than M approvals
        (or one approver approving twice) never releases.
  - [ ] 11. Recovery flows (`DESIGN-recovery.md`): recovery codes,
        LUKS/file escrow deposits, helpdesk device-key delivery.
        Lemmas: a recovery-code finish implies the code was issued to
        that user and not yet used; helpdesk delivery hands the device
        key only to a registered depositor's seal. Attack lemma: a
        guessed recovery code fails (codes are server-generated
        randomness, so this should verify as impossible -- the lemma
        documents it).
  - [ ] 12. CI identities (`DESIGN-ci.md`): voucher leases and
        `ticket.leased`. Lemma: a leased host's tickets stop at lease
        end (KDC-side enforcement, like item 3's `not_after`). Attack
        lemma: after the lease the host is removed, so a recorded
        ticket grants nothing new.

## Protocol and implementation

- [ ] User seals (`kuipa seal`) and the unified recovery request (§7.6),
      in phases:
  - [x] 1. `tang-pqc` commitments (`provision_committed`,
        `OpenedRequest::verify_commitment`).
  - [x] 2. Unified recovery request; host and service escrow as machine
        seals carrying the commitment.
  - [x] 3. Seal model: policy, limits, devices, signed descriptor, `IPUF`
        two-share format, answers encrypted to the device, server seal
        operations and the ticket factor (with `ticket.delegation` checked
        against whatever the directory reports as transited services).
  - [x] 4. The seal container in LDAP, HTTP routes, test directories.
  - [ ] 5. Delegated tickets: PAC S4U delegation info for
        `ticket.delegation` (deferred; work in progress on branch
        `seal-pac-delegation`: generated NDR from pidl-rs, committed,
        with `samba-ndr` as the dependency). Until then kuipad reports the
        delegation as unknown, which only `allow` accepts.
  - [x] 6. `kuipa seal` with passphrase file devices and per-user state.
  - [x] 7. Re-authentication sessions; the unlock counter (per-server
        values on the seal entry).
  - [x] 8. Offline sessions.
  - [x] 9a. PKCS#11 devices: an ML-KEM key on a token through
        pkcs11-provider (no attestation yet: registered at `any`).
  - [x] 9b. Passkeys, classical (ES256, ES384, EdDSA, RS256) and
        ML-DSA-44/65/87: the passkey factor (relying-party verifier from
        ahdapa in `kuipa_enroll::passkey`, assertions in `IPEQ` v3 and in
        the session `unlock`, `ipaPassKey` and `ipaRequireUserVerification`
        read by kuipad, the `passkeys` seal operation for allow lists) and
        passkey-wrapped device keys (`hmac-secret`, `kuipa seal device add
        --passkey`), through the new `kuipa-fido2` libfido2 FFI crate; no
        attestation yet: registered at `any`.  Tested with a software
        authenticator; **not yet run against a real security key** or
        against FreeIPA's LDAP.
  - [x] Registered sealing (`sealing = registered`).
  - [x] Realm limits per group, and the factor sets a policy must meet
        (§7.6.2).
  - [x] Shared seals (§7.6.12): managers and members by user, group,
        host or service, devices held by members, `OWNER/NAME`
        references, `kuipa seal share`/`unshare`; departed members'
        devices pruned at every seal operation; user-seal releases
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
      (`kuipa-witness`, required counts on hosts), seal, escrow, Keys and
      signing events with receipts, `kuipa tlog watch`, `kuipa-audit tlog`;
      claim logs migrated onto typed leaves; committed leaves (only the
      kind and the day public, openings to the subject in lookups, kept
      13 months) and heads published hourly (`DESIGN-tlog.md` §1, §5, §9).
- [ ] Transparency logs, remaining: the tlog-tiles layout and a C2SP
      signed-note checkpoint with a witness endpoint (§6); logging the
      opening of machine (keytab) bindings, which only seal releases are
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
  - [x] Device-key deposits in a helpdesk seal, and their delivery
        (`kuipa seal recover helpdesk|deliver|fetch`).
- [x] M-of-N approvals for break-glass releases, recorded in the
      transparency log (`docs/DESIGN-approvals.md`).
- [x] Short-lived CI runner identities (voucher leases, `ticket.leased`)
      and pipeline secrets in shared seals (`docs/DESIGN-ci.md`).
- [ ] Trust bundles from the realm (`docs/src/use-cases.md`, "Deliver CA
      bundles without trusting DNS or TLS"): refresh the CA chain at
      `rotate-keys` and `check`; a realm-managed bundle in the
      advertisement (extra CAs, distrusted keys by SPKI hash); install
      into the system trust store with `update-ca-trust` and its
      blocklist; a dracut module carrying the pinned anchors and the
      last verified bundle into the initramfs.
- [ ] Recipes in the book: Ansible seal passwords, `systemd-creds` and
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
      the `ipaKUSeal` class with `ipaKUSealOwner`, `ipaKUSealName`,
      `ipaKUSealPolicy`, `ipaKUSealDevice`, `ipaKUSealState`,
      `ipaKUSealUnlocks`, `ipaKUSealSessionKey`, `ipaKUSealBinding`,
      `ipaKUSealManager`, `ipaKUSealMember`, `ipaKUSealApprover`
      (indexed for equality), the `ipaKURelease` class for release
      requests under a seal (`ipaKUReleaseRequest`,
      `ipaKUReleaseApproval`, `ipaKUReleaseDenied`, `ipaKUReleaseUses`),
      `ipaKUDeviceEscrow` on user entries (written by the daemon),
      `ipaKUSealDepositor` (indexed for equality), the `ipaKUDeposit`
      class for deposits under a seal (`ipaKUDepositData`), `ipaKURecovery`
      on a `cn=recovery,cn=kuipa,cn=etc` entry,
      `ipaKUServerEscrowKey` on
      `cn=masters` entries,
      `ipaKUSealLimits`, the `cn=seals,cn=kuipa,cn=etc` container, `ipaKUStaged`, `ipaKUVoucherSpent`, `ipaKULease` on host entries
      (written by the daemon, which may delete only entries carrying it),
      `ipaKUVouchers` on a `cn=vouchers,cn=kuipa,cn=etc` entry,
      `ipaKUTrustInvitation`,
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
