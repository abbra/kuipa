# kuipa — open work

What exists and how it is tested is in [docs/DESIGN.md](docs/DESIGN.md)
§18. This list holds only what remains; section numbers refer to
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

## Protocol and implementation

- [ ] TPM factor for sealed keytabs and `kuipa prepare --tpm` (§7.1, §8.2).
- [ ] gssproxy as the keytab holder in `kuipa protect`, once gssproxy has
      `keytab_loader` (§7.4).
- [ ] MTC: anchors issued as Merkle Tree Certificates and pre-distributed
      tree heads (§16).
- [x] Notice a stolen anchor where the host knows only one: done as the
      anchor epoch log (§4.8) — canonical per-sequence entries signed by
      the current anchors, a `(sequence, head)` in every advertisement,
      a public `anchor-log` route, and an `epoch` watermark line in
      `/etc/ipa/ku-anchors`.
- [ ] S4U2Proxy with the caller's evidence ticket instead of protocol
      transition (§16).

## Outside this workspace

- [ ] FreeIPA server: schema (`ipaKUEscrowBinding`, `ipaKUEscrowFileBinding`,
      `ipaKUStaged`, `ipaKUVoucherSpent`, `ipaKUTrustInvitation`,
      `ipaKUTrustedRealm`) and
      the `cn=trusts,cn=kuipa,cn=etc` entry; ACIs for the daemon's identity
      (including adding hosts and host-group members for vouchers, and
      cross-realm `krbtgt` principals and their keys for trusts, and the
      escrow attributes on service and user entries as well as hosts, §7.5);
      framework commands (`pq-anchor-show`,
      `host-add/host-mod --pq-stage`, enrollment strings from `--random`,
      `--clear-pq-escrow`, also for services and users), installers and
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
- [ ] gssproxy: per-service `keytab_loader` (memfd on fd 3 into a `MEMORY:`
      keytab), reload on `SIGHUP`, loader retry, `MADV_DONTDUMP` (§7.4).
- [ ] FreeIPA trusts: a `trust-add --type=ipa` front end for
      `trust-invitation` / `establish-trust`, and the trust objects next to
      the recorded partners; run
      `kuipa trusted-realms` after enrollment and from a timer; SSSD
      reading `/etc/krb5.conf.d` (Fedora's `krb5.conf` already has
      `includedir`).
- [ ] SSSD: LDAP TGT and ticket validation through GSS-API and gssproxy,
      anonymous-PKINIT armour, so `host/<fqdn>` can move to gssproxy (§7.4).
- [ ] Fedora packaging of the crates and their missing dependencies.
