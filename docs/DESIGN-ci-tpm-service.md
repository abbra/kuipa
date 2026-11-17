# Test design: a TPM-bound IPA client serving HTTPS with Akamu certificates

The FreeIPA integration job (`contrib/ci/freeipa/`) runs three kuipa suites on
VMs without a TPM. The TPM factor (`kuipa protect --tpm`, `kuipa prepare
--tpm`) is only unit tested, and `TODO.md` lists "TPM-sealed keytabs through
gssproxy's loader under SELinux enforcing" as not checked. This test closes
both gaps with one realistic deployment: a client host whose secrets open only
on its own TPM, serving a web page over TLS with a certificate from the
realm's ACME server (Akamu), and accepting Kerberos logins through gssproxy.

## What it proves

1. A host keytab, a service keytab and a TLS private key, sealed with
   `--tpm`, open again after a **reboot**, with no operator, and are never on
   disk in plain form.
2. gssproxy 0.9.3 loads the service keytab through `keytab_loader`
   (`kuipa-unseal --memfd`) **under SELinux enforcing**, from inside its
   systemd sandbox, using the TPM.
3. nginx serves a page over TLS with an **Akamu-issued** certificate whose
   key is kuipa-protected, and a Kerberos client authenticates to it.
4. The TPM is a real second factor: with every server reachable and every
   ticket valid, a host whose TPM no longer opens the credential gets
   nothing, with a plain error and not a retry loop.

## Topology

| host | role | notes |
|---|---|---|
| `master1` | IPA server | kuipad, Akamu and ipacta from abbra/pqc; as in `test_kuipa_enrollment.py` |
| `client1` | the host under test | `tpm: true`; kuipa, gssproxy 0.9.3, nginx, certbot, python3-gssapi, tpm2-tools |
| `client2` | a second enrolled host | `tpm: true`; the HTTPS and Kerberos client, and the "stolen disk" machine |

Preset: a copy of `kuipa-ipa.yaml` with `master1`, `client1` and `client2`
(no replica), and `vm.vms` entries named after the hosts:

```yaml
vm:
  vms:
    - {name: client1, tpm: true}
    - {name: client2, tpm: true}
```

ci-freeipa's qemu backend starts one swtpm per VM and boots such a VM with
UEFI. The swtpm outlives a guest reboot and is discarded at `down`. The
control node needs `swtpm` and `edk2-ovmf` (add them to the apt list in
`.github/workflows/freeipa.yml`). The guest check is `systemd-analyze
has-tpm2` saying `yes`. The test skips, with that reason, if it says
anything else.

Packages: kuipa from the commit under test (as `upgrade-kuipa.sh` does),
**gssproxy 0.9.3** from abbra/pqc (the build exists; Fedora ships 0.9.2),
and the clients' own `nginx`, `certbot`, `python3-gssapi`, `tpm2-tools`.

## Why the Kerberos check needs a helper

nginx has no GSSAPI authentication module in Fedora (`mod_auth_gssapi` is for
httpd, `lighttpd-mod_authn_gssapi` for lighttpd). The test keeps nginx, since
it is what operators run, and puts a 30-line Python helper behind
`auth_request`:

```text
client2 --TLS--> nginx (:443) --auth_request--> helper (127.0.0.1:8081, user "spnego")
                    |                              gss_accept_sec_context, GSS_USE_PROXY=yes
                    +--> /usr/share/nginx/html/kuipa.html
```

The helper runs as an unprivileged user with no keytab. gssproxy holds
`HTTP/client1.ipa.test` and accepts on its behalf, so the test exercises the
real gssproxy path (an interposed `gss_accept_sec_context`), the one NFS and
`mod_auth_gssapi` use. The helper returns 200 with `X-Remote-User`, or 401
with `WWW-Authenticate: Negotiate`; nginx forwards the header into the page
response. If a maintainers' decision prefers httpd, swapping nginx for httpd
with `mod_auth_gssapi` removes the helper and changes nothing else.

## Setup (class `install`)

1. `install_master`, then enroll `client1` and `client2` with an enrollment
   string and `ipa-client-install`, as the existing suites do. Check
   `systemd-analyze has-tpm2` on both.
2. `client1`: `kuipa protect --tpm` for the host keytab. `kuipa status`
   must show the TPM factor. The shipped `kuipa-unseal.service` ordering
   (`Before=sssd.service gssproxy.service`) is what is under test here.
3. Service principal: `ipa service-add HTTP/client1.ipa.test`, then
   `ipa-getkeytab` into `/etc/nginx/http.keytab`, then `kuipa protect
   --keytab /etc/nginx/http.keytab --tpm`. This gives a sealed file and a
   link to a memory copy.
4. gssproxy: `/etc/gssproxy/60-http.conf` with `cred_usage = accept`,
   `euid = spnego`, `cred_store = keytab:MEMORY:http` and `keytab_loader =
   /usr/libexec/kuipa-unseal --memfd --sealed /etc/nginx/http.keytab.sealed`.
   The path of the sealed file is read from `kuipa status`, not assumed.
5. Certificate from Akamu: generate the key and a CSR in `/run` (tmpfs). The
   host gets EAB credentials with its keytab (`kinit -k`, then `curl
   --negotiate https://master1.ipa.test/akamu/acme/eab`) and runs `certbot
   certonly --standalone --csr … --eab-kid … --eab-hmac-key … --server
   https://master1.ipa.test/akamu/acme/directory`. Akamu is under `/akamu`;
   `/acme` is Dogtag's own responder. The `http-01` challenge needs port 80
   on the client, so nginx is stopped, and the firewall allows http and
   https (`firewall-offline-cmd`: firewalld may start only at the next boot).
   Akamu on the master needs `http_validation_allow_private_ips = true` in
   `[server]`, since the test network is RFC 1918. Install the key at
   `/etc/pki/tls/private/client1.key` and `kuipa protect --file … --tpm`
   it; delete the tmpfs copy.
6. nginx: TLS server using the certificate and the sealed key, the
   `auth_request` location, and the systemd drop-in `After=kuipa-unseal.service
   Wants=kuipa-unseal.service` from `docs/src/host/protect.md`.
7. gssproxy: IPA installs its own unit drop-in (`ipa.conf`: network,
   `IPAddressDeny=` cleared, `CAP_SYS_PTRACE`) on servers and clients, since
   0.9.3 sandboxes the daemon. The test adds only `PrivateDevices=no` for the
   TPM, and an SELinux module (see Risks).

## Tests (in this order; the last one destroys the TPM state)

1. `test_no_plain_secrets_on_disk`: the host keytab, the HTTP keytab and the
   TLS key are links into `/run`; a scan of the root file system (not `/run`)
   for a keytab header (`05 02`) and `BEGIN PRIVATE KEY` finds only the
   unrelated system files listed in an allow-list, and none under
   `/etc/nginx`, `/etc/pki/tls/private`, `/etc/krb5.keytab` or
   `/var/lib/ipa-client/ku`.
2. `test_https_and_kerberos_before_reboot`: from `client2`, `kinit admin`;
   `curl --cacert /etc/ipa/ca.crt --negotiate -u : https://client1…/kuipa.html`
   returns 200, the page text, and `X-Remote-User: admin@IPA.TEST`. The served
   certificate's issuer is the IPA CA and its issuance appears in Akamu's
   log (`journalctl --namespace akamu`). Without a ticket the answer is 401.
3. `test_reboot_unseals_everything`: reboot `client1` (poll ssh until
   `/proc/sys/kernel/random/boot_id` changes), then assert:
   `kuipa-unseal.service` succeeded and ran before `gssproxy.service` and
   `nginx.service` (`systemd-analyze critical-chain` or journal order);
   `kinit -k` with the host keytab works; the test-2 requests work again
   with no manual step; and the plain-secrets scan of test 1 still passes.
   Repeat the reboot once to catch a first-boot-only success.
4. `test_service_keytab_never_reaches_a_file`: during the run, gssproxy holds
   the keytab in memory only: no new file with a keytab header appears under
   `/var/lib/gssproxy`, `/run`, `/tmp` after the second reboot (the loader's
   memfd is the only copy).
5. `test_selinux_is_enforcing_and_clean`: `getenforce` says `Enforcing`, and
   `ausearch -m avc -ts boot` reports no denial involving `gssproxy_t`,
   `systemd-creds`, `kuipa_unseal_t`, `nginx` or `/dev/tpmrm0`. A denial is a
   failure of this test with the AVC text; it is a product bug (policy),
   not something the test relaxes.
6. `test_reissue_reseals_the_key`: run the deploy hook for a second
   certificate from Akamu; nginx reloads and serves the new certificate; the
   previous sealed key stops opening (its credential is gone), and the disk
   scan stays clean.
7. `test_stolen_disk_has_no_tpm`: copy `client1`'s sealed files and
   `/var/lib/ipa-client/ku/` to `client2` and run `kuipa-unseal --sealed … `
   there. It must fail with the TPM error (exit not 75) and write nothing,
   whatever the servers would answer. This shows the credential is bound to
   the TPM it was made on.
8. `test_cleared_tpm_denies_service` (last): on `client1`, `tpm2_clear`;
   reboot. `kuipa-unseal.service` fails with a plain error and not a retry,
   `gssproxy` and `nginx` fail to start or serve, the page is unreachable,
   and `kinit -k` fails, with `master1` reachable throughout. This is the
   "servers alone are not enough" property.

Teardown: `uninstall_client` on both, `uninstall_master`. A cleared TPM
cannot be restored, so a new run starts from new VMs (the swtpm state is
discarded at `down` anyway).

## Risks and expected findings

- **gssproxy's unit sandbox (found by the test).** The 0.9.3 unit sets
  `PrivateDevices=yes`, `PrivateNetwork=yes`, `IPAddressDeny=any` and a
  capability bound of `CAP_DAC_OVERRIDE`. The loader needs `/dev/tpmrm0` (the
  test's `PrivateDevices=no`) and the IPA servers (IPA's drop-in). Without
  `CAP_SYS_PTRACE`, gssproxy cannot read `/proc/PID/exe` of a root client
  and `program =` sections (kuipad-keys) never match.
- **SELinux (found by the test).** `gssproxy_t` may not run the loader, open
  `/dev/tpmrm0`, read the memfd or connect to port 443, and `httpd_t` may not
  read the unsealed key copy under `/run/ipa`. The test installs a small
  policy module; the fix belongs in selinux-policy. The test keeps SELinux
  enforcing.
- **nginx and the sealed key.** nginx reads the key at start and on reload,
  so reload after reseal is covered by test 6. The key file is a link to
  `/run`; whether nginx's unit sandboxing lets it follow the link is
  checked by the test, not assumed.
- **certbot.** `certonly --csr` does not support `renew`. The deploy hook
  re-runs the issuance. A later test can use `certbot renew` with a
  `--key-path` hook if Akamu's renewal flow needs it.
- **Time and memory.** Two reboots, two issuances and the client installs
  add to the realm install of `test_kuipa_server_enrollment`. The clients
  have 2.5 GB each with the TPM, so the four VMs need about 10 GB of the
  runner's 16 GB. The suite runs in the main job: a TPM or swtpm problem
  fails the whole job, and the logs of each test stay separate.
- **Hardware limits.** swtpm is a software TPM: it proves the flows and the
  binding, not hardware resistance, and has no PCR policy beyond what
  `--tpm-pcrs` selects. A PCR-bound variant (`--tpm-pcrs 7`) is a follow-up:
  it needs Secure Boot state under OVMF to be stable across the reboot.

## Where the files go

- `freeipa-kuipa-integration/ipatests/test_integration/test_kuipa_tpm_service.py`
  with the helper script embedded as a string.
- `contrib/ci/freeipa/kuipa-ipa.yaml`, the main CI preset: its clients are
  the two TPM VMs, and the test runs after the three other suites.
- `.github/workflows/freeipa.yml` installs `swtpm`, `swtpm-tools` and `ovmf`
  on the runner, and links the firmware to the path ci-freeipa expects
  (`/usr/share/edk2/ovmf/OVMF_CODE.fd`). The RPM upgrade
  (`upgrade-kuipa.sh`) runs before the tests as for the other suites.
- Until abbra/pqc's ipatests carries the new file, the test is copied to the
  controller by hand, as `test_kuipa_clevis.py` was.
