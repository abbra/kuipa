# kuipa recovery: lost devices, LUKS and backup keys

A vault with the device factor (DESIGN.md §7.6) keeps the realm's
administrators out: a file needs a registered device's key besides the
server's share. The same property loses the files when the owner loses
every device. This design adds three ways back, from the most private to
the most managed:

1. a **recovery code** the user prints and keeps, which no one else can
   use;
2. **deposits** of the user's device key into a helpdesk vault, opened
   only with the helpdesk's own devices and M-of-N approval
   (DESIGN-approvals.md);
3. the same deposits for machine secrets: **LUKS recovery keys** and
   **backup repository keys**, deposited by hosts, or by services and
   users through their keytabs, which cannot read them back.

| piece | status |
|---|---|
| recovery codes (`kuipa seal recovery-code`, `recover code`, `recover finish`) | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |
| depositors, deposits, `kuipa seal deposit put`, `list`, `fetch`, `retire` | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |
| device-key deposits and delivery (`kuipa seal recover helpdesk`, `deliver`, `fetch`) | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |
| `kuipa escrow luks`, `kuipa escrow file` | implemented, tested against a real KDC (a LUKS key as `systemd-cryptenroll` prints it); **not yet run** against a real LUKS volume |

Device-key deposits do not apply to keys that never leave hardware (a
`pkcs11` device, §7.6.2): they cannot be copied, so they cannot be
deposited. A policy that demands `hardware-bound` keeps meaning what it
says, and such vaults recover through a second hardware device (§7).

## 1. What recovery restores

A user's device key (`device.key`, one per host) is registered in each
of their vaults under its thumbprint, and every file sealed since then
carries a device slot for it (DESIGN.md §7.6.4). Recovery gives the user
**that same key** back on a new host. With it, `kuipa seal reseal` seals
each file again to the new host's device, and `kuipa seal device remove`
then retires the old one from every vault. Nothing about the sealed
format changes, and the server's share still comes only under each
vault's policy: recovery restores a factor, it does not bypass one.

## 2. Recovery codes

`kuipa seal recovery-code` makes a code for this host's device key (a
file device: a token's key never leaves the token):

```text
code  ←$ 128 bits, shown once as 26 base32 characters in groups of 4
K     = PBKDF2-HMAC-SHA-512(code, salt, 600 000)
blob  = IPDK(kdf, iterations, salt, GCM_K(private JWK))   (the device.key format)
```

The client stores the blob with the vault operation `escrow-code
{device, blob}`, authenticated by the owner's ticket; the device must be
one the caller holds in one of their vaults, and the blob at most 16 KiB.
The server keeps it on the owner's own entry, one `ipaKUDeviceEscrow`
value per device (`{"device", "kind": "code", "blob", "added"}`). A new
code for the same device replaces the old one. The event is logged
(`escrow-code`, kind 2, with the device's id) in every vault where the
caller holds the device, so the vault's watchers see that its device can
be recovered.

On a new host, `kuipa seal recover code` fetches the blobs with the
operation `recover-code` (the owner's ticket; logged as `recover-code` in
those vaults, which `kuipa tlog watch` always flags), asks for the code,
opens the blob it opens, and keeps the old key beside this host's own as
`recovered.key`, under this host's device passphrase. `kuipa seal open`
uses it for files that have a slot for it and none for this host's
device.

`kuipa seal recover finish FILE.sealed…` registers this host's device
(made now if the host has none) in every vault where the recovered device
is the user's, and reseals the files to it. Only with `--retire-old`
does it also remove the recovered device from those vaults and forget it
here. That is a separate flag because a file left out of the list,
sealed only to the old device, would stop opening: the user retires the
old device once everything is resealed, and until then the laptop that
was lost still holds a key the vaults accept.

The blob is readable by whoever reads the directory, which is why the
code has the full 128 bits: no one guesses it, whatever the iteration
count. The code is the user's to keep, on paper or in a password manager;
kuipa never stores it. A user who has their code and their password has
everything back; a user without the code needs the helpdesk.

## 3. Depositors and deposits

A shared vault (DESIGN.md §7.6.12) gains a fourth role, below member:

| role | may |
|---|---|
| depositor (`depositors`, named as members are, in `ipaKUVaultDepositor`) | show the vault (to seal to it), deposit, list and retire their own deposits, leave |

A depositor never opens: they register no device, start no session, ask
for no release, fetch no deposit, and a release refuses an opener who is
only a depositor. `kuipa seal share VAULT --depositor --group G` makes
them one; managers, members and depositors count together against
`max_members`. A **deposit** is a file sealed to the vault (`IPUF`) that
the server keeps for the members, since its depositor may be gone by the
time anyone needs it:

```text
cn=<deposit id>,cn=<vault id>,cn=vaults,cn=kuipa,cn=etc,<suffix>
  objectClass ipaKUDeposit
  ipaKUDepositData: { "id", "vault", "depositor", "kind": "device" | "luks" | "file",
                      "subject": <what it is for>, "added", "sealed": <IPUF, ≤ 16 KiB> }
```

`subject` says what the deposit is for among its depositor's deposits of
that kind, as string pairs (at most 8): `{"device"}` for a device key,
`{"uuid"}` for a LUKS volume, `{"name"}` for a file; the depositor (a
user, or a host's principal) is the deposit's own field. The vault
operations are:

| operation | who | does |
|---|---|---|
| `deposit` | any role | checks the file is sealed to this vault, keeps it, and with `sealing = registered` registers its bindings; a deposit with the same depositor, kind and subject replaces the earlier one, whose bindings are retired |
| `deposits` | any role | lists deposits without their files: all of them for members, their own for a depositor |
| `fetch-deposit` | members | one deposit with its file, which opens as any file of the vault, under its policy |
| `retire-deposit` | a deposit's depositor, or a manager | removes it and retires its bindings |

Deposits and retirements are logged (`deposit` with `H` of the file,
`retire-deposit` with `H` of its id, kind 3). The realm limits gain
`max_deposits` per depositor and vault (default 32). On the command
line they are `kuipa seal deposit put VAULT FILE [--name N]`, `list`,
`fetch VAULT ID --out F.sealed` and `retire VAULT ID`.

The vault's own policy decides how deposits open, as for any file. For a
helpdesk it would be:

```text
factors:   device (the helpdesk staff's devices), ticket
approvals: m = 2, from = group "helpdesk-leads"     (DESIGN-approvals.md)
sealing:   registered
```

So opening one deposit needs a helpdesk member's device and ticket, and
two leads' approval for that deposit's bindings, and the realm's
administrators cannot open it with the escrow keys alone.

## 4. Device-key deposits and delivery

The realm names its device escrow vault in `cn=recovery,cn=kuipa,cn=etc`
(`ipaKURecovery`: `{"device_vault": "OWNER/NAME", "required": false}`),
and the realm's users are its depositors (for example the group
`ipausers`). Clients learn the setting with the vault operation
`recovery-settings`.

**Depositing.** When `kuipa seal device add` registers a key-file device,
and the realm names a device vault, the client first seals the private
JWK to that vault as a deposit of kind `device` with subject `{"device":
id}`, unless the user already deposited that device; a token's key
(`pkcs11`) never leaves the token and is not deposited. With `"required":
true`, `add-device` refuses an extractable device (`file`,
`pkcs11-wrapped`) unless its holder has a device deposit with that id,
and a failed deposit stops the registration; otherwise it is only
warned about. The server can check that the deposit exists, not that it
holds the right key: a user who deposits garbage only loses their own
recovery.

**Recovering.**

1. The user, on a new host with a ticket (after the helpdesk reset their
   password if need be), registers a new device (`kuipa seal device add
   VAULT`) and runs `kuipa seal recover helpdesk`, which prints the new
   device's id for the helpdesk.
2. A helpdesk member finds the deposit (`kuipa seal deposit list
   helpdesk/device-escrow`: the one whose subject is the lost device),
   fetches it and asks for its release: `kuipa seal request
   helpdesk/device-escrow DEPOSIT.sealed --reason "INC-1234: alice, lost
   laptop"`. The leads approve after checking the user's identity their
   own way.
3. The helpdesk member runs `kuipa seal recover deliver DEPOSIT --user
   alice --device NEW --request RQ`: it opens the deposit (with their
   device, their ticket and the approved request), looks up the new
   device's public key (the operation `device-key`, which answers only
   for a device the user registered), encrypts the old key to it
   (`IPDD`: an ML-KEM encapsulation to the new device, the private JWK
   under a key derived from it), and hands that to the operation
   `deliver`. The server keeps it on the user's entry, as an
   `ipaKUDeviceEscrow` value of kind `delivery`, and logs it (`deliver`,
   kind 2) in every vault where the user holds the new device; `kuipa
   tlog watch` always flags one. `device-key` and `deliver` answer only
   members of the realm's device vault.
4. The user runs `kuipa seal recover fetch`: the delivery opens only with
   the new device's key, and the old key is kept as `recovered.key`.
   Then `recover finish` as in §2.

The helpdesk member holds the old key while delivering it. That is the
price of not letting administrators recover alone. It is bounded:
two leads approved this one deposit, the request, the approvals, the
release and the delivery are all in the log, and the user retires the
old key right after.

## 5. LUKS and backup keys

Hosts, and services or users with a keytab on a host, are depositors of
a realm vault such as `helpdesk/disks`.

* `systemd-cryptenroll --recovery-key DEVICE | kuipa escrow luks DEVICE
  --vault helpdesk/disks` (root) enrolls a recovery key in the LUKS2
  header and deposits it as kind `luks`, with subject `{uuid}` (what
  `cryptsetup luksUUID` says, or `--uuid`), in place of the host's
  previous deposit for that volume. kuipa does not enroll the key itself:
  it reads what `systemd-cryptenroll` prints (or `--key-file`), takes the
  line shaped like a systemd recovery key (eight groups of eight modhex
  characters) and refuses input without one, so a mistyped pipe deposits
  nothing. Run again after `cryptsetup luksKillSlot` or a reinstall, it
  keeps the deposit current.
* `kuipa escrow file NAME FILE --vault V` deposits any small secret, such
  as a restic or Borg repository password, as kind `file`, subject
  `{name}`.

The host's own principal deposits, with a ticket from its keytab (the
sealed one's unsealed copy when the keytab is protected); with `--keytab
FILE`, the principal of that keytab does instead. The credential is
GSS-API's: `gss_acquire_cred_from` with `client_keytab` (and a private
in-memory ccache, so no ticket already in the default ccache stands in
for the keytab's principal), named by `gss_inquire_cred`. kuipa never
reads the keytab itself, so gssproxy can hold it and the process needs
no access to the file; the host's keytab must act as the host. A backup
service with its own keytab thus deposits its repository password as
`backup/web1.example.test`, not as the host. Either keeps the vault's descriptor in the host's root-only
state directory (`/var/lib/ipa-client/ku/escrow`), and can neither list
other depositors' deposits nor open its own. When a disk will not unlock
(a dead TPM, a lost Tang server), the helpdesk opens the deposit under
the vault's policy and reads the key to whoever is at the console.

## 6. What each party gets

| someone has | recovery code | device deposit (helpdesk vault with device factor and approvals) |
|---|---|---|
| the directory, the code blob, the deposits | nothing (128-bit code) | nothing (the helpdesk's device share) |
| the realm's escrow keys (an administrator) | nothing | nothing alone; with a helpdesk member's device, the deposits |
| one helpdesk member | — | nothing without `m` approvals |
| a helpdesk member and `m` leads | — | the user's old device key, then (with the server share under the user's own vault policy, or the escrow keys) the user's files sealed to it |
| the user's code | the old device key, and with the user's ticket their files | — |

## 7. Decisions

* **Recover the device key, not each file.** A deposit of the key is one
  object per device, needs no access to the user's files, and works for
  files sealed since. The alternative, a recovery slot in every file,
  would put the helpdesk's key in every file and make every reseal carry
  it.
* **Helpdesk devices decrypt, not the user.** A helpdesk vault without
  the device factor would let the user open their own deposit under the
  helpdesk's approvals, so no helpdesk member would see the key; but the
  realm's administrators could then open every deposit with the escrow
  keys alone. The design prefers to keep administrators out and accepts
  that the delivering helpdesk member sees one key.
* **Deposits live in the directory.** kuipa servers otherwise hold no
  data, but a deposit must outlive its depositor (the lost laptop, the
  reinstalled host), and it is small and sealed. The 16 KiB cap keeps it
  that way.
* **Hardware vaults recover through hardware.** A `hardware-bound`
  device has no copy to deposit, and that is the point of such vaults.
  Their recovery is a second hardware-bound device registered in the
  vault, for example an ML-KEM key in an HSM that the helpdesk operates
  through PKCS#11: every file then carries a slot for it, and its key
  still never leaves hardware. How that device is held and opened (as a
  member, under approvals) is left for its own design, with the
  attestation that `hardware-bound` needs first.
