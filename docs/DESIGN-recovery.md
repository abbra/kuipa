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
   **backup repository keys**, deposited by hosts that cannot read them
   back.

| piece | status |
|---|---|
| recovery codes (`kuipa seal recovery-code`, `recover --code`) | designed |
| depositors, deposits, `kuipa seal deposit` | designed |
| device-key deposits and delivery (`kuipa seal recover`) | designed; needs DESIGN-approvals.md |
| `kuipa escrow luks`, `kuipa escrow file` | designed |

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

`kuipa seal recovery-code [--device ID]` makes a code for this host's
device key:

```text
code  ←$ 128 bits, shown once as 26 base32 characters in groups of 4
K     = PBKDF2-HMAC-SHA-512(code, salt, 600 000)
blob  = IPDK(kdf, iterations, salt, GCM_K(private JWK))   (the device.key format)
```

The client stores the blob with the vault operation `escrow-code
{device, blob}`, authenticated by the owner's ticket. The server keeps it
on the owner's own entry, one `ipaKUDeviceEscrow` value per device
(`{"device", "kind": "code", "blob", "added"}`), and logs the event. A
new code for the same device replaces the old one.

On a new host, `kuipa seal recover --code` fetches the blobs with the
operation `recover-code` (the owner's ticket; logged), asks for the code,
opens the blob and installs the old key as a second device of this host,
`recovered.key`. `kuipa seal recover finish` then reseals the files it is
given and removes the old device from every vault of the user.

The blob is readable by whoever reads the directory, which is why the
code has the full 128 bits: no one guesses it, whatever the iteration
count. The code is the user's to keep, on paper or in a password manager;
kuipa never stores it. A user who has their code and their password has
everything back; a user without the code needs the helpdesk.

## 3. Depositors and deposits

A shared vault (DESIGN.md §7.6.12) gains a fourth role, below member:

| role | may |
|---|---|
| depositor (`depositors`, named as members are) | show the vault (to seal to it), deposit, list and retire their own deposits |

A depositor never opens: they hold no device in the vault, and a release
refuses an opener who is only a depositor. A **deposit** is a file sealed
to the vault (`IPUF`) that the server keeps for the members, since its
depositor may be gone by the time anyone needs it:

```text
cn=<deposit id>,cn=<vault id>,cn=vaults,cn=kuipa,cn=etc,<suffix>
  ipaKUDeposit: { "depositor", "kind": "device" | "luks" | "file",
                  "subject": <what it is for>, "added", "sealed": <IPUF, ≤ 16 KiB> }
```

`subject` is structured by kind: `{"user", "device"}` for a device key,
`{"host", "uuid"}` for a LUKS volume, `{"host", "name"}` for a file. The
vault operations are `deposit` (which, with `sealing = registered`, also
registers the file's bindings), `deposits` (members see all, depositors
their own) and `retire-deposit` (a depositor's own, or any for a
manager). A new deposit with the same depositor, kind and subject retires
the previous one. The realm limits gain `max_deposits` per depositor and
vault (default 32).

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
`ipausers`).

**Depositing.** When `kuipa seal device add` makes a device key, and
whenever `kuipa seal recovery deposit` is run, the client seals the
private JWK to the escrow vault as a deposit of kind `device` with
subject `{user, device id}`. With `"required": true`, `add-device` refuses
a device of an extractable type (`file`, and `pkcs11-wrapped` at
creation) unless its holder has a device deposit with that id. The
server can check that the deposit exists, not that it holds the right
key: a user who deposits garbage only loses their own recovery.

**Recovering.**

1. The user, on a new host with a ticket (after the helpdesk reset their
   password if need be), makes and registers a new device key and runs
   `kuipa seal recover --helpdesk OLD-DEVICE`, which prints the new
   device's thumbprint for the helpdesk.
2. A helpdesk member requests the release of the deposit:
   `kuipa seal request helpdesk/device-escrow --deposit ID --reason
   "INC-1234: alice, lost laptop"`. Two leads approve after checking the
   user's identity their own way.
3. The helpdesk member runs `kuipa seal recover deliver --deposit ID
   --to-device NEW`: it opens the deposit (with their device, their
   ticket and the approved request), encrypts the old key to the new
   device's registered public key (ML-KEM, `IPDD`), and stores that with
   the operation `deliver`, which the server keeps on the user's entry
   until fetched and logs. The new device is looked up in the user's
   vaults; the server refuses a delivery to a device the user did not
   register.
4. The user runs `kuipa seal recover --fetch`: the delivery opens only
   with the new device's key. Then `recover finish` as in §2.

The helpdesk member holds the old key while delivering it. That is the
price of not letting administrators recover alone. It is bounded:
two leads approved this one deposit, the request, the approvals, the
release and the delivery are all in the log, and the user retires the
old key right after.

## 5. LUKS and backup keys

Hosts are depositors of a realm vault such as `helpdesk/disks`.

* `kuipa escrow luks DEVICE` (root) enrolls a recovery key in the LUKS2
  header with `systemd-cryptenroll --recovery-key`, seals it to the
  vault as a deposit of kind `luks` with subject `{host, uuid}`, and
  replaces the host's previous deposit for that volume. Run again after
  `cryptsetup luksKillSlot` or a reinstall, it keeps the deposit current.
* `kuipa escrow file NAME FILE` deposits any small secret, such as a
  restic or Borg repository password, as kind `file`.

The host's own principal deposits, with its host ticket; it can neither
list other hosts' deposits nor open its own. When a disk will not unlock
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
