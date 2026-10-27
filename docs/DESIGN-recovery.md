# kuipa recovery: lost devices, LUKS and backup keys

A seal with the device factor (DESIGN.md §7.6) keeps the realm's
administrators out: a file needs a registered device's key besides the
server's share. The same property loses the files when the owner loses
every device. This design adds three ways back, from the most private to
the most managed:

1. a **recovery code** the user prints and keeps, which no one else can
   use, or **recovery shards**: the same recovery split over several
   papers, of which a few are enough (§2.1);
2. **deposits** of the user's device key into a helpdesk seal, opened
   only with the helpdesk's own devices and M-of-N approval
   (DESIGN-approvals.md);
3. the same deposits for machine secrets: **LUKS recovery keys** and
   **backup repository keys**, deposited by hosts, or by services and
   users through their keytabs, which cannot read them back.

| piece | status |
|---|---|
| recovery codes (`kuipa seal recovery-code`, `recover code`, `recover finish`) | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |
| recovery shards (`kuipa seal recovery-shards`, `recover shards`): N of M paper shards | designed here (§2.1); the share format, Shamir splitting, word code and passphrase mask are implemented and tested (`kuipa-enroll::shards`); the server operations and commands are **not** |
| depositors, deposits, `kuipa seal deposit put`, `list`, `fetch`, `retire` | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |
| device-key deposits and delivery (`kuipa seal recover helpdesk`, `deliver`, `fetch`) | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |
| `kuipa escrow luks`, `kuipa escrow file` | implemented, tested against a real KDC (a LUKS key as `systemd-cryptenroll` prints it); **not yet run** against a real LUKS volume |

Device-key deposits do not apply to keys that never leave hardware (a
`pkcs11` device, §7.6.2): they cannot be copied, so they cannot be
deposited. A policy that demands `hardware-bound` keeps meaning what it
says, and such seals recover through a second hardware device (§7).

## 1. What recovery restores

A user's device key (`device.key`, one per host) is registered in each
of their seals under its thumbprint, and every file sealed since then
carries a device slot for it (DESIGN.md §7.6.4). Recovery gives the user
**that same key** back on a new host. With it, `kuipa seal reseal` seals
each file again to the new host's device, and `kuipa seal device remove`
then retires the old one from every seal. Nothing about the sealed
format changes, and the server's share still comes only under each
seal's policy: recovery restores a factor, it does not bypass one.

## 2. Recovery codes

`kuipa seal recovery-code` makes a code for this host's device key (a
file device: a token's key never leaves the token):

```text
code  ←$ 128 bits, shown once as 26 base32 characters in groups of 4
K     = PBKDF2-HMAC-SHA-512(code, salt, 600 000)
blob  = IPDK(kdf, iterations, salt, GCM_K(private JWK))   (the device.key format)
```

The client stores the blob with the seal operation `escrow-code
{device, blob}`, authenticated by the owner's ticket; the device must be
one the caller holds in one of their seals, and the blob at most 16 KiB.
The server keeps it on the owner's own entry, one `ipaKUDeviceEscrow`
value per device (`{"device", "kind": "code", "blob", "added"}`). A new
code for the same device replaces the old one. The event is logged
(`escrow-code`, kind 2, with the device's id) in every seal where the
caller holds the device, so the seal's watchers see that its device can
be recovered.

On a new host, `kuipa seal recover code` fetches the blobs with the
operation `recover-code` (the owner's ticket; logged as `recover-code` in
those seals, which `kuipa tlog watch` always flags), asks for the code,
opens the blob it opens, and keeps the old key beside this host's own as
`recovered.key`, under this host's device passphrase. `kuipa seal open`
uses it for files that have a slot for it and none for this host's
device.

`kuipa seal recover finish FILE.sealed…` registers this host's device
(made now if the host has none) in every seal where the recovered device
is the user's, and reseals the files to it. Only with `--retire-old`
does it also remove the recovered device from those seals and forget it
here. That is a separate flag because a file left out of the list,
sealed only to the old device, would stop opening: the user retires the
old device once everything is resealed, and until then the laptop that
was lost still holds a key the seals accept.

The blob is readable by whoever reads the directory, which is why the
code has the full 128 bits: no one guesses it, whatever the iteration
count. The code is the user's to keep, on paper or in a password manager;
kuipa never stores it. A user who has their code and their password has
everything back; a user without the code needs the helpdesk.

### 2.1 Recovery shards: a paper key that needs N of M

A recovery code is a **bearer token**: whoever finds the paper, and the
user's ticket, has the device key back. It protects one device, and a
device registered after the code was printed is not covered until the user
prints another. A user who wants the paper to be their last resort asks
for more of it:

1. **no single paper is enough**: N of M papers, kept in different places,
   so that losing or losing sight of a few neither opens nor loses the key;
2. **the papers survive damage**: a stain, a tear or a misread word must
   not make a share unusable, so each share carries heavy error correction;
3. **the papers alone do not suffice**: a passphrase the user remembers is
   part of the key;
4. **a paper explains itself**, in English and in a form a program reads,
   years later;
5. **new devices need no paper**: the paper holds a key pair, so a device
   registered later is protected with the public half and nobody has to
   gather the shares.

`kuipa seal recovery-shards create --shares M --threshold N` makes a
**recovery key** and splits it. The command, and everything below, is an
alternative to `recovery-code`: a user may hold a code, a shard set, or
both, per device.

**The key.** A recovery key is an ML-KEM key pair (ML-KEM-1024 under
CNSA 2.0, as the KEM suite, §5.1 of DESIGN.md) made from a 32-byte seed
`s`: `(d, z) = HKDF(s, "ipa-ku recovery key v1")`. Only the seed is secret.
The public key and its thumbprint (the **key id**) are public and the
server keeps them (below).

**The passphrase.** The user chooses one. The seed is not split as it
is; it is first hidden under the passphrase:

```text
salt = 16 random bytes, made with the set and carried by every share
pad  = PBKDF2-HMAC-SHA-512(NFKC(passphrase), salt, iterations)[0..32]
w    = s XOR pad
```

PBKDF2 is the only password-based KDF that FIPS approves (SP 800-132), and
kuipa keeps to FIPS-approved algorithms, so this is the KDF, as in §2. The
salt is 128 random bits, which SP 800-132 asks for, and the iteration
count is in units of 100 000 (default 20, so 2 million; 1 to 63): the
cost of one try on the user's host: 0.5 to 0.8 seconds for the default on a current laptop. PBKDF2
needs no memory, so a graphics card tries passphrases far faster than a
host, and the passphrase has to make up for it.

`w` has no authentication tag on purpose, so that a wrong passphrase gives
a wrong seed and nothing says so: the only check is that the public key
derived from a candidate seed has the key id. An attacker who has N shares
learns `w`, and then tries passphrases against the public key id at the
cost of one PBKDF2 each. The passphrase therefore has to resist an offline
search by someone who can use specialized hardware, not just a login
prompt: kuipa asks for at least 16 characters (a phrase of five or six
random words is the advice it prints), refuses a shorter one unless asked
with `--weak-passphrase`, and an empty one unless asked with
`--no-passphrase`. Characters are normalized (NFKC) before use, so the
passphrase types the same on any keyboard.

**Splitting.** `w` is split bytewise with **Shamir's scheme over GF(256)**
into M shares of 32 bytes, any N of which give `w` back (N from 2, M at
most 16); the polynomials' random coefficients come from OpenSSL's
generator. Fewer than N shares give no information about `w`. A share is
32 bytes of one point of the polynomials, and its x-coordinate.

**Words and error correction.** A share is written as words of a list of
1024 (10 bits each; the SLIP-39 list, whose words differ in their first
four letters, so four letters identify one). The share's bytes, with a
header, are the words' **data symbols**, and a Reed-Solomon code over
GF(2^10) adds `P` **parity words** (24 by default; `--parity` allows 4 to
200). A word is one symbol, so a damaged word costs one symbol and not a
whole byte or two. A share is 68 words by default: 5 of header, 13 of
salt, 26 of secret and 24 of parity.

| the reader | the code corrects |
|---|---|
| marks a word as unreadable (`?`), so its place is known (an erasure) | up to `P` of them: 24 of 68 words |
| types a wrong word without knowing (an error) | up to `P/2`: 12 of 68 words |
| both | `e` erasures and `r` errors while `e + 2r <= P` |

A share the code cannot repair is reported as such, and the other
shares are enough while N of them are intact. The words are printed in
numbered lines of five, so a lost word is a known place:

```text
kuipa recovery shard 2 of 5 (any 3 are needed)           set 8F3A1
for alice, realm EXAMPLE.TEST      recovery key id  Zr9Q…k2w
made 2026-10-27 by kuipa 0.4      the passphrase you chose is also needed

 01  humidity   disease    academic   always     aluminum
 02  …
```

**The header.** The first data words say, protected by the same
code: the format version, a 20-bit **set id** that every share of one set
carries (so shares of two sets are never mixed), N, M, this share's index,
the PBKDF2 iteration count, `P`, and the 16-byte salt. Beside the words the page says the same in
English, and how to decode a share with nothing but the page: the word
list, the code (the field polynomial and generator), Shamir's scheme, the
PBKDF2 parameters, the seed's HKDF label and ML-KEM's key generation. The
English is for the person; nothing reads it back, and the words do not
depend on it.

The format is defined by the module documentation of `kuipa-enroll`'s `shards`
module (bit layout, field, generator, word order) and pinned by a test vector, which an
independent implementation of the text above reproduces word for word.

**What the server keeps.** The recovery key's public key, its id and the
set id are registered with the seal operation `escrow-shards`, authenticated
by the owner's ticket and logged, on the owner's own entry (a value of
`ipaKUDeviceEscrow` of kind `shards-key`). For each device key, the client
makes a **blob** for the recovery public key, in the format of a device-key
delivery (`IPDD`, §4: an ML-KEM encapsulation to the recovery key, the
private JWK under a key derived from it) and stores it as a value of kind
`shards`. Nothing the server holds is secret: the blobs open only with the
recovery private key. `kuipa seal device add` makes the blob for a new key
file as soon as the user has a shard set (as it deposits a key when the
realm names a device seal, §4), so the new device is covered **without
any paper**. A token's key never leaves the token and has no blob.

**Recovering.** On a new host, with a ticket, `kuipa seal recover shards`
asks for shards: for each, the words by line, `?` for a word that cannot be
read, a blank line to go on to the next. It repairs each, drops a share
whose code cannot be repaired, refuses shares of different sets, and
stops asking at N consistent shares; then it asks for the passphrase,
recombines `w`, takes `s = w XOR pad`, makes the key pair and checks the key
id against the printed and the registered one, so a wrong passphrase or
a wrong share is told apart from damage. Only then does it ask the server for the
blobs (the operation `recover-shards`, logged, which `kuipa tlog watch`
always flags, as for `recover-code`), opens them, and keeps the old keys
as `recovered.key` for `recover finish` (§2).

**Checking before it matters.** `kuipa seal recovery-shards check`
takes shards in the same way and reports, per share, how many words it
repaired and whether the set would recover, against the registered key id,
without asking for any blob. A paper backup is only as good as the day it
is tested; the command is for that day, and the user is told to run it
after printing.

**Replacing a set.** A shard set is replaced, not edited: a lost paper
is no reason to believe it is lost safely. `recovery-shards create` again
makes a new key and set, and makes the blobs for every device key this host
holds (the other hosts do it with `recovery-shards enroll`; a device whose
key is nowhere is not covered until it is seen). The old set's registration
and blobs are removed; whoever kept an old paper holds nothing the server
accepts.

| someone has | recovery code | recovery shards |
|---|---|---|
| the directory, the blobs | nothing (128-bit code) | nothing (they open only with the recovery key) |
| one or a few shards (fewer than N) | — | nothing |
| N shards, not the passphrase | — | a passphrase search against the key id, at one PBKDF2 each |
| N shards and the passphrase | — | the old device keys, then with the user's ticket their files |
| the paper of the code | the old device key, and with the ticket their files | — |

Decisions:

* **A key pair, not a symmetric key.** A code encrypts to the device
  key's holder and so needs the code each time. A recovery public key
  lets any host protect its device key with no secret in hand, and keeps
  the paper offline.
* **Shamir over the hidden seed, not the key.** The seed is 32 bytes,
  so a share is short, and keeping the passphrase outside the split makes
  the shares worthless without it however many are gathered.
* **Reed-Solomon over words.** The symbol is the word the user reads, so an
  unreadable word is a clean erasure, which the code corrects twice as
  well as an error. It is the SLIP-39 idea, with the checksum grown into
  correction.
* **Not SLIP-39.** SLIP-39 splits a symmetric secret and its checksum finds
  errors without correcting them; neither is what this wants, so shares
  are not interchangeable with its tools. Its word list is reused.
* **PBKDF2, with the passphrase doing the work.** FIPS allows no
  memory-hard KDF, so the cost of a guess is only time. The design spends
  it (2 million iterations), asks for a long passphrase, and keeps the
  salt in the shares so that nothing else has to be kept.
* **No verifiable sharing.** The client that makes the shares is the
  user's, so a share set the user's own client got wrong is found by
  `check`, not by commitments in the shares.
* **No deniable passphrase.** A wrong passphrase gives another key, which
  opens nothing; kuipa does not make it look like a real one.

## 3. Depositors and deposits

A shared seal (DESIGN.md §7.6.12) gains a fourth role, below member:

| role | may |
|---|---|
| depositor (`depositors`, named as members are, in `ipaKUSealDepositor`) | show the seal (to seal to it), deposit, list and retire their own deposits, leave |

A depositor never opens: they register no device, start no session, ask
for no release, fetch no deposit, and a release refuses an opener who is
only a depositor. `kuipa seal share SEAL --depositor --group G` makes
them one; managers, members and depositors count together against
`max_members`. A **deposit** is a file sealed to the seal (`IPUF`) that
the server keeps for the members, since its depositor may be gone by the
time anyone needs it:

```text
cn=<deposit id>,cn=<seal id>,cn=seals,cn=kuipa,cn=etc,<suffix>
  objectClass ipaKUDeposit
  ipaKUDepositData: { "id", "seal", "depositor", "kind": "device" | "luks" | "file",
                      "subject": <what it is for>, "added", "sealed": <IPUF, ≤ 16 KiB> }
```

`subject` says what the deposit is for among its depositor's deposits of
that kind, as string pairs (at most 8): `{"device"}` for a device key,
`{"uuid"}` for a LUKS volume, `{"name"}` for a file; the depositor (a
user, or a host's principal) is the deposit's own field. The seal
operations are:

| operation | who | does |
|---|---|---|
| `deposit` | any role | checks the file is sealed to this seal, keeps it, and with `sealing = registered` registers its bindings; a deposit with the same depositor, kind and subject replaces the earlier one, whose bindings are retired |
| `deposits` | any role | lists deposits without their files: all of them for members, their own for a depositor |
| `fetch-deposit` | members | one deposit with its file, which opens as any file of the seal, under its policy |
| `retire-deposit` | a deposit's depositor, or a manager | removes it and retires its bindings |

Deposits and retirements are logged (`deposit` with `H` of the file,
`retire-deposit` with `H` of its id, kind 3). The realm limits gain
`max_deposits` per depositor and seal (default 32). On the command
line they are `kuipa seal deposit put SEAL FILE [--name N]`, `list`,
`fetch SEAL ID --out F.sealed` and `retire SEAL ID`.

The seal's own policy decides how deposits open, as for any file. For a
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

The realm names its device escrow seal in `cn=recovery,cn=kuipa,cn=etc`
(`ipaKURecovery`: `{"device_seal": "OWNER/NAME", "required": false}`),
and the realm's users are its depositors (for example the group
`ipausers`). Clients learn the setting with the seal operation
`recovery-settings`.

**Depositing.** When `kuipa seal device add` registers a key-file device,
and the realm names a device seal, the client first seals the private
JWK to that seal as a deposit of kind `device` with subject `{"device":
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
   SEAL`) and runs `kuipa seal recover helpdesk`, which prints the new
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
   kind 2) in every seal where the user holds the new device; `kuipa
   tlog watch` always flags one. `device-key` and `deliver` answer only
   members of the realm's device seal.
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
a realm seal such as `helpdesk/disks`.

* `systemd-cryptenroll --recovery-key DEVICE | kuipa escrow luks DEVICE
  --seal helpdesk/disks` (root) enrolls a recovery key in the LUKS2
  header and deposits it as kind `luks`, with subject `{uuid}` (what
  `cryptsetup luksUUID` says, or `--uuid`), in place of the host's
  previous deposit for that volume. kuipa does not enroll the key itself:
  it reads what `systemd-cryptenroll` prints (or `--key-file`), takes the
  line shaped like a systemd recovery key (eight groups of eight modhex
  characters) and refuses input without one, so a mistyped pipe deposits
  nothing. Run again after `cryptsetup luksKillSlot` or a reinstall, it
  keeps the deposit current.
* `kuipa escrow file NAME FILE --seal V` deposits any small secret, such
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
`backup/web1.example.test`, not as the host. Either keeps the seal's descriptor in the host's root-only
state directory (`/var/lib/ipa-client/ku/escrow`), and can neither list
other depositors' deposits nor open its own. When a disk will not unlock
(a dead TPM, a lost Tang server), the helpdesk opens the deposit under
the seal's policy and reads the key to whoever is at the console.

## 6. What each party gets

| someone has | recovery code | device deposit (helpdesk seal with device factor and approvals) |
|---|---|---|
| the directory, the code blob, the deposits | nothing (128-bit code) | nothing (the helpdesk's device share) |
| the realm's escrow keys (an administrator) | nothing | nothing alone; with a helpdesk member's device, the deposits |
| one helpdesk member | — | nothing without `m` approvals |
| a helpdesk member and `m` leads | — | the user's old device key, then (with the server share under the user's own seal policy, or the escrow keys) the user's files sealed to it |
| the user's code | the old device key, and with the user's ticket their files | — |

## 7. Decisions

* **Recover the device key, not each file.** A deposit of the key is one
  object per device, needs no access to the user's files, and works for
  files sealed since. The alternative, a recovery slot in every file,
  would put the helpdesk's key in every file and make every reseal carry
  it.
* **Helpdesk devices decrypt, not the user.** A helpdesk seal without
  the device factor would let the user open their own deposit under the
  helpdesk's approvals, so no helpdesk member would see the key; but the
  realm's administrators could then open every deposit with the escrow
  keys alone. The design prefers to keep administrators out and accepts
  that the delivering helpdesk member sees one key.
* **Deposits live in the directory.** kuipa servers otherwise hold no
  data, but a deposit must outlive its depositor (the lost laptop, the
  reinstalled host), and it is small and sealed. The 16 KiB cap keeps it
  that way.
* **Hardware seals recover through hardware.** A `hardware-bound`
  device has no copy to deposit, and that is the point of such seals.
  Their recovery is a second hardware-bound device registered in the
  seal, for example an ML-KEM key in an HSM that the helpdesk operates
  through PKCS#11: every file then carries a slot for it, and its key
  still never leaves hardware. How that device is held and opened (as a
  member, under approvals) is left for its own design, with the
  attestation that `hardware-bound` needs first.
