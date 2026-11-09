# Backups sealed to paper

A FreeIPA server backup holds the CA keys, the Directory Manager hash,
the KDC master key and, with kuipa, the key directory `/var/lib/ipa/ku`.
kuipa seals it to a recovery key kept on paper and has the realm sign it,
so the backup opens after every server is lost, and a file someone plants
in the backup repository is refused before anything is decrypted.
FreeIPA's `ipa-backup --kuipa` does this (see its design,
`doc/designs/kuipa-backup.md`); this page is the kuipa side.

## Make the key, once

Anywhere with the `kuipa` package. It needs no ticket and registers
nothing:

```sh
kuipa backup key create --realm EXAMPLE.TEST --threshold 2 --shares 3 \
    --out recipient.json
```

It asks for a recovery passphrase (at least 16 characters; five or six
random words) and prints three pages of words. Any two pages and the
passphrase make the key; one page, or two without the passphrase, tell a
reader nothing. Print the pages, keep them apart from each other and from
the backups, and check them now:

```sh
kuipa backup key check --recipient recipient.json < two-pages.txt
```

`recipient.json` holds the public key only. Give it to the hosts that make
backups. On an enrolled host, print the **realm card** and keep it with
the papers:

```sh
kuipa backup card --recipient recipient.json
```

## Seal and sign

```sh
tar -czf - /some/data | kuipa backup seal --recipient recipient.json -o backup.tar.kuipa
kuipa sign blob --purpose ipa-backup backup.tar.kuipa header
```

The realm's signing policy must list the host for the purpose
`ipa-backup`. A backup of any size is digested as a stream.

## Open, after the loss

On a new host with nothing from the realm, with two papers on standard
input and the anchors from the card:

```sh
kuipa backup open backup.tar.kuipa --also header \
    --realm EXAMPLE.TEST --anchor <thumbprint from the card> \
    --signer host/ipa1.example.test --out backup.tar
```

The signature is checked first; a changed file, a signature for another
purpose or signer, or other anchors stop the command before the papers
are asked for. A card printed before an anchor rotation still verifies
backups made after it for as long as the servers carry the succession
(400 days by default). `--no-verify` opens without a signature and says
so.

Nothing here replaces testing a restore: `ipa-restore` on a fresh host is
the only proof the whole chain works.
