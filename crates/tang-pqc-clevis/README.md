# tang-pqc-clevis

A command-line client for post-quantum Tang servers, and the Clevis pin
`tang-pqc`. It is built on [`tang-pqc`](../tang-pqc).

The binary is called `tang-pqc`. When installed as
`clevis-encrypt-tang-pqc` and `clevis-decrypt-tang-pqc`, it also works as
a Clevis pin. It can unlock LUKS volumes and other Clevis-protected data
with any server that implements `tang-pqc`, including `kuipad`.

## Usage

To list the signing keys a server advertises, and pick the one to trust,
run:

```sh
tang-pqc adv https://tang.example.test
```

Encrypt and decrypt through Clevis:

```sh
clevis encrypt tang-pqc '{"url":"https://tang.example.test","thp":"<thumbprint>"}' < secret > secret.jwe
clevis decrypt < secret.jwe
```

The pin takes this configuration:

| key | meaning |
|---|---|
| `url` | the base URL of the Tang server (required) |
| `thp` | the thumbprint of a trusted signing key (required) |
| `adv` | a file containing a trusted advertisement, used instead of fetching one (for offline provisioning) |
| `ca` | a PEM file to verify an `https` server against |

## Installation

To install the binary, the Clevis pin links and the dracut module that
brings the pin into the initramfs, run:

```sh
cargo build --release -p tang-pqc-clevis
contrib/clevis/install.sh [PREFIX] [DESTDIR]
```

Run this from the root of the repository.

## License

This crate is part of [kuipa](../../README.md). It is licensed under the
GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
