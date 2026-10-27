# Keys and rotation

Each server keeps its keys in `/var/lib/ipa/ku` (mode 0600, written
atomically). None of them leave the server.

| key | file | what it does |
|---|---|---|
| anchor | `anchor.jwk` | vouches for the realm's servers; hosts pin its thumbprint |
| signing key | `signing.jwk` | signs this server's advertisement |
| join keys | `join-<kid>.jwk` | receive enrollments and rekeys (ML-KEM) |
| escrow keys | `escrow-<kid>.jwk` | release the shares of sealed keytabs, files and seals |
| trust keys | `trust-<kid>.jwk` | receive trust requests from other realms |
| voucher keys | `voucher-<thp>.jwk` | public keys of the voucher issuers this server accepts |
| Tang keys | `tang/<thp>.jwk` | the post-quantum Tang service, if enabled |

A file whose name starts with a dot (`.join-…`) is a **retired** key: still
answered, no longer advertised.

## Rotating the working keys

```sh
kuipad rotate-keys                 # join, escrow and trust keys
kuipad rotate-keys --signing       # also the signing key
systemctl restart kuipad
```

New keys are advertised; the old ones are retired and keep answering, so
nothing in flight breaks. Rotate on a schedule that suits you (monthly is
a good start). A new signing key needs a new delegation, which the next
exchange round issues.

## Pruning retired keys

```sh
kuipad prune-keys                       # join and trust keys retired over 14 days ago,
                                        # escrow keys retired over 400 days ago
kuipad prune-keys --escrow-days 800     # keep escrow keys longer
systemctl restart kuipad
```

Escrow keys must outlive every sealed keytab and file bound to them: a
host unseals with the key that was current when it last sealed. Hosts
reseal at every key rotation (monthly with `kuipa-rotate.timer`), but
sealed *files* and users' seal files are only resealed when someone
reseals them. Keep retired escrow keys at least as long as such files
should keep opening.

## Rotating the anchor

```sh
kuipad rotate-anchor --days 400
systemctl restart kuipad
```

The old anchor signs a **succession** to the new one, valid for `--days`,
and is deleted. Hosts that pin the old anchor follow the succession and
switch their pins at their next key rotation. After the succession expires,
hosts that never came back must be given a new enrollment string or pin.

Rotate an anchor:

* when you suspect it was copied: the old anchor cannot sign anything new
  once deleted, and hosts that also pin another anchor refuse impostors at
  once;
* when a server leaves the realm;
* before image pins expire.

Reissue enrollment strings and image pins naming the old anchor, and check
that every host has rotated its keys within the succession's lifetime
(`kuipa status` on the host shows its pins).

## Anchor servers in large realms

Every anchor adds to the exchange's state. Measured: with 60 servers all
holding anchors, the state is about 490 KB and a claim renewal sends
about 320 KB; with 6 anchors among the 60, 55 KB and 32 KB. Give the
anchor role to a few servers (`"anchor": true`
on, say, one per site) and `"anchor": false` to the rest: they still
serve hosts and are vouched for by the anchor servers. A realm needs at
least one anchor server, and hosts are safest pinning two.

## Tang

```sh
kuipad tang-keygen        # enable the Tang service; prints the thumbprint clients pin
kuipad tang-thp           # the current thumbprints
kuipad tang-rotate        # retire the Tang keys, make new ones
systemctl restart kuipad
```

Retired Tang exchange keys keep answering existing bindings. They are never
pruned automatically: delete their `.`-files from `/var/lib/ipa/ku/tang`
once every client has rebound (`clevis luks regen`).
