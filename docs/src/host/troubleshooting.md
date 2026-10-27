# Troubleshooting

## Exit status

| status | means | what to do |
|---|---|---|
| 0 | done | |
| 75 | no server could be used now (unreachable, rate-limited, not replicated yet) | retry later; the units do this themselves |
| 1 | an administrator must act, or another error: the message says which | read the message; the server's log has the reason for a refusal |
| 2 | wrong usage | `kuipa <command> --help` |

## Seeing what happens

```sh
kuipa --verbose enroll …        # each request, decision and file written
kuipa --trace enroll …          # also endpoints, TLS modes, full advertisements
KUIPA_TRACE=kuipa_tools=trace,kuipa_gssapi=debug kuipa enroll …
```

Traces go to standard error; results stay on standard output. They never
contain secrets: OTPs, passwords, keys and tokens appear only as sizes and
thumbprints. [A traced session](../scenarios/walkthrough.md) reads one
line by line.

## A server refused

A refusal reaches the host as an empty `403`, deliberately without a
reason. The server logs the reason:

```sh
journalctl -u kuipad | grep refused
```

Common ones:

| logged reason | usually |
|---|---|
| an LDAP bind failure on an OTP join | the OTP was mistyped or already spent: issue a new one |
| `… may not rekey …` | the host's keys are for another host name |
| `binding not registered or its principal disabled` | the sealed keytab or file was resealed, retired, or its host or service deleted or locked |
| `the binding is not committed to this seal` | a sealed file presented under another principal or seal: tampering or a bug |
| `unknown join key` / `unknown escrow key` | the host used a key the server has pruned: rotate keys, or keep retired keys longer |

## The advertisement does not verify

* **expired or not yet valid**: check the host's clock;
* **not signed by a trusted realm anchor**: the string or pins name an
  anchor the server does not carry; a rotated anchor is followed only
  while its succession is valid, so issue a new string or pin;
* **describes another deployment**: the server named in DNS or
  `--server` claims another realm, domain or server list. That is an
  attack or a misconfiguration, so `kuipa` stops instead of trying the
  next server;
* **its claim is proven by 1 of the 2 anchors known here**: the host pins
  two anchors and only one vouches for this server, so the server may be
  built on a stolen anchor. Run `kuipa check` and look at the servers'
  anchor exchange.

## Sealed keytabs at boot

```sh
systemctl status kuipa-unseal.service
journalctl -u kuipa-unseal
kuipa-unseal --all --verbose
```

Exit 75 means no server answered: check the network to the IPA servers'
HTTPS port. A refusal means the seal is no longer registered: run `kuipa
protect` again (with the right `--keytab` or `--file`) once the host is
healthy.
