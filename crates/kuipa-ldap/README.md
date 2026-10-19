# kuipa-ldap

A synchronous LDAP client: a thin, safe wrapper around the OpenLDAP C
library.

* Simple, SASL GSSAPI and S4U (impersonated) binds
* Search, add, modify and delete
* Extended operations

The calls block, so use them from blocking code or from
`tokio::task::spawn_blocking`.

```rust
use kuipa_ldap::{Auth, LdapConnection, Scope};

let mut conn = LdapConnection::connect("ldapi://%2Frun%2Fslapd-EXAMPLE-COM.socket", None, false, 10)?;
conn.bind(&Auth::Gssapi)?;
for e in conn.search("cn=accounts,dc=example,dc=com", Scope::Subtree, "(fqdn=web1.example.com)", &["cn"])? {
    println!("{}: {:?}", e.dn, e.attrs);
}
```

## Requirements

You need the OpenLDAP, Cyrus SASL and MIT Kerberos development files:
`openldap-devel`, `cyrus-sasl-devel` and `krb5-devel` on Fedora.

## License

This crate is part of [kuipa](../../README.md). It is derived from the
LDAP bindings of the ahdapa project (`ahdapa-ldap`). It is licensed under
the GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
