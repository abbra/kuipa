//! Server discovery through DNS SRV records against a stub DNS server over
//! real UDP and TCP sockets (§4.6).

mod support;

use std::collections::HashMap;

use kuipa_tools::dns;

fn table() -> HashMap<String, Vec<support::dns::Record>> {
    let records = [
        (10, 0, 389, "ipa2.example.test"),
        (0, 10, 389, "ipa1.example.test"),
        (0, 50, 389, "ipa3.example.test"),
        (0, 90, 389, "evil\nname"),
        (0, 5, 389, "IPA1.example.test"),
    ];
    HashMap::from([(
        "_ldap._tcp.example.test".to_owned(),
        records
            .iter()
            .map(|(p, w, port, t)| (*p, *w, *port, (*t).to_owned()))
            .collect(),
    )])
}

#[test]
fn servers_by_priority_and_weight_over_udp_and_tcp() {
    for truncate_udp in [false, true] {
        let resolver = support::dns::serve(table(), truncate_udp);
        let servers = dns::ipa_servers_from("example.test", &[resolver]).unwrap();
        assert_eq!(
            servers,
            [
                "ipa3.example.test",
                "ipa1.example.test",
                "ipa2.example.test"
            ],
            "priority, then weight; unsafe and duplicate names dropped (truncated: {truncate_udp})"
        );
    }
}

#[test]
fn no_records_is_an_error() {
    let resolver = support::dns::serve(table(), false);
    let err = dns::ipa_servers_from("other.test", &[resolver]).unwrap_err();
    assert!(err.to_string().contains("_ldap._tcp.other.test"), "{err}");
    // No resolver at all.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let err = dns::ipa_servers_from("example.test", &[silent.local_addr().unwrap()]);
    assert!(err.is_err());
}

/// `KUIPA_DNS` and `KUIPA_DNS_CA` are process-wide, so the encrypted
/// transport tests serialise.
static TRANSPORT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` with `KUIPA_DNS` set to `server`'s address and
/// `KUIPA_DNS_CA` pointing at a temporary file with its CA, restoring
/// both after.
fn with_dot_env(server: &support::dns::TlsDns, scheme: &str, f: impl FnOnce()) {
    let _guard = TRANSPORT.lock().unwrap();
    let ca = server.ca_pem.clone();
    let file = std::env::temp_dir().join(format!("kuipa-dns-ca-{}.pem", std::process::id()));
    std::fs::write(&file, &ca).unwrap();
    // The certificate carries the server's IP in its SAN, so the address
    // is the TLS name too (no name resolution in tests).
    let dns = format!("{scheme}://{}", server.addr);
    let old_dns = std::env::var("KUIPA_DNS").ok();
    let old_ca = std::env::var("KUIPA_DNS_CA").ok();
    // SAFETY: the transport tests hold TRANSPORT and the test harness runs
    // one test at a time per binary; the resolver's tokio runtime threads
    // have exited before the variables are restored.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("KUIPA_DNS", &dns);
        std::env::set_var("KUIPA_DNS_CA", &file);
    }
    f();
    match old_dns {
        Some(v) => {
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var("KUIPA_DNS", v);
            }
        }
        None => {
            #[allow(unsafe_code)]
            unsafe {
                std::env::remove_var("KUIPA_DNS");
            }
        }
    }
    match old_ca {
        Some(v) => {
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var("KUIPA_DNS_CA", v);
            }
        }
        None => {
            #[allow(unsafe_code)]
            unsafe {
                std::env::remove_var("KUIPA_DNS_CA");
            }
        }
    }
    let _ = std::fs::remove_file(&file);
}

#[test]
fn servers_over_dot() {
    let server = support::dns::serve_tls(table(), "dot");
    with_dot_env(&server, "dot", || {
        let servers = dns::ipa_servers("example.test").unwrap();
        assert_eq!(
            servers,
            [
                "ipa3.example.test",
                "ipa1.example.test",
                "ipa2.example.test"
            ],
            "SRV discovery over DoT, verified against KUIPA_DNS_CA"
        );
    });
}

#[test]
fn servers_over_doh() {
    let server = support::dns::serve_tls(table(), "doh");
    with_dot_env(&server, "doh", || {
        let servers = dns::ipa_servers("example.test").unwrap();
        assert_eq!(
            servers,
            [
                "ipa3.example.test",
                "ipa1.example.test",
                "ipa2.example.test"
            ],
            "SRV discovery over DoH, verified against KUIPA_DNS_CA"
        );
    });
}

#[test]
fn dot_without_ca_fails() {
    let server = support::dns::serve_tls(table(), "dot");
    with_dot_env(&server, "dot", || {
        // Without the CA, the server's certificate must not be trusted.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("KUIPA_DNS_CA");
        };
        let err = dns::ipa_servers("example.test").unwrap_err();
        assert!(
            err.to_string().contains("no IPA servers") || err.to_string().contains("lookup"),
            "untrusted DoT server rejected: {err}"
        );
    });
}
