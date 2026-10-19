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
