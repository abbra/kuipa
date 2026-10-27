//! A stub DNS server answering SRV queries from a fixed table, over UDP and
//! TCP on the same local port.  With `truncate_udp`, UDP answers are
//! truncated so clients must retry over TCP.  `serve_tls` and `serve_https`
//! answer the same table over TLS (a TCP stream per query for `DoT`, an
//! HTTP/2 POST for `DoH`), with a certificate from a freshly generated CA,
//! which the returned [`TlsDns`] hands to a trusting client.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use native_ossl::pkey::{Pkey, Private};
use synta_certificate::{
    CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder, SubjectAlternativeNameBuilder,
    der_to_pem,
};

/// `(priority, weight, port, target)`.
pub type Record = (u16, u16, u16, String);

/// The server's address; it runs until the process exits.
pub fn serve(records: HashMap<String, Vec<Record>>, truncate_udp: bool) -> SocketAddr {
    let records = Arc::new(records);
    let (udp, tcp) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()) {
            break (udp, tcp);
        }
    };
    let addr = udp.local_addr().unwrap();
    let r = records.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = udp.recv_from(&mut buf) {
            if let Some(a) = answer(&buf[..n], &r, truncate_udp) {
                let _ = udp.send_to(&a, from);
            }
        }
    });
    std::thread::spawn(move || {
        for stream in tcp.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut len = [0u8; 2];
            if s.read_exact(&mut len).is_err() {
                continue;
            }
            let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
            if s.read_exact(&mut q).is_err() {
                continue;
            }
            if let Some(a) = answer(&q, &records, false) {
                let len = u16::try_from(a.len()).unwrap().to_be_bytes();
                let _ = s.write_all(&len).and_then(|()| s.write_all(&a));
            }
        }
    });
    addr
}

/// The question name of query `q`, lowercase, and the end of the question.
fn question(q: &[u8]) -> Option<(String, usize)> {
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*q.get(pos)?);
        if len == 0 {
            return Some((labels.join(".").to_ascii_lowercase(), pos + 5));
        }
        labels.push(String::from_utf8(q.get(pos + 1..pos + 1 + len)?.to_vec()).ok()?);
        pos += 1 + len;
    }
}

fn answer(q: &[u8], records: &HashMap<String, Vec<Record>>, truncate: bool) -> Option<Vec<u8>> {
    let (name, end) = question(q)?;
    let mut a = q.get(..end)?.to_vec();
    let found = records.get(&name);
    let rcode = if found.is_some() { 0 } else { 3 };
    let flags: u16 = 0x8180 | rcode | if truncate { 0x0200 } else { 0 };
    a[2..4].copy_from_slice(&flags.to_be_bytes());
    // The question only: no authority or additional records (a client's
    // EDNS record is not echoed).
    a[8..12].fill(0);
    let found = if truncate { None } else { found };
    let list = found.map_or(&[][..], Vec::as_slice);
    a[6..8].copy_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
    for (prio, weight, port, target) in list {
        a.extend_from_slice(&[0xc0, 12, 0, 33, 0, 1, 0, 0, 1, 44]);
        let mut rdata = Vec::new();
        for v in [prio, weight, port] {
            rdata.extend_from_slice(&v.to_be_bytes());
        }
        for label in target.split('.') {
            rdata.push(u8::try_from(label.len()).unwrap());
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        a.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        a.extend_from_slice(&rdata);
    }
    Some(a)
}

/// A stub DNS server over TLS: `dot` (RFC 7858, a length-prefixed stream
/// per query) or `doh` (RFC 8484, HTTP/2 POSTs of wire-format queries).
/// The certificate is signed by a freshly generated CA, whose PEM the
/// caller gives back to the client through `KUIPA_DNS_CA`.
pub struct TlsDns {
    /// Where the server listens (853 or 443 semantics; any local port).
    pub addr: SocketAddr,
    /// The CA's PEM, to write where `KUIPA_DNS_CA` points.
    pub ca_pem: Vec<u8>,
    /// The runtime the accept loop runs on; the server stops when this
    /// is dropped.
    pub runtime: tokio::runtime::Runtime,
}

/// Serve `records` over TLS as `dot` or `doh`; see [`TlsDns`].  Runs
/// until the process exits.
///
/// # Panics
///
/// If a listening port, the TLS configuration or the certificate cannot
/// be made.
pub fn serve_tls(records: HashMap<String, Vec<Record>>, kind: &str) -> TlsDns {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(async { tokio::net::TcpListener::bind("127.0.0.1:0").await })
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let (cert, key, ca_pem) = chain(addr.ip());
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls_native_ossl::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let records = Arc::new(records);
    let doh = kind == "doh";
    runtime.spawn(async move {
        let config = Arc::new(config);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let config = config.clone();
            let records = records.clone();
            tokio::spawn(async move {
                let tls = tokio_rustls::TlsAcceptor::from(config)
                    .accept(tcp)
                    .await
                    .ok()?;
                if doh {
                    serve_doh(tls, &records).await
                } else {
                    serve_dot(tls, &records).await
                }
            });
        }
    });
    TlsDns {
        addr,
        ca_pem,
        runtime,
    }
}

/// Answer length-prefixed DNS queries on `tls` until the peer leaves.
async fn serve_dot(
    mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    records: &HashMap<String, Vec<Record>>,
) -> Option<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let mut len = [0u8; 2];
        tls.read_exact(&mut len).await.ok()?;
        let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
        tls.read_exact(&mut q).await.ok()?;
        if let Some(a) = answer(&q, records, false) {
            let len = u16::try_from(a.len()).unwrap().to_be_bytes();
            tls.write_all(&len).await.ok()?;
            tls.write_all(&a).await.ok()?;
        }
    }
}

/// Answer one HTTP/2 `POST` of a wire-format query with the wire-format
/// response, as RFC 8484 §4.1 defines; the connection then closes.
async fn serve_doh(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    records: &HashMap<String, Vec<Record>>,
) -> Option<()> {
    let mut connection = h2::server::Builder::new()
        .initial_connection_window_size(1024 * 1024)
        .handshake::<_, bytes::Bytes>(tls)
        .await
        .ok()?;
    while let Some(request) = connection.accept().await {
        let Ok((request, mut respond)) = request else {
            continue;
        };
        let (parts, mut body) = request.into_parts();
        let records = records.clone();
        tokio::spawn(async move {
            let mut query = Vec::new();
            while let Some(chunk) = body.data().await {
                query.extend_from_slice(chunk.ok()?.as_ref());
            }
            let _ = body;
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/dns-message")
                .body(())
                .ok()?;
            let mut send = respond.send_response(response, false).ok()?;
            if parts.method == http::Method::POST
                && let Some(a) = answer(&query, &records, false)
            {
                send.send_data(a.into(), true).ok()?;
            }
            Some(())
        });
    }
    Some(())
}

/// A server certificate for `ip` (SAN: the address), the key, and the
/// CA's PEM.
fn chain(ip: std::net::IpAddr) -> (CertificateDer<'static>, PrivateKeyDer<'static>, Vec<u8>) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ec = || {
        let params = native_ossl::params::ParamBuilder::new()
            .unwrap()
            .set(native_ossl::typed_params::ec::GROUP, c"P-256")
            .unwrap()
            .build()
            .unwrap();
        let mut kgen = native_ossl::pkey::KeygenCtx::new(c"EC").unwrap();
        let _ = kgen.set_params(&params);
        kgen.generate().unwrap()
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now = i64::try_from(now).unwrap();
    let validity = |offset: i64| {
        let gt = synta::GeneralizedTime::from_unix(now + offset).unwrap();
        synta::UtcTime::new(gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second).unwrap()
    };
    let ca_key = ec();
    let ca_spki = ca_key.public_key_to_der().unwrap();
    let ca_name = NameBuilder::new()
        .common_name("kuipa Test DNS CA")
        .build()
        .unwrap();
    let sign = |key: &Pkey<Private>,
                subject_name: &[u8],
                subject_spki: &[u8],
                serial: i64,
                ca: bool,
                extra: &[(&[u32], bool, &[u8])]|
     -> Vec<u8> {
        let backend = synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
            key.to_pkcs8_der().unwrap(),
        );
        let signer = synta_certificate::crypto::PrivateKey::as_signer(&backend, "sha256");
        let ski = synta_certificate::encode_subject_key_identifier(
            subject_spki,
            synta_certificate::KeyIdMethod::Rfc5280Sha1,
            &synta_certificate::OpensslKeyIdHasher,
        )
        .unwrap();
        let mut builder = CertificateBuilder::new()
            .subject_name(subject_name)
            .issuer_name(&ca_name)
            .public_key_der(subject_spki)
            .serial_number(synta::Integer::from_i64(serial))
            .not_valid_before(synta_certificate::Time::UtcTime(validity(-90 * 24 * 3600)))
            .not_valid_after(synta_certificate::Time::UtcTime(validity(90 * 24 * 3600)))
            .add_extension_oid(synta_certificate::oids::SUBJECT_KEY_IDENTIFIER, false, &ski);
        if ca {
            let bc = synta_certificate::encode_basic_constraints(true, None).unwrap();
            builder =
                builder.add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc);
        }
        for (oid, critical, value) in extra {
            builder = builder.add_extension_oid(oid, *critical, value);
        }
        builder.sign(&signer).unwrap()
    };
    let ca_der = sign(&ca_key, &ca_name, &ca_spki, 1, true, &[]);
    let key = ec();
    let spki = key.public_key_to_der().unwrap();
    let san = SubjectAlternativeNameBuilder::new()
        .ip_address(&match ip {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        })
        .build()
        .unwrap();
    let eku = ExtendedKeyUsageBuilder::new()
        .server_auth()
        .build()
        .unwrap();
    let leaf_der = sign(
        &ca_key,
        &NameBuilder::new()
            .common_name("kuipa Test DNS")
            .build()
            .unwrap(),
        &spki,
        2,
        false,
        &[
            (synta_certificate::oids::SUBJECT_ALT_NAME, false, &san),
            (synta_certificate::oids::EXTENDED_KEY_USAGE, false, &eku),
        ],
    );
    (
        CertificateDer::from(leaf_der),
        PrivateKeyDer::Pkcs8(key.to_pkcs8_der().unwrap().into()),
        der_to_pem("CERTIFICATE", &ca_der),
    )
}
