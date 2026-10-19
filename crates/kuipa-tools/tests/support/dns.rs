//! A stub DNS server answering SRV queries from a fixed table, over UDP and
//! TCP on the same local port.  With `truncate_udp`, UDP answers are
//! truncated so clients must retry over TCP.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;

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
