//! `kuipa-witness`: cosign servers' transparency-log heads that extend
//! the last ones this witness cosigned (DESIGN-tlog.md §4).
//!
//! A witness holds one ML-DSA key and a state file of the last head it
//! cosigned per log.  Each pass, per server: verify the server's
//! advertisement against the given anchors, which names the log's
//! signing key; fetch the head; fetch the consistency proof from the
//! last cosigned head; cosign only a head that extends it
//! ([`kuipa_enroll::tlog::witness`]); post the cosignature back.  A
//! server that shows different logs to different readers is caught
//! unless its witnesses collude.

use std::collections::BTreeMap;
use std::path::Path;

use kuipa_enroll::tlog::{self, Head};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tang_pqc::{Policy, SigningKey, Thumbprint, b64, unix_seconds};

use crate::net::{Endpoint, NetError, Trust};
use crate::paths::{self, Error};

/// The last head cosigned for one log.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Cosigned {
    size: u64,
    root: String,
    time: u64,
}

fn read_state(path: &Path) -> Result<BTreeMap<String, Cosigned>, Error> {
    match std::fs::read(path) {
        Ok(bytes) => {
            Ok(serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e.into()),
    }
}

/// One pass over `servers`: cosign each server's head when it extends
/// the last one cosigned, and record it.  A server whose head does not
/// extend is reported `forked` and never cosigned again until its state
/// entry is removed by hand.
///
/// # Errors
///
/// An unreadable or unwritable state file.  A server's own failure is
/// reported in its row.
pub fn pass(
    key: &SigningKey,
    servers: &[String],
    anchors: &[Thumbprint],
    state: &Path,
) -> Result<Value, Error> {
    let mut cosigned = read_state(state)?;
    let mut rows = Vec::new();
    for server in servers {
        let row = match one(key, server, anchors, &mut cosigned) {
            Ok(row) => row,
            Err(e) => json!({ "server": server, "state": format!("skipped: {e}") }),
        };
        rows.push(row);
    }
    paths::write_file(state, &serde_json::to_vec_pretty(&cosigned)?, 0o600)?;
    Ok(json!({ "witness": key.public().thumbprint().to_string(), "servers": rows }))
}

fn one(
    key: &SigningKey,
    server: &str,
    anchors: &[Thumbprint],
    cosigned: &mut BTreeMap<String, Cosigned>,
) -> Result<Value, Error> {
    let endpoint = Endpoint::new(server, &Trust::FirstContact)?;
    let policy = Policy::from_system()?;
    let (log, log_key) = crate::audit::advertised_log(&endpoint, anchors, &policy)?;
    let id = log.to_string();
    let row = |state: &str, size: u64| json!({ "server": server, "log": id, "state": state, "size": size });
    let Some(mut head) = endpoint.tlog_head(&log)? else {
        return Ok(row("empty", 0));
    };
    let previous = cosigned
        .get(&id)
        .map(|c| -> Result<Head, Error> {
            Ok(Head {
                log,
                size: c.size,
                root: b64::decode(&c.root)?
                    .try_into()
                    .map_err(|_| "a malformed root in the witness state")?,
                time: c.time,
            })
        })
        .transpose()?;
    let proof = match &previous {
        Some(p) if head.head.size > p.size => {
            endpoint.tlog_consistency(&log, p.size, head.head.size)?
        }
        _ => Vec::new(),
    };
    let me = *key.public().thumbprint();
    if head.cosignatures.iter().any(|c| c.witness == me) {
        return Ok(row("unchanged", head.head.size));
    }
    let now = unix_seconds(std::time::SystemTime::now());
    match tlog::witness(
        key,
        &log_key,
        &policy,
        previous.as_ref(),
        &mut head,
        &proof,
        now,
    ) {
        Ok(()) => {}
        Err(kuipa_enroll::Error::Mismatch(_)) => return Ok(row("forked", head.head.size)),
        Err(e) => return Err(e.into()),
    }
    let path = format!("tlog/{log}/cosign");
    match endpoint.post(&path, head.to_bytes()) {
        Ok(_) => {}
        // A head re-signed since it was fetched: cosign the new one next
        // pass.  Nothing is recorded, so the next pass starts from the
        // same previous head.
        Err(NetError::Other(m)) if m.contains("409") => return Ok(row("stale", head.head.size)),
        Err(e) => return Err(e.into()),
    }
    cosigned.insert(
        id.clone(),
        Cosigned {
            size: head.head.size,
            root: b64::encode(&head.head.root),
            time: head.head.time,
        },
    );
    Ok(row("cosigned", head.head.size))
}
