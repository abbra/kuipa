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
use crate::paths::{self, Error, Paths};

/// The witnesses a host trusts (`/etc/ipa/ku-witnesses.json`), and how
/// many of them must cosign a head for `kuipa tlog watch` to accept it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Trusted {
    /// Cosignatures a head needs; 0 requires none.
    pub required: usize,
    /// The witnesses' public JWKs.
    pub witnesses: Vec<Value>,
}

impl Trusted {
    /// The host's list; empty, requiring nothing, when there is none.
    ///
    /// # Errors
    ///
    /// An unreadable or malformed file: a broken list is not an empty one.
    pub fn load(paths: &Paths) -> Result<Self, Error> {
        let path = paths.witnesses();
        match std::fs::read(&path) {
            Ok(bytes) => {
                Ok(serde_json::from_slice(&bytes)
                    .map_err(|e| format!("{}: {e}", path.display()))?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// The witnesses' keys.
    ///
    /// # Errors
    ///
    /// A JWK that is not a public ML-DSA key.
    pub fn keys(&self) -> Result<Vec<tang_pqc::VerifyingKey>, Error> {
        self.witnesses
            .iter()
            .map(|w| {
                Ok(tang_pqc::VerifyingKey::from_jwk_json(
                    w.to_string().as_bytes(),
                )?)
            })
            .collect()
    }
}

/// `kuipa tlog witnesses`: add a witness (its public JWK), remove one
/// (by thumbprint), set how many must cosign, and show the list.  Run
/// as root: the file is the host's.
///
/// # Errors
///
/// A private or malformed JWK, an unknown thumbprint, more required
/// cosignatures than witnesses, or an I/O error.
pub fn manage(
    paths: &Paths,
    add: Option<&Path>,
    remove: Option<&str>,
    required: Option<usize>,
) -> Result<Value, Error> {
    let mut trusted = Trusted::load(paths)?;
    let changed = add.is_some() || remove.is_some() || required.is_some();
    if let Some(file) = add {
        let jwk: Value = serde_json::from_slice(&std::fs::read(file)?)?;
        if jwk.get("priv").is_some() {
            return Err("give the witness's public JWK, not its private key".into());
        }
        let key = tang_pqc::VerifyingKey::from_jwk_json(jwk.to_string().as_bytes())?;
        let keys = trusted.keys()?;
        if !keys.iter().any(|k| k.thumbprint() == key.thumbprint()) {
            trusted
                .witnesses
                .push(serde_json::from_str(&key.to_jwk_json())?);
        }
    }
    if let Some(thp) = remove {
        let keys = trusted.keys()?;
        let before = trusted.witnesses.len();
        trusted.witnesses = trusted
            .witnesses
            .into_iter()
            .zip(&keys)
            .filter(|(_, k)| k.thumbprint().to_string() != thp)
            .map(|(w, _)| w)
            .collect();
        if trusted.witnesses.len() == before {
            return Err(format!("no witness {thp}").into());
        }
    }
    if let Some(n) = required {
        trusted.required = n;
    }
    if trusted.required > trusted.witnesses.len() {
        return Err(format!(
            "{} cosignatures required of {} witnesses",
            trusted.required,
            trusted.witnesses.len()
        )
        .into());
    }
    if changed {
        paths::write_file(
            &paths.witnesses(),
            &serde_json::to_vec_pretty(&trusted)?,
            0o644,
        )?;
    }
    let thumbprints: Vec<String> = trusted
        .keys()?
        .iter()
        .map(|k| k.thumbprint().to_string())
        .collect();
    Ok(json!({ "required": trusted.required, "witnesses": thumbprints }))
}

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

#[cfg(test)]
mod tests {
    use tang_pqc::SignatureAlg;

    use super::*;

    #[test]
    fn the_hosts_witness_list() {
        let root = std::env::temp_dir().join(format!("kuipa-witnesses-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/ipa")).unwrap();
        let paths = Paths::new(&root);
        // No file: nothing trusted, nothing required.
        let none = Trusted::load(&paths).unwrap();
        assert_eq!((none.required, none.witnesses.len()), (0, 0));

        let key = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
        let public = root.join("w.pub.jwk");
        std::fs::write(&public, key.public().to_jwk_json()).unwrap();
        let private = root.join("w.jwk");
        std::fs::write(&private, key.to_jwk().unwrap().as_ref()).unwrap();
        assert!(manage(&paths, Some(&private), None, None).is_err());
        // More required than trusted is refused, and nothing is written.
        assert!(manage(&paths, None, None, Some(1)).is_err());
        assert!(!paths.witnesses().exists());

        let shown = manage(&paths, Some(&public), None, Some(1)).unwrap();
        assert_eq!(shown["required"], 1);
        let thp = key.public().thumbprint().to_string();
        assert_eq!(shown["witnesses"][0], thp.as_str());
        // Adding it again changes nothing; the keys load back.
        manage(&paths, Some(&public), None, None).unwrap();
        let trusted = Trusted::load(&paths).unwrap();
        assert_eq!(trusted.keys().unwrap().len(), 1);
        // It cannot be removed while one cosignature is required.
        assert!(manage(&paths, None, Some(&thp), None).is_err());
        assert!(manage(&paths, None, Some("nope"), Some(0)).is_err());
        manage(&paths, None, None, Some(0)).unwrap();
        let emptied = manage(&paths, None, Some(&thp), None).unwrap();
        assert_eq!(emptied["witnesses"].as_array().unwrap().len(), 0);
        // A broken list is an error, not an empty one.
        std::fs::write(paths.witnesses(), b"{").unwrap();
        assert!(Trusted::load(&paths).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
