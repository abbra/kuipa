//! `kuipa-audit`: read-only reports on a realm's claim logs
//! (DESIGN-claim-logs.md §5).
//!
//! The tool fetches only public endpoints — the advertisement, the
//! anchor log and the claim-log pages — and checks what it fetches
//! against heads (pinned or given): it is `curl` plus the tree math.
//! It holds no keys, writes nothing, and authenticates nothing a
//! public reader could not.

use serde_json::{Value, json};

use crate::net::{Endpoint, Trust};
use crate::paths::Error;
use crate::paths::{self, Paths};

/// `kuipa-audit claim-log`: one anchor's page, decoded.
///
/// # Errors
///
/// [`Error`] when the server cannot be reached or answers nothing for
/// the anchor.
pub fn claim_log(server: &str, anchor: &str, from: u64) -> Result<Value, Error> {
    let endpoint = Endpoint::new(server, &Trust::FirstContact)?;
    let anchor: tang_pqc::Thumbprint = anchor.parse().map_err(|_| "bad anchor thumbprint")?;
    let page = endpoint.claim_log(&anchor, from)?;
    Ok(json!({
        "server": server,
        "anchor": page.anchor,
        "size": page.size,
        "root": tang_pqc::b64::encode(&page.root),
        "exp": page.exp,
        "leaves": page.leaves,
        "vouch": page.vouch,
    }))
}

/// `kuipa-audit coverage`: what the pinned heads cover, per anchor.
///
/// With no heads given and run on an enrolled host, the host's pinned
/// windows are the subject; otherwise `--pinned-head "THP SIZE ROOT"`
/// names them.  Each anchor's report says whether the server's newest
/// head extends the pinned one (current), the server's tree has grown
/// beyond it (stale — with the consistency check applied read-only),
/// or is shorter (restarted).
///
/// # Errors
///
/// [`Error`] when no server answers.
pub fn coverage(
    server: &str,
    given: &[(tang_pqc::Thumbprint, u64, [u8; 32])],
) -> Result<Value, Error> {
    let endpoint = Endpoint::new(server, &Trust::FirstContact)?;
    let pins: Vec<paths::Pin> = if given.is_empty() {
        let paths = Paths::from_env();
        paths::read_anchor_pins(&paths.anchors()).map_err(|e| {
            format!("no pinned heads given and none on this host (--pinned-head, or run on an enrolled host): {e}")
        })?
    } else {
        given
            .iter()
            .map(|(anchor, size, root)| paths::Pin {
                anchor: *anchor,
                exp: None,
                heads: vec![(*size, *root)],
                frozen: false,
            })
            .collect()
    };
    let anchors: Vec<tang_pqc::Thumbprint> = pins.iter().map(|p| p.anchor).collect();
    // The heads the server would serve for these anchors.
    let heads: Vec<kuipa_enroll::delegation::HeadPin> = pins
        .iter()
        .flat_map(|p| {
            p.heads
                .iter()
                .map(|(size, root)| kuipa_enroll::delegation::HeadPin {
                    anchor: p.anchor,
                    size: *size,
                    root: *root,
                })
        })
        .collect();
    let _ = endpoint.advertisement_with_heads(&anchors, &heads)?;
    let mut rows = Vec::new();
    for pin in &pins {
        let Some((newest, pinned_root)) = pin.heads.last().copied() else {
            rows.push(json!({
                "anchor": pin.anchor.to_string(),
                "state": "no head pinned",
            }));
            continue;
        };
        let page = endpoint.claim_log(&pin.anchor, 0);
        let row = match page {
            Ok(page) => {
                let state = if page.size == newest && page.root == pinned_root {
                    "current"
                } else if page.size == newest {
                    "split: the served head differs at the same size"
                } else if page.size > newest {
                    // The consistency check, read-only: does the served
                    // log contain the pinned prefix?
                    let mut leaves = Vec::new();
                    let mut consistent = false;
                    if (page.leaves.len() as u64) >= newest {
                        for leaf in &page.leaves {
                            if let Ok(bytes) = tang_pqc::b64::decode(leaf)
                                && bytes.len() == 32
                            {
                                let mut h = [0u8; 32];
                                h.copy_from_slice(&bytes);
                                leaves.push(h);
                            }
                        }
                        consistent = usize::try_from(newest)
                            .ok()
                            .and_then(|n| leaves.get(..n))
                            .and_then(|l| kuipa_enroll::merkle::root(l).ok())
                            .is_some_and(|r| r == pinned_root);
                    }
                    if consistent {
                        "stale: the tree grew"
                    } else {
                        "split: the served log does not contain the pinned history"
                    }
                } else {
                    "restarted: the server's tree is shorter"
                };
                json!({
                    "anchor": pin.anchor.to_string(),
                    "state": state,
                    "pinned": json!({"size": newest, "root": tang_pqc::b64::encode(&pinned_root)}),
                    "served": json!({"size": page.size, "root": tang_pqc::b64::encode(&page.root)}),
                    "exp": page.exp,
                })
            }
            Err(e) => json!({
                "anchor": pin.anchor.to_string(),
                "state": format!("no claim log served: {e}"),
            }),
        };
        rows.push(row);
    }
    Ok(json!({ "server": server, "anchors": rows }))
}

/// `kuipa-audit split-view`: the heads each server answers for the
/// realm's anchors, and where they disagree.
///
/// # Errors
///
/// [`Error`] when no server answers.
pub fn split_view(servers: &[String]) -> Result<Value, Error> {
    let mut per_server = Vec::new();
    for server in servers {
        let endpoint = Endpoint::new(server, &Trust::FirstContact)?;
        // The plain advertisement names the realm's anchors; the
        // anchor log answers their current heads.
        let adv = endpoint.advertisement(&[])?;
        let anchors: Vec<String> = adv
            .unverified_member("ipa")?
            .as_ref()
            .and_then(|ipa| ipa.get("anchors"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(|a| a.as_str().map(str::to_string))
            .collect();
        let mut heads = Vec::new();
        for anchor in &anchors {
            if let Ok(a) = anchor.parse::<tang_pqc::Thumbprint>()
                && let Ok(page) = endpoint.claim_log(&a, 0)
            {
                heads.push(json!({
                    "anchor": page.anchor,
                    "size": page.size,
                    "root": tang_pqc::b64::encode(&page.root),
                    "exp": page.exp,
                    "vouch": page.vouch,
                }));
            }
        }
        per_server.push(json!({ "server": server, "anchors": anchors, "heads": heads }));
    }
    // Compare: an anchor named by two servers with different heads.
    let mut disagreements = Vec::new();
    let names: std::collections::BTreeSet<String> = per_server
        .iter()
        .flat_map(|s| s["anchors"].as_array().cloned().unwrap_or_default())
        .filter_map(|a| a.as_str().map(str::to_string))
        .collect();
    for a in names {
        let sides: Vec<Value> = per_server
            .iter()
            .filter_map(|s| {
                let head = s["heads"].as_array()?.iter().find(|h| h["anchor"] == a)?;
                let server = s["server"].as_str()?;
                Some(json!({"server": server, "head": head}))
            })
            .collect::<Vec<_>>();
        let roots: std::collections::BTreeSet<String> = sides
            .iter()
            .filter_map(|s| s["head"]["root"].as_str().map(str::to_string))
            .collect();
        if roots.len() > 1 {
            disagreements.push(json!({ "anchor": a, "sides": sides }));
        }
    }
    Ok(json!({
        "servers": per_server,
        "disagreements": disagreements,
    }))
}

/// Whether a report is clean: a coverage with no split, a split-view
/// with no disagreement.  The binary's exit status follows it.
#[must_use]
pub fn clean(value: &Value) -> bool {
    if let Some(anchors) = value.get("anchors").and_then(Value::as_array) {
        return anchors
            .iter()
            .all(|a| !a["state"].as_str().unwrap_or_default().starts_with("split"));
    }
    if let Some(d) = value.get("disagreements").and_then(Value::as_array) {
        return d.is_empty();
    }
    true
}
