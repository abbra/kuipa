//! `kuipa-audit`: read-only reports on a realm's claim logs
//! (DESIGN-claim-logs.md §5).
//!
//! The tool fetches only public endpoints — the advertisement, the
//! anchor log and the claim-log pages — and checks what it fetches
//! against heads (pinned or given): it is `curl` plus the tree math.
//! It holds no keys, writes nothing, and authenticates nothing a
//! public reader could not.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use serde_json::{Value, json};

use kuipa_enroll::delegation::Delegation;
use kuipa_enroll::merkle;
use kuipa_enroll::realm::VerifiedRealm;
use kuipa_enroll::server::{ClaimLogPage, MAX_CLAIM_LOG_PAGE};
use tang_pqc::Policy;

use crate::net::{Endpoint, Trust};
use crate::paths::Error;
use crate::paths::{self, Paths};

/// Pages one coverage row walks per anchor: past that the log is
/// reported `unchecked`, not "split" — the auditor cannot see the
/// pinned prefix, and must say so rather than guess.
const MAX_AUDIT_PAGES: usize = 64;

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
/// is shorter or not backed by the anchor's signature (split: claim
/// logs only grow), or is longer than the walk can see (unchecked).
///
/// Each anchor is asked for its own advertisement and verified against
/// its own pin: only heads the delegation proves **by signature**
/// ([`VerifiedRealm::proved_heads`]) are accepted as served — a page
/// head among them is the anchor's, anywhere else it is the server's
/// assertion (§4.9.6, DESIGN-claim-logs.md §4).
///
/// # Errors
///
/// [`Error`] when no server answers.
pub fn coverage(
    server: &str,
    given: &[(tang_pqc::Thumbprint, u64, merkle::Hash)],
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
                retired: Vec::new(),
            })
            .collect()
    };
    let now = SystemTime::now();
    let cap = MAX_AUDIT_PAGES * MAX_CLAIM_LOG_PAGE;
    let mut rows = Vec::new();
    for pin in &pins {
        let Some((newest, pinned_root)) = pin.heads.last().copied() else {
            rows.push(json!({
                "anchor": pin.anchor.to_string(),
                "state": "no head pinned",
            }));
            continue;
        };
        rows.push(row_for(
            &endpoint,
            pin.anchor,
            newest,
            pinned_root,
            now,
            cap,
        ));
    }
    Ok(json!({ "server": server, "anchors": rows }))
}

/// One anchor's coverage row.  A failure to fetch, or a served head the
/// pinned anchor never signed, is a `split` row: an unaudited head is
/// not a clean report.
fn row_for(
    endpoint: &Endpoint,
    anchor: tang_pqc::Thumbprint,
    newest: u64,
    pinned_root: merkle::Hash,
    now: SystemTime,
    cap: usize,
) -> Value {
    let pinned = json!({"size": newest, "root": tang_pqc::b64::encode(&pinned_root)});
    let split = |why: String| {
        json!({
            "anchor": anchor.to_string(),
            "state": format!("split: {why}"),
        })
    };
    let adv = match endpoint.advertisement(std::slice::from_ref(&anchor)) {
        Ok(adv) => adv,
        Err(e) => return split(format!("no advertisement served: {e}")),
    };
    // The realm is the one the pinned anchor signs; `verify` then binds
    // the unsigned realm metadata to that claim.  Only this anchor is
    // trusted, and only for this row.
    let verified = adv
        .unverified_member("delegation")
        .ok()
        .flatten()
        .and_then(|v| Delegation::from_value(v).ok())
        .and_then(|d| d.claim().ok())
        .and_then(|claim| {
            VerifiedRealm::verify(
                &adv,
                &claim.realm,
                &[anchor],
                &Policy::from_system().ok()?,
                now,
            )
            .ok()
        });
    let Some(verified) = verified else {
        return split("the advertisement does not verify against the pinned anchor".into());
    };
    let page = match endpoint.claim_log(&anchor, 0) {
        Ok(page) => page,
        Err(e) => return split(format!("no claim log served: {e}")),
    };
    let served = json!({"size": page.size, "root": tang_pqc::b64::encode(&page.root)});
    let row = |state: String| {
        json!({
            "anchor": anchor.to_string(),
            "state": state,
            "pinned": pinned,
            "served": served,
            "exp": page.exp,
        })
    };
    if !verified
        .proved_heads()
        .iter()
        .any(|h| h.anchor == anchor && h.size == page.size && *h.root == *page.root)
    {
        return row("split: the served head is not signed by the anchor".into());
    }
    if page.size < newest {
        // Claim logs only grow (DESIGN-tlog.md §8): a shorter tree is a
        // log that does not contain the pinned history.
        return row("split: the server's tree is shorter than the pinned head".into());
    }
    if page.size == newest {
        return row(if *page.root == *pinned_root {
            "current".into()
        } else {
            "split: the served head differs at the same size".into()
        });
    }
    // The tree grew past the pin.  The consistency check is read-only,
    // over **every** fetched leaf up to the pinned size: a log longer
    // than one page cannot be checked against page 0 alone.
    if newest > cap as u64 {
        return json!({
            "anchor": anchor.to_string(),
            "state": format!("unchecked: log larger than {cap} leaves"),
            "pinned": pinned,
            "served": served,
            "exp": page.exp,
        });
    }
    let mut leaves = page_leaves(&page);
    let mut from = page.leaves.len() as u64;
    let mut pages = 1;
    while (leaves.len() as u64) < newest && pages < MAX_AUDIT_PAGES {
        let next = match endpoint.claim_log(&anchor, from) {
            Ok(next) => next,
            Err(e) => return row(format!("split: the claim log walk failed: {e}")),
        };
        if next.leaves.is_empty() {
            break; // the server serves less than its own head claims
        }
        leaves.extend(page_leaves(&next));
        from += next.leaves.len() as u64;
        pages += 1;
    }
    let consistent = usize::try_from(newest)
        .ok()
        .and_then(|n| leaves.get(..n))
        .and_then(|l| merkle::root(l).ok())
        .is_some_and(|r| r == pinned_root);
    row(if consistent {
        "stale: the tree grew".into()
    } else {
        "split: the served log does not contain the pinned history".into()
    })
}

/// The page's leaves as hashes; entries that are not hashes of the
/// head's algorithm are skipped, so malformed entries cannot fake a
/// prefix.
fn page_leaves(page: &ClaimLogPage) -> Vec<merkle::Hash> {
    page.leaves
        .iter()
        .filter_map(|leaf| {
            let bytes = tang_pqc::b64::decode(leaf).ok()?;
            merkle::Hash::from_slice(&bytes)
                .ok()
                .filter(|h| h.len() == page.root.len())
        })
        .collect()
}

/// One server's side of the split view.
struct ServerView {
    server: String,
    anchors: Vec<String>,
    heads: Vec<Value>,
    /// Why the advertisement was refused; its anchors are then not
    /// trusted at all.
    error: Option<String>,
}

/// `kuipa-audit split-view`: the heads each server answers for the
/// realm's anchors, and where they disagree.
///
/// Each advertisement is checked for self-consistency first — its
/// signature must verify against the key its own delegation's claim
/// names — so a relay cannot edit an answer in flight.  The auditor
/// trusts no key: this proves nothing about the server, only that the
/// bytes arrived as signed.
///
/// # Errors
///
/// [`Error`] when no server answers.
pub fn split_view(servers: &[String]) -> Result<Value, Error> {
    let now = SystemTime::now();
    let mut views = Vec::new();
    for server in servers {
        let endpoint = Endpoint::new(server, &Trust::FirstContact)?;
        // The plain advertisement names the realm's anchors; the
        // anchor log answers their current heads.
        let adv = endpoint.advertisement(&[])?;
        if let Err(why) = self_consistent(&adv, now) {
            views.push(ServerView {
                server: server.clone(),
                anchors: Vec::new(),
                heads: Vec::new(),
                error: Some(why),
            });
            continue;
        }
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
        views.push(ServerView {
            server: server.clone(),
            anchors,
            heads,
            error: None,
        });
    }
    let servers: Vec<Value> = views
        .iter()
        .map(|v| {
            let mut row = json!({ "server": v.server, "anchors": v.anchors, "heads": v.heads });
            if let Some(error) = &v.error {
                row["error"] = json!(error);
            }
            row
        })
        .collect();
    Ok(json!({
        "servers": servers,
        "disagreements": disagreements(&views),
        "inconsistent": views
            .iter()
            .filter_map(|v| v.error.as_ref().map(|e| json!({"server": v.server, "error": e})))
            .collect::<Vec<Value>>(),
    }))
}

/// The advertisement's own signature, against the key its delegation's
/// claim names: an advertisement edited in flight fails here, and its
/// anchor list is not trusted.  Nothing is pinned — the auditor trusts
/// no key.
///
/// # Errors
///
/// A message naming what failed to parse or verify.
fn self_consistent(adv: &tang_pqc::SignedAdvertisement, now: SystemTime) -> Result<(), String> {
    let delegation = Delegation::from_value(
        adv.unverified_member("delegation")
            .map_err(|e| e.to_string())?
            .ok_or("no delegation member".to_owned())?,
    )
    .map_err(|e| e.to_string())?;
    let claim = delegation.claim().map_err(|e| e.to_string())?;
    adv.verify_at(
        &claim.key,
        &Policy::from_system().map_err(|e| e.to_string())?,
        now,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Where the views disagree: an anchor served at different roots, an
/// anchor **named** by at least two servers where one of them serves
/// no claim-log head for it (a server that names an anchor it does not
/// answer is holding a split view back), and an anchor string no
/// server can parse — recorded, not dropped.
fn disagreements(views: &[ServerView]) -> Vec<Value> {
    let mut out = Vec::new();
    let named: BTreeMap<&String, Vec<&String>> =
        views.iter().fold(BTreeMap::new(), |mut acc, v| {
            for a in &v.anchors {
                acc.entry(a).or_default().push(&v.server);
            }
            acc
        });
    for (anchor, servers) in named {
        if anchor.parse::<tang_pqc::Thumbprint>().is_err() {
            out.push(json!({ "anchor": anchor, "malformed": servers }));
            continue;
        }
        let sides: Vec<Value> = views
            .iter()
            .filter_map(|v| {
                let head = v.heads.iter().find(|h| h["anchor"] == *anchor)?;
                Some(json!({"server": v.server, "head": head}))
            })
            .collect();
        let roots: BTreeSet<String> = sides
            .iter()
            .filter_map(|s| s["head"]["root"].as_str().map(str::to_string))
            .collect();
        if roots.len() > 1 {
            out.push(json!({ "anchor": anchor, "sides": sides.clone() }));
        }
        let missing: Vec<&String> = servers
            .iter()
            .filter(|s| !sides.iter().any(|side| side["server"] == ***s))
            .copied()
            .collect();
        if servers.len() >= 2 && !missing.is_empty() {
            out.push(json!({ "anchor": anchor, "sides": sides, "missing": missing }));
        }
    }
    out
}

/// Whether a report is clean: a coverage whose every anchor row reads
/// `current` or `stale` — a split (a shorter or unsigned tree), an
/// `unchecked` log, a missing claim log and an unpinned head are all not clean —
/// and a split-view with no disagreement, no malformed anchor, and no
/// server whose advertisement failed self-consistency.  The binary's
/// exit status follows it.
#[must_use]
pub fn clean(value: &Value) -> bool {
    if let Some(anchors) = value.get("anchors").and_then(Value::as_array) {
        return anchors.iter().all(|a| {
            let state = a["state"].as_str().unwrap_or_default();
            state.starts_with("current") || state.starts_with("stale")
        });
    }
    if let Some(d) = value.get("disagreements").and_then(Value::as_array) {
        let inconsistent = value
            .get("inconsistent")
            .and_then(Value::as_array)
            .is_some_and(|v| !v.is_empty());
        return d.is_empty() && !inconsistent;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{ServerView, clean, disagreements};
    use serde_json::{Value, json};

    fn anchor() -> String {
        tang_pqc::Thumbprint::from_bytes([7u8; 32]).to_string()
    }

    fn head(anchor: &str, size: u64, root: &str) -> Value {
        json!({"anchor": anchor, "size": size, "root": root, "exp": 0, "vouch": null})
    }

    fn view(server: &str, anchors: &[&str], heads: &[Value]) -> ServerView {
        ServerView {
            server: server.to_owned(),
            anchors: anchors.iter().map(|a| (*a).to_owned()).collect(),
            heads: heads.to_vec(),
            error: None,
        }
    }

    #[test]
    fn coverage_is_clean_only_when_every_row_was_checked() {
        let row = |state: &str| json!({"anchor": "thp", "state": state});
        assert!(clean(
            &json!({"server": "s", "anchors": [row("current"), row("stale: the tree grew")]})
        ));
        for state in [
            "split: the served head is not signed by the anchor",
            "unchecked: log larger than 262144 leaves",
            "split: the server's tree is shorter than the pinned head",
            "no claim log served: HTTP 404",
            "no head pinned",
        ] {
            assert!(
                !clean(&json!({"server": "s", "anchors": [row("current"), row(state)]})),
                "{state} must not read clean"
            );
        }
    }

    #[test]
    fn split_view_needs_no_disagreement_and_no_untrusted_server() {
        assert!(clean(
            &json!({"servers": [], "disagreements": [], "inconsistent": []})
        ));
        assert!(!clean(
            &json!({"servers": [], "disagreements": [{"anchor": "a"}], "inconsistent": []})
        ));
        assert!(
            !clean(
                &json!({"servers": [], "disagreements": [], "inconsistent": [{"server": "s", "error": "tampered"}]})
            ),
            "a refused advertisement must not read clean"
        );
    }

    #[test]
    fn same_heads_agree() {
        let a = anchor();
        let views = vec![
            view("s1", &[&a], &[head(&a, 5, "R")]),
            view("s2", &[&a], &[head(&a, 5, "R")]),
        ];
        assert_eq!(disagreements(&views), Vec::<Value>::new());
    }

    #[test]
    fn different_roots_disagree() {
        let a = anchor();
        let views = vec![
            view("s1", &[&a], &[head(&a, 5, "R")]),
            view("s2", &[&a], &[head(&a, 6, "S")]),
        ];
        let d = disagreements(&views);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0]["anchor"], a);
        assert_eq!(d[0]["sides"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn an_anchor_named_but_not_answered_disagrees() {
        let a = anchor();
        let views = vec![
            view("s1", &[&a], &[head(&a, 5, "R")]),
            view("s2", &[&a], &[]),
        ];
        let d = disagreements(&views);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0]["missing"].as_array().map(Vec::len), Some(1));
        assert_eq!(d[0]["missing"][0], "s2");
    }

    #[test]
    fn one_server_naming_without_a_head_is_not_a_disagreement() {
        let a = anchor();
        let views = vec![view("s1", &[&a], &[])];
        assert_eq!(disagreements(&views), Vec::<Value>::new());
    }

    #[test]
    fn malformed_anchor_strings_are_recorded() {
        let views = vec![view("s1", &["not-a-thumbprint"], &[])];
        let d = disagreements(&views);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0]["anchor"], "not-a-thumbprint");
        assert_eq!(d[0]["malformed"].as_array().map(Vec::len), Some(1));
        assert_eq!(d[0]["malformed"][0], "s1");
    }
}

/// What `kuipa-audit tlog --state` keeps of one server's log between
/// runs: the size and root it last verified.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Audited {
    log: String,
    size: u64,
    root: String,
}

/// Leaves one `kuipa-audit tlog` run reads at most: past that the log is
/// reported `unchecked` rather than guessed at.
const MAX_TLOG_LEAVES: u64 = 1 << 20;

/// `kuipa-audit tlog`: one server's whole transparency log, checked
/// from its public routes (DESIGN-tlog.md §5).
///
/// The server's advertisement is verified against `anchors` (the
/// host's pinned anchors when none are given), which names the server's
/// signing key; the served head must carry that key's signature.  Every
/// leaf is then fetched and the log replayed — tombstone rules included
/// — and its root must be the head's.  With `state`, the root the last
/// run verified must be the root of the same prefix now (the log only
/// grew), and the new head is recorded.
///
/// `witnesses` are the cosigners the report counts: `witnesses` lists
/// those of them whose cosignatures on the served head verify.
///
/// The report's `state` is `verified`, `empty`, `forked: …` (the head
/// is not the replayed log's, or does not extend what was recorded),
/// or `unchecked: …` (the log is larger than one run reads).
///
/// # Errors
///
/// [`Error`] when the server cannot be reached, its advertisement does
/// not verify, or the state file cannot be read or written.
pub fn tlog(
    server: &str,
    anchors: &[tang_pqc::Thumbprint],
    witnesses: &[tang_pqc::VerifyingKey],
    state: Option<&std::path::Path>,
) -> Result<Value, Error> {
    let endpoint = Endpoint::new(server, &Trust::FirstContact)?;
    let policy = Policy::from_system()?;
    let (log, key) = advertised_log(&endpoint, anchors, &policy)?;
    let report = |state: String, extra: Value| {
        let mut v = json!({ "server": server, "log": log.to_string(), "state": state });
        if let (Some(v), Some(extra)) = (v.as_object_mut(), extra.as_object()) {
            v.extend(extra.clone());
        }
        v
    };
    let Some(signed) = endpoint.tlog_head(&log)? else {
        return Ok(report("empty".into(), json!({})));
    };
    if signed.verify(&key, &policy).is_err() {
        return Ok(report(
            "forked: the head is not signed by the advertised key".into(),
            json!({}),
        ));
    }
    let head = signed.head;
    let cosigned: Vec<String> = signed
        .witnesses(witnesses, &policy)
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut summary = json!({
        "size": head.size,
        "root": tang_pqc::b64::encode(&head.root),
        "time": head.time,
        "witnesses": cosigned,
    });
    if head.size > MAX_TLOG_LEAVES {
        return Ok(report(
            format!("unchecked: {} leaves, more than one run reads", head.size),
            summary,
        ));
    }
    let (leaves, replayed) = match replay_served(&endpoint, &head)? {
        Ok(replay) => replay,
        Err(why) => return Ok(report(format!("forked: {why}"), summary)),
    };
    summary["kinds"] = json!(kind_counts(&leaves));
    if let Some(path) = state
        && let Some(why) = check_recorded(path, &head, &replayed, &mut summary)?
    {
        return Ok(report(format!("forked: {why}"), summary));
    }
    Ok(report("verified".into(), summary))
}

/// The log of the server whose advertisement verifies against `anchors`
/// (the host's pinned ones when none are given), and its signing key.
pub(crate) fn advertised_log(
    endpoint: &Endpoint,
    anchors: &[tang_pqc::Thumbprint],
    policy: &Policy,
) -> Result<(kuipa_enroll::tlog::LogId, tang_pqc::VerifyingKey), Error> {
    let anchors = if anchors.is_empty() {
        paths::read_anchors(&Paths::from_env())
            .map_err(|e| format!("no anchors given and none pinned on this host (--anchor): {e}"))?
    } else {
        anchors.to_vec()
    };
    let adv = endpoint.advertisement(&anchors)?;
    let realm = adv
        .unverified_member("delegation")?
        .and_then(|v| Delegation::from_value(v).ok())
        .and_then(|d| d.claim().ok())
        .ok_or("the advertisement carries no delegation")?
        .realm;
    let verified = VerifiedRealm::verify(&adv, &realm, &anchors, policy, SystemTime::now())?;
    let key = verified
        .signing_key()
        .ok_or("the advertisement carries no signing key")?
        .clone();
    // The log is hashed as the server's signing key decides.
    let alg = merkle::TreeHash::for_signer(key.alg());
    Ok((
        kuipa_enroll::tlog::LogId::of(&realm, verified.server(), alg)?,
        key,
    ))
}

/// Every leaf up to `head`, and the log they replay to; or why they do
/// not make the head's log.
fn replay_served(
    endpoint: &Endpoint,
    head: &kuipa_enroll::tlog::Head,
) -> Result<Result<(Vec<kuipa_enroll::tlog::Leaf>, kuipa_enroll::tlog::Log), String>, Error> {
    let mut leaves = Vec::new();
    while (leaves.len() as u64) < head.size {
        let page = endpoint.tlog_leaves(&head.log, leaves.len() as u64)?;
        if page.is_empty() {
            break;
        }
        leaves.extend(page);
    }
    leaves.truncate(usize::try_from(head.size)?);
    if (leaves.len() as u64) < head.size {
        return Ok(Err(format!(
            "the head names {} leaves, the log serves {}",
            head.size,
            leaves.len()
        )));
    }
    let replayed = match kuipa_enroll::tlog::Log::replay(head.log, &leaves) {
        Ok(l) => l,
        Err(e) => return Ok(Err(format!("the leaves break the log's rules: {e}"))),
    };
    if replayed.root()? != head.root {
        return Ok(Err("the head is not the root of the leaves served".into()));
    }
    Ok(Ok((leaves, replayed)))
}

/// How many leaves of each kind, by name.
fn kind_counts(leaves: &[kuipa_enroll::tlog::Leaf]) -> BTreeMap<String, u64> {
    use kuipa_enroll::tlog::Kind;

    let mut kinds = BTreeMap::new();
    for l in leaves {
        let name = match l.kind {
            Kind::CLAIM => "claim".into(),
            Kind::SEAL_DEVICE => "seal-device".into(),
            Kind::SEAL_POLICY => "seal-policy".into(),
            Kind::ESCROW_RELEASE => "escrow-release".into(),
            Kind::STATEMENT => "statement".into(),
            Kind::KEYS_FETCH => "keys-fetch".into(),
            Kind::TOKEN_KEY => "token-key".into(),
            Kind::TOMBSTONE => "tombstone".into(),
            Kind(other) => format!("kind {other}"),
        };
        *kinds.entry(name).or_default() += 1;
    }
    kinds
}

/// With a state file: the recorded root must be the root of the same
/// prefix of `replayed` (the log only grew); then `head` is recorded.
/// Returns why not, leaving the file as it was, or none.
fn check_recorded(
    path: &std::path::Path,
    head: &kuipa_enroll::tlog::Head,
    replayed: &kuipa_enroll::tlog::Log,
    summary: &mut Value,
) -> Result<Option<String>, Error> {
    let mut audited: BTreeMap<String, Audited> = match std::fs::read(path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
        Err(e) => return Err(e.into()),
    };
    let id = head.log.to_string();
    if let Some(before) = audited.get(&id) {
        let old: Option<merkle::Hash> = tang_pqc::b64::decode(&before.root)
            .ok()
            .and_then(|r| merkle::Hash::from_slice(&r).ok());
        let prefix = usize::try_from(before.size)
            .ok()
            .filter(|s| *s > 0 && *s <= replayed.hashes().len());
        let extends = match (old, prefix) {
            (Some(old), Some(n)) => merkle::root(&replayed.hashes()[..n])? == old,
            _ => false,
        };
        summary["previous"] = json!({ "size": before.size, "root": before.root });
        if !extends {
            return Ok(Some(format!(
                "the log does not extend the {} leaves recorded",
                before.size
            )));
        }
    }
    audited.insert(
        id.clone(),
        Audited {
            log: id,
            size: head.size,
            root: tang_pqc::b64::encode(&head.root),
        },
    );
    paths::write_file(path, &serde_json::to_vec_pretty(&audited)?, 0o644)?;
    Ok(None)
}
