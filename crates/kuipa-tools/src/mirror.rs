//! The mirror's cache and sync: what `kuipa-mirror` fetches from the
//! origin and serves back, byte for byte (DESIGN-claim-logs.md §6).
//!
//! The rules the serving layer must not bypass: a claim-log page is
//! cached only when the advertisement synced in the same round proves
//! its head **by signature** (§4) — pages an origin serves unbacked,
//! forged, or under an anchor the advertisement does not name leave the
//! older cache untouched — and an anchor string that does not parse is
//! skipped with a warning rather than trusted or fatal.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};
use std::time::SystemTime;

use kuipa_enroll::delegation::{Delegation, HeadPin};
use kuipa_enroll::server::ClaimLogPage;
use tang_pqc::{Policy, SignedAdvertisement, Thumbprint, unix_seconds};

use crate::net::Endpoint;

/// Pages fetched per anchor per sync round.  A log longer than
/// `MAX_CLAIM_LOG_PAGE * MAX_PAGES_PER_ANCHOR` leaves is cached in part
/// and reported `unchecked` by the audit.
pub const MAX_PAGES_PER_ANCHOR: usize = 64;
/// Head queries remembered for the next sync; the oldest are dropped
/// past this.
pub const MAX_WANTED: usize = 128;
/// Head-proof answers cached; the oldest are dropped past this.
pub const MAX_HEADS: usize = 64;

/// What the mirror holds: the public bytes it serves, and the queries
/// it has seen (to fetch head answers for at the next sync).
#[derive(Default)]
pub struct Cache {
    /// The plain advertisement, as received.
    advertisement: RwLock<Option<Vec<u8>>>,
    /// Advertisements by their full query string, as received: the
    /// head-proof answers clients ask for by name.
    heads: RwLock<BTreeMap<String, Vec<u8>>>,
    /// Head queries clients asked and no sync has fetched yet.
    wanted: RwLock<BTreeSet<String>>,
    /// The anchor log, as received.
    anchor_log: RwLock<Option<Vec<u8>>>,
    /// Claim-log pages by `(anchor, from)`, as received.
    claim_log: RwLock<BTreeMap<(String, u64), Vec<u8>>>,
}

impl Cache {
    /// The plain advertisement bytes, as received.
    #[must_use]
    pub fn advertisement(&self) -> Option<Vec<u8>> {
        self.advertisement
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    /// A cached head-proof answer for `query`, verbatim.
    #[must_use]
    pub fn head_answer(&self, query: &str) -> Option<Vec<u8>> {
        self.heads
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(query)
            .cloned()
    }
    /// Remember a `head=` query for the next sync, dropping the oldest
    /// past [`MAX_WANTED`].
    pub fn remember_wanted(&self, query: &str) {
        let mut wanted = self.wanted.write().unwrap_or_else(PoisonError::into_inner);
        wanted.insert(query.to_owned());
        while wanted.len() > MAX_WANTED {
            wanted.pop_first();
        }
    }
    /// The anchor log bytes, as received.
    #[must_use]
    pub fn anchor_log(&self) -> Option<Vec<u8>> {
        self.anchor_log
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
    /// One cached claim-log page, verbatim.
    #[must_use]
    pub fn claim_log(&self, anchor: &str, from: u64) -> Option<Vec<u8>> {
        self.claim_log
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(anchor.to_owned(), from))
            .cloned()
    }
    /// Cache a head-proof answer, dropping the oldest past
    /// [`MAX_HEADS`].
    fn put_head(&self, query: String, bytes: Vec<u8>) {
        let mut heads = self.heads.write().unwrap_or_else(PoisonError::into_inner);
        heads.insert(query, bytes);
        while heads.len() > MAX_HEADS {
            heads.pop_first();
        }
    }
    /// Cache one page of `(anchor, from)`, replacing the older page at
    /// the same position when a newer verified one arrives.
    fn put_page(&self, anchor: &str, from: u64, bytes: Vec<u8>) {
        self.claim_log
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((anchor.to_owned(), from), bytes);
    }
    /// The pages cached for `anchor`, in `from` order.
    #[must_use]
    pub fn cached_pages(&self, anchor: &str) -> Vec<(u64, Vec<u8>)> {
        self.claim_log
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|((a, _), _)| a == anchor)
            .map(|((_, from), bytes)| (*from, bytes.clone()))
            .collect()
    }
}

/// The heads the advertisement's delegation proves **by signature**
/// (DESIGN-claim-logs.md §4): a page whose head is not among them is
/// the origin's assertion, not the anchor's, and is not cached.
#[must_use]
pub fn signed_heads(adv_json: &[u8], at: u64) -> Vec<HeadPin> {
    SignedAdvertisement::from_json(adv_json)
        .ok()
        .and_then(|adv| adv.unverified_member("delegation").ok().flatten())
        .and_then(|v| Delegation::from_value(v).ok())
        .map(|d| d.verified_heads(&Policy::default(), at))
        .unwrap_or_default()
}

/// Fetch the origin's public endpoints into the cache.
///
/// # Errors
///
/// A message naming the endpoint that failed.  An unparsable anchor is
/// not an error: it is skipped with a warning, and the realm's own
/// anchors still sync.
pub fn sync(origin: &Endpoint, cache: &Cache) -> Result<(), String> {
    // The plain advertisement, and the anchors it names.
    let adv = origin.advertisement(&[]).map_err(|e| e.to_string())?;
    let bytes = adv.to_json().into_bytes();
    let anchors: Vec<String> = adv
        .unverified_member("ipa")
        .map_err(|e| e.to_string())?
        .as_ref()
        .and_then(|ipa| ipa.get("anchors"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|a| a.as_str().map(str::to_string))
        .collect();
    // The heads this advertisement proves; a page may be cached only
    // under one of them.
    let heads = signed_heads(&bytes, unix_seconds(SystemTime::now()));
    let mut walked = Vec::new();

    // Every anchor's claim log, page by page; the head is the page's,
    // recorded once per anchor.
    for anchor in &anchors {
        match sync_anchor(cache, anchor, &heads, |a, from| {
            origin.claim_log(a, from).map_err(|e| e.to_string())
        }) {
            Ok(Some(head)) => walked.push(head),
            Ok(None) => {}
            Err(e) => return Err(format!("claim log {anchor}: {e}")),
        }
    }

    // The anchor log, with the heads the pages just walked.
    let entries = origin.anchor_log(0).map_err(|e| e.to_string())?;
    let log = serde_json::to_vec(&serde_json::json!({ "entries": entries, "heads": walked }))
        .map_err(|e| e.to_string())?;
    *cache
        .anchor_log
        .write()
        .unwrap_or_else(PoisonError::into_inner) = Some(log);
    // Publish the advertisement *after* its pages: a reader that sees
    // it must also see the claim logs it names, so a round is served
    // whole and never half-synced.
    *cache
        .advertisement
        .write()
        .unwrap_or_else(PoisonError::into_inner) = Some(bytes);

    // The head queries clients asked for: fetch and cache the origin's
    // answers, so the next client with the same query gets the
    // head-proof advertisement.
    let wanted: Vec<String> =
        std::mem::take(&mut *cache.wanted.write().unwrap_or_else(PoisonError::into_inner))
            .into_iter()
            .collect();
    for query in wanted {
        if let Ok(answer) = origin.advertisement_query(query.as_str()) {
            cache.put_head(query, answer);
        }
    }
    Ok(())
}

/// Sync one anchor named by the advertisement.  A string that does not
/// parse is a foreign entry: warn and skip it, so it cannot abort the
/// sync of the realm's own anchors, nor poison the cache.
fn sync_anchor(
    cache: &Cache,
    anchor: &str,
    heads: &[HeadPin],
    fetch: impl Fn(&Thumbprint, u64) -> Result<ClaimLogPage, String>,
) -> Result<Option<serde_json::Value>, String> {
    let Ok(a) = anchor.parse::<Thumbprint>() else {
        eprintln!("kuipa-mirror: sync: skipping unparsable anchor {anchor}");
        return Ok(None);
    };
    walk(cache, anchor, &a, heads, |from| fetch(&a, from))
}

/// Walk one anchor's pages into the cache, at most
/// [`MAX_PAGES_PER_ANCHOR`] per round: past that warn and stop, keeping
/// the older cached pages serving.  A page is cached only when it
/// carries its signed vouch, names this very anchor, and the synced
/// advertisement's delegation signs its head (§6, DESIGN-claim-logs.md
/// §4); a page that does not is refused and the walk of this anchor
/// stops.  `Ok(Some(head))` is the last page's signed head, for the
/// anchor log.
fn walk(
    cache: &Cache,
    anchor: &str,
    a: &Thumbprint,
    heads: &[HeadPin],
    mut fetch: impl FnMut(u64) -> Result<ClaimLogPage, String>,
) -> Result<Option<serde_json::Value>, String> {
    let mut from = 0;
    let mut head = None;
    let mut complete = false;
    for _ in 0..MAX_PAGES_PER_ANCHOR {
        let page = fetch(from)?;
        if page.vouch.is_none() {
            eprintln!("kuipa-mirror: sync: {anchor}: the page head is not signed; not caching");
            return Ok(None);
        }
        if page.anchor != anchor || page.anchor.parse::<Thumbprint>().ok() != Some(*a) {
            eprintln!("kuipa-mirror: sync: {anchor}: a page names another anchor; not caching");
            return Ok(None);
        }
        if !heads
            .iter()
            .any(|h| h.anchor == *a && h.size == page.size && h.root == page.root)
        {
            eprintln!(
                "kuipa-mirror: sync: {anchor}: the page head is not signed by the advertisement; not caching"
            );
            return Ok(None);
        }
        let page_bytes = serde_json::to_vec(&page).map_err(|e| e.to_string())?;
        cache.put_page(anchor, from, page_bytes);
        head = Some(serde_json::json!({
            "anchor": page.anchor,
            "size": page.size,
            "root": tang_pqc::b64::encode(&page.root),
        }));
        if page.leaves.is_empty() {
            complete = true;
            break;
        }
        from += page.leaves.len() as u64;
    }
    if !complete {
        eprintln!(
            "kuipa-mirror: sync: {anchor}: log longer than {MAX_PAGES_PER_ANCHOR} pages this round; stopped, older pages still served"
        );
    }
    Ok(head)
}

/// Keep the cache under `dir`, so a restart starts warm.
///
/// # Errors
///
/// A filesystem error writing any cached object.
pub fn store(cache: &Cache, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    if let Some(bytes) = cache.advertisement() {
        std::fs::write(dir.join("adv"), bytes).map_err(|e| e.to_string())?;
    }
    if let Some(bytes) = cache.anchor_log() {
        std::fs::write(dir.join("anchor-log"), bytes).map_err(|e| e.to_string())?;
    }
    for ((anchor, from), bytes) in cache
        .claim_log
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
    {
        std::fs::write(dir.join(format!("claim-log-{anchor}-{from}")), bytes)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The cache directory: `--data` as the operator gave it, used as-is;
/// otherwise a private `kuipa-mirror-<pid>` under the temporary
/// directory, created with `create_dir` — a squatting symlink or file
/// at that name is refused, not followed — and mode `0700`.
///
/// # Errors
///
/// A message when the default directory cannot be created or made
/// private.
pub fn cache_dir(data: Option<&Path>, pid: u32) -> Result<PathBuf, String> {
    if let Some(dir) = data {
        return Ok(dir.to_owned());
    }
    let dir = std::env::temp_dir().join(format!("kuipa-mirror-{pid}"));
    std::fs::create_dir(&dir).map_err(|e| format!("cache dir {}: {e}", dir.display()))?;
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .map_err(|e| format!("cache dir {}: {e}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::{Cache, MAX_PAGES_PER_ANCHOR, signed_heads, sync_anchor};
    use kuipa_enroll::delegation::{Delegation, HeadPin, SignedVouch};
    use kuipa_enroll::realm::{RealmInfo, ServerKeys};
    use kuipa_enroll::server::{ClaimLogPage, EnrollServer, MAX_CLAIM_LOG_PAGE};
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::time::SystemTime;
    use tang_pqc::{ExchangeKeyPair, KemAlg, SignatureAlg, SigningKey, Thumbprint, unix_seconds};

    /// A one-anchor realm whose claim log is the claim's own leaf.
    fn test_server() -> (EnrollServer, Thumbprint) {
        let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let at = unix_seconds(SystemTime::now());
        let delegation = Delegation::issue(
            &anchor,
            "EXAMPLE.TEST",
            "ipa1.example.test",
            signing.public(),
            at - 60,
            at + 86400,
        )
        .unwrap();
        let thp = *anchor.public().thumbprint();
        let info = RealmInfo {
            realm: "EXAMPLE.TEST".into(),
            domain: "example.test".into(),
            basedn: "dc=example,dc=test".into(),
            server: "ipa1.example.test".into(),
            servers: vec!["ipa1.example.test".into()],
            ca_certs: vec![b"not really a certificate".to_vec()],
            pkinit_anchors: vec![b"pkinit anchor".to_vec()],
            anchors: vec![thp],
            heads: Vec::new(),
            trusts: Vec::new(),
        };
        let keys = ServerKeys {
            signing,
            join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            trust: Vec::new(),
            vouchers: Vec::new(),
            retired: Vec::new(),
        };
        let server = EnrollServer::new(keys, info, delegation.clone());
        let leaf = delegation.claim().unwrap().leaf().unwrap();
        let mut vouches = HashMap::new();
        vouches.insert(
            thp,
            SignedVouch::issue(&anchor, "EXAMPLE.TEST", [leaf], at - 60, at + 3600, None).unwrap(),
        );
        server.publish(delegation, vec![thp], vouches);
        (server, thp)
    }

    fn page(
        anchor: &str,
        size: u64,
        root: [u8; 32],
        leaves: usize,
        vouch: Option<String>,
    ) -> ClaimLogPage {
        ClaimLogPage {
            anchor: anchor.to_owned(),
            size,
            root,
            exp: unix_seconds(SystemTime::now()) + 3600,
            leaves: (0..leaves)
                .map(|i| tang_pqc::b64::encode(&[u8::try_from(i).unwrap_or(255); 32]))
                .collect(),
            vouch,
        }
    }

    #[test]
    fn wanted_and_head_caches_drop_the_oldest() {
        let cache = Cache::default();
        for i in 0..200 {
            cache.remember_wanted(&format!("head=a.{i}.r"));
        }
        let wanted = cache
            .wanted
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(wanted.len(), super::MAX_WANTED);
        assert!(
            !wanted.contains("head=a.0.r"),
            "wanted keeps the newest queries"
        );
        assert!(wanted.contains("head=a.199.r"));
        for i in 0..100 {
            cache.put_head(format!("q{i}"), vec![u8::try_from(i).unwrap_or(255)]);
        }
        let heads = cache
            .heads
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        assert_eq!(heads, super::MAX_HEADS);
        assert!(cache.head_answer("q0").is_none());
        assert!(cache.head_answer("q99").is_some());
    }

    #[test]
    fn the_page_loop_stops_at_the_cap() {
        let cache = Cache::default();
        let a = Thumbprint::from_bytes([1u8; 32]);
        let anchor = a.to_string();
        let root = [9u8; 32];
        let heads = vec![HeadPin {
            anchor: a,
            size: 400_000,
            root,
        }];
        let fetch = |_from: u64| {
            Ok(page(
                &anchor,
                400_000,
                root,
                MAX_CLAIM_LOG_PAGE,
                Some("v".into()),
            ))
        };
        let head = super::walk(&cache, &anchor, &a, &heads, fetch).unwrap();
        assert!(head.is_some(), "the signed head is still the log's head");
        let pages = cache.cached_pages(&anchor);
        assert_eq!(pages.len(), MAX_PAGES_PER_ANCHOR);
        assert_eq!(
            pages.last().map(|(from, _)| *from),
            Some((MAX_PAGES_PER_ANCHOR - 1) as u64 * MAX_CLAIM_LOG_PAGE as u64)
        );
    }

    #[test]
    fn a_complete_walk_caches_every_page() {
        let cache = Cache::default();
        let a = Thumbprint::from_bytes([2u8; 32]);
        let anchor = a.to_string();
        let root = [8u8; 32];
        let heads = vec![HeadPin {
            anchor: a,
            size: 4096,
            root,
        }];
        let fetch = |from: u64| {
            Ok(if from == 0 {
                page(&anchor, 4096, root, 4096, Some("v".into()))
            } else {
                page(&anchor, 4096, root, 0, Some("v".into()))
            })
        };
        assert!(
            super::walk(&cache, &anchor, &a, &heads, fetch)
                .unwrap()
                .is_some()
        );
        assert_eq!(cache.cached_pages(&anchor).len(), 2);
    }

    #[test]
    fn the_page_check_rejects_unsigned_and_forged_pages() {
        let (server, thp) = test_server();
        let adv = server.advertisement(&[]).unwrap().to_json().into_bytes();
        let heads = signed_heads(&adv, unix_seconds(SystemTime::now()));
        assert!(
            heads.iter().any(|h| h.anchor == thp),
            "the advertisement proves its anchor's head"
        );
        let genuine = server.claim_log(&thp, 0).unwrap();
        let anchor = thp.to_string();

        // A genuine page caches.
        let cache = Cache::default();
        let done = |from: u64| {
            Ok(if from == 0 {
                genuine.clone()
            } else {
                ClaimLogPage {
                    leaves: Vec::new(),
                    ..genuine.clone()
                }
            })
        };
        super::walk(&cache, &anchor, &thp, &heads, done)
            .unwrap()
            .unwrap();
        assert_eq!(cache.cached_pages(&anchor).len(), 2);

        // The same page with a tampered root: the advertisement does
        // not sign that head.
        let forged = ClaimLogPage {
            root: [0xa5; 32],
            ..genuine.clone()
        };
        let cache = Cache::default();
        assert!(
            super::walk(&cache, &anchor, &thp, &heads, |_| Ok(forged.clone()))
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.cached_pages(&anchor), Vec::new());

        // A page whose head is not signed at all.
        let unsigned = ClaimLogPage {
            vouch: None,
            ..genuine.clone()
        };
        let cache = Cache::default();
        assert!(
            super::walk(&cache, &anchor, &thp, &heads, |_| Ok(unsigned.clone()))
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.cached_pages(&anchor), Vec::new());

        // A page naming another anchor, served under this name.
        let other = Thumbprint::from_bytes([3u8; 32]);
        let foreign = ClaimLogPage {
            anchor: other.to_string(),
            ..genuine.clone()
        };
        let cache = Cache::default();
        assert!(
            super::walk(&cache, &anchor, &thp, &heads, |_| Ok(foreign.clone()))
                .unwrap()
                .is_none(),
            "a page that names another anchor is refused"
        );
        assert_eq!(cache.cached_pages(&anchor), Vec::new());
    }

    #[test]
    fn an_unparsable_anchor_is_skipped_and_the_others_sync() {
        let (server, thp) = test_server();
        let adv = server.advertisement(&[]).unwrap().to_json().into_bytes();
        let heads = signed_heads(&adv, unix_seconds(SystemTime::now()));
        let cache = Cache::default();
        let fetch = |a: &Thumbprint, from: u64| {
            server
                .claim_log(a, from)
                .ok_or_else(|| "the origin has no such anchor".to_owned())
        };
        assert!(
            sync_anchor(&cache, "not-a-thumbprint", &heads, fetch)
                .unwrap()
                .is_none(),
            "the foreign string is skipped, not fatal"
        );
        assert!(
            sync_anchor(&cache, &thp.to_string(), &heads, fetch)
                .unwrap()
                .is_some()
        );
        assert!(cache.claim_log(&thp.to_string(), 0).is_some());
        assert_eq!(cache.cached_pages("not-a-thumbprint"), Vec::new());
    }

    #[test]
    fn the_default_cache_dir_is_private_and_a_squat_is_refused() {
        let dir = super::cache_dir(None, 991_237).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // A second default at a taken name (a symlink or file squat) is
        // refused, not followed.
        assert!(super::cache_dir(None, 991_237).is_err());
        std::fs::remove_dir(&dir).unwrap();
        let squat = std::env::temp_dir().join("kuipa-mirror-991238");
        std::fs::write(&squat, b"squat").unwrap();
        assert!(super::cache_dir(None, 991_238).is_err());
        std::fs::remove_file(&squat).unwrap();
        let given = std::env::temp_dir().join("kuipa-mirror-operator");
        assert_eq!(super::cache_dir(Some(&given), 991_237).unwrap(), given);
        std::fs::remove_dir_all(&given).ok();
    }
}
