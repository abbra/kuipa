//! `kuipa-mirror`: a keyless, read-only proof replica
//! (DESIGN-claim-logs.md §6).
//!
//! ```text
//! kuipa-mirror --origin URL --listen ADDR [--data DIR] [--interval SECS]
//! ```
//!
//! Every `--interval` seconds (and once at start) it fetches the
//! origin's **public** endpoints — the plain advertisement, the anchor
//! log and every anchor's claim-log pages — and stores them under
//! `--data`.  It then answers, read-only:
//!
//! * `/ipa/ku/adv` — the cached advertisement bytes as received: a
//!   cached advertisement is valid until its own expiry.  A query
//!   with `head=` parameters is answered with the origin's answer for
//!   that same query, cached when a sync has seen it; an unseen one
//!   falls back to the cached plain advertisement, which the client
//!   verifies through signatures — the same silent fallback a server
//!   gives a stale head (§4.9.2).
//! * `/ipa/ku/anchor-log` and `/ipa/ku/claim-log/{anchor}` — the
//!   cached pages.
//!
//! Join, rekey and every authenticated route are absent: a mirror is
//! not a server, and a client that tries to join through one is
//! refused by the missing route.  When the origin is unreachable past
//! a vouch's expiry, the mirror's head proofs stop verifying for new
//! verifications — the clients' own clocks decide, and the mirror
//! cannot lie about it: it serves the signed bytes as received.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::response::IntoResponse;
use clap::Parser;
use kuipa_tools::net::{Endpoint, Trust};

/// What the mirror holds: the public bytes it serves, and the queries
/// it has seen (to fetch head answers for at the next sync).
#[derive(Default)]
struct Cache {
    /// The plain advertisement, as received.
    advertisement: RwLock<Option<Vec<u8>>>,
    /// Advertisements by their full query string, as received: the
    /// head-proof answers clients ask for by name.
    heads: RwLock<std::collections::BTreeMap<String, Vec<u8>>>,
    /// Head queries clients asked and no sync has fetched yet.
    wanted: RwLock<std::collections::BTreeSet<String>>,
    /// The anchor log, as received.
    anchor_log: RwLock<Option<Vec<u8>>>,
    /// Claim-log pages by `(anchor, from)`, as received.
    claim_log: RwLock<std::collections::BTreeMap<(String, u64), Vec<u8>>>,
}

#[derive(Parser)]
#[command(
    name = "kuipa-mirror",
    about = "A keyless, read-only replica of a realm's public proof endpoints.",
    after_help = "The mirror fetches only public endpoints from --origin and serves what it \
cached: advertisements (including head-proof answers), the anchor log and claim-log pages. \
It holds no keys and answers no authenticated route.  When the origin is unreachable past a \
vouch's expiry, its head proofs stop verifying for new verifications."
)]
struct Cli {
    /// The origin's base URL (its `/ipa/ku/`), or `unix:/path`.
    #[arg(long)]
    origin: String,
    /// The address to listen on.
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: String,
    /// Where to keep the cache (default: a kuipa-mirror/ under the
    /// system temporary directory).
    #[arg(long)]
    data: Option<PathBuf>,
    /// Seconds between syncs (default 60).
    #[arg(long, default_value = "60")]
    interval: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = cli.data.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("kuipa-mirror-{}", std::process::id()))
    });
    let cache = Arc::new(Cache::default());
    if let Err(e) = run(&cli, &dir, Arc::clone(&cache)) {
        eprintln!("kuipa-mirror: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run(cli: &Cli, dir: &Path, cache: Arc<Cache>) -> Result<(), String> {
    // Fail fast when the origin is unusable, before binding.
    drop(Endpoint::new(&cli.origin, &Trust::FirstContact).map_err(|e| e.to_string())?);
    {
        let origin = Endpoint::new(&cli.origin, &Trust::FirstContact).map_err(|e| e.to_string())?;
        let cache = Arc::clone(&cache);
        let dir = dir.to_owned();
        let interval = cli.interval;
        std::thread::spawn(move || {
            loop {
                if let Err(e) = sync(&origin, &cache) {
                    eprintln!("kuipa-mirror: sync: {e}");
                } else if let Err(e) = store(&cache, &dir) {
                    eprintln!("kuipa-mirror: store: {e}");
                }
                std::thread::sleep(Duration::from_secs(interval.max(1)));
            }
        });
    }

    let app = axum::Router::new()
        .route("/ipa/ku/adv", axum::routing::get(adv))
        .route("/ipa/ku/anchor-log", axum::routing::get(anchor_log))
        .route("/ipa/ku/claim-log/{anchor}", axum::routing::get(claim_log))
        .with_state(cache);
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(&cli.listen)
            .await
            .map_err(|e| format!("listen {}: {e}", cli.listen))?;
        eprintln!("kuipa-mirror: serving {} on {}", cli.origin, cli.listen);
        axum::serve(listener, app).await.map_err(|e| e.to_string())
    })
}

/// Fetch the origin's public endpoints into the cache.
fn sync(origin: &Endpoint, cache: &Cache) -> Result<(), String> {
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
    *cache
        .advertisement
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bytes);
    let mut heads = Vec::new();

    // Every anchor's claim log, page by page; the head is the page's,
    // recorded once per anchor.
    for anchor in &anchors {
        let a: tang_pqc::Thumbprint = anchor.parse().map_err(|_| format!("bad anchor {anchor}"))?;
        let mut from = 0;
        // Assigned on every round; the last one is kept.
        let mut head;
        loop {
            let page = origin.claim_log(&a, from).map_err(|e| e.to_string())?;
            let n = page.leaves.len();
            let page_bytes = serde_json::to_vec(&page).map_err(|e| e.to_string())?;
            cache
                .claim_log
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert((anchor.clone(), from), page_bytes);
            head = Some(serde_json::json!({
                "anchor": page.anchor,
                "size": page.size,
                "root": tang_pqc::b64::encode(&page.root),
            }));
            if n == 0 {
                break;
            }
            from += n as u64;
        }
        heads.extend(head);
    }

    // The anchor log, with the heads the pages just walked.
    let entries = origin.anchor_log(0).map_err(|e| e.to_string())?;
    let log = serde_json::to_vec(&serde_json::json!({ "entries": entries, "heads": heads }))
        .map_err(|e| e.to_string())?;
    *cache
        .anchor_log
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(log);

    // The head queries clients asked for: fetch and cache the origin's
    // answers, so the next client with the same query gets the
    // head-proof advertisement.
    let wanted: Vec<String> = std::mem::take(
        &mut *cache
            .wanted
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
    .into_iter()
    .collect();
    for query in wanted {
        if let Ok(answer) = origin.advertisement_query(query.as_str()) {
            cache
                .heads
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(query, answer);
        }
    }
    Ok(())
}

/// Keep the cache under `dir`, so a restart starts warm.
fn store(cache: &Cache, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    if let Some(bytes) = cache
        .advertisement
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        std::fs::write(dir.join("adv"), bytes).map_err(|e| e.to_string())?;
    }
    if let Some(bytes) = cache
        .anchor_log
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        std::fs::write(dir.join("anchor-log"), bytes).map_err(|e| e.to_string())?;
    }
    for ((anchor, from), bytes) in cache
        .claim_log
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
    {
        std::fs::write(dir.join(format!("claim-log-{anchor}-{from}")), bytes)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

type Shared = Arc<Cache>;

async fn adv(
    axum::extract::State(cache): axum::extract::State<Shared>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> axum::response::Response {
    let query = query.unwrap_or_default();
    if query.contains("head=") {
        if let Some(bytes) = cache
            .heads
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&query)
            .cloned()
        {
            return binary(bytes);
        }
        // Not cached: remember the query for the next sync and serve
        // the plain advertisement — the client's stale-head fallback
        // (§4.9.2), which verifies through signatures.
        cache
            .wanted
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(query);
    }
    cache
        .advertisement
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .map_or_else(|| axum::http::StatusCode::NOT_FOUND.into_response(), binary)
}

async fn anchor_log(
    axum::extract::State(cache): axum::extract::State<Shared>,
) -> axum::response::Response {
    cache
        .anchor_log
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .map_or_else(|| axum::http::StatusCode::NOT_FOUND.into_response(), binary)
}

async fn claim_log(
    axum::extract::State(cache): axum::extract::State<Shared>,
    axum::extract::Path(anchor): axum::extract::Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> axum::response::Response {
    let from = query
        .unwrap_or_default()
        .split('&')
        .find_map(|p| p.strip_prefix("from="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    cache
        .claim_log
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(anchor, from))
        .cloned()
        .map_or_else(|| axum::http::StatusCode::NOT_FOUND.into_response(), binary)
}

fn binary(bytes: Vec<u8>) -> axum::response::Response {
    use axum::http::header;
    ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}
