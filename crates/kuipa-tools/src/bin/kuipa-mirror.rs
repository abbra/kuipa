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
//! `--data` (the cache and sync live in `kuipa_tools::mirror`).  It
//! then answers, read-only:
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

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::response::IntoResponse;
use clap::Parser;
use kuipa_tools::mirror::{self, Cache};
use kuipa_tools::net::{Endpoint, Trust};

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
    /// Where to keep the cache (default: a private `kuipa-mirror-<pid>`
    /// under the system temporary directory, mode `0700`).
    #[arg(long)]
    data: Option<PathBuf>,
    /// Seconds between syncs (default 60).
    #[arg(long, default_value = "60")]
    interval: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = match mirror::cache_dir(cli.data.as_deref(), std::process::id()) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("kuipa-mirror: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cache = Arc::new(Cache::default());
    if let Err(e) = run(&cli, &dir, Arc::clone(&cache)) {
        eprintln!("kuipa-mirror: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run(cli: &Cli, dir: &std::path::Path, cache: Arc<Cache>) -> Result<(), String> {
    // Fail fast when the origin is unusable, before binding.
    drop(Endpoint::new(&cli.origin, &Trust::FirstContact).map_err(|e| e.to_string())?);
    {
        let origin = Endpoint::new(&cli.origin, &Trust::FirstContact).map_err(|e| e.to_string())?;
        let cache = Arc::clone(&cache);
        let dir = dir.to_owned();
        let interval = cli.interval;
        std::thread::spawn(move || {
            loop {
                if let Err(e) = mirror::sync(&origin, &cache) {
                    eprintln!("kuipa-mirror: sync: {e}");
                } else if let Err(e) = mirror::store(&cache, &dir) {
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
        // Port 0 asks for a free one; say which, so a caller (the
        // playground session) learns where to reach the mirror.
        let bound = listener.local_addr().map_err(|e| e.to_string())?;
        println!("{}", bound.port());
        eprintln!("kuipa-mirror: serving {} on {}", cli.origin, bound);
        axum::serve(listener, app).await.map_err(|e| e.to_string())
    })
}

type Shared = Arc<Cache>;

async fn adv(
    axum::extract::State(cache): axum::extract::State<Shared>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> axum::response::Response {
    let query = query.unwrap_or_default();
    if query.contains("head=") {
        if let Some(bytes) = cache.head_answer(&query) {
            return binary(bytes);
        }
        // Not cached: remember the query for the next sync and serve
        // the plain advertisement — the client's stale-head fallback
        // (§4.9.2), which verifies through signatures.
        cache.remember_wanted(&query);
    }
    cache
        .advertisement()
        .map_or_else(|| axum::http::StatusCode::NOT_FOUND.into_response(), binary)
}

async fn anchor_log(
    axum::extract::State(cache): axum::extract::State<Shared>,
) -> axum::response::Response {
    cache
        .anchor_log()
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
        .claim_log(&anchor, from)
        .map_or_else(|| axum::http::StatusCode::NOT_FOUND.into_response(), binary)
}

fn binary(bytes: Vec<u8>) -> axum::response::Response {
    use axum::http::header;
    ([(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}
