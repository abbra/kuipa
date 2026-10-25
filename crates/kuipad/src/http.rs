//! HTTP routes (§11).  The daemon sits behind httpd, which proxies
//! `/ipa/ku/` to a Unix socket.
//!
//! Every refusal is an empty `403`; the reason goes to the log only.
//! Requests over the rate limits are answered `429` before any work is done
//! (§5.1).  A request whose host name or principal is not even shaped like
//! one is refused before that: nothing of it reaches the limiter's tables,
//! the LDAP directory or the log.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use kuipa_enroll::EnrollServer;
use kuipa_enroll::delegation::HeadPin;
use kuipa_enroll::escrow::EscrowRequest;
use kuipa_enroll::join::{Operation, Request};
use kuipa_enroll::server::Directory;
use kuipa_enroll::trust::TrustRequest;
use serde_json::json;
use tang_pqc::{Thumbprint, b64};

use crate::limit::{self, Limiter};
use crate::peers::Peers;
use crate::tang::Tang;

/// Largest accepted request body.  Large enough for a sealed CA or KRA
/// subsystem PKCS#12 or a wrapped ML-DSA key (§18): an ML-DSA-87 key and
/// certificate, base64-encoded, stay well under a megabyte.
const BODY_LIMIT: usize = 1024 * 1024;

/// Most leaves in one page of `GET tlog/{id}/leaves`.
const MAX_LOG_PAGE: usize = 4096;

/// Most anchors a client may name in `GET adv`.
const MAX_WANTED_ANCHORS: usize = 16;

/// Longest host name or principal accepted in a request.  Well-formed
/// names are far shorter; longer ones serve only to bloat logs and the
/// limiter's keys.
const MAX_NAME: usize = 256;

/// Shared state.
pub struct App<D> {
    /// The protocol server.
    pub server: Arc<EnrollServer>,
    /// The directory.
    pub directory: D,
    /// The anchor exchange, if this server takes part in one.
    pub peers: Option<Arc<Peers>>,
    /// Rate limits.
    pub limiter: Limiter,
    /// The post-quantum Tang server, if this server has Tang keys (§11.5).
    pub tang: Option<Arc<Tang>>,
    /// The `keys` operation's handlers and audit, if enabled (§18.5).
    pub keys: Option<Arc<crate::keys::Keys>>,
    /// This server's transparency log, if it keeps one (`DESIGN-tlog.md`).
    pub ledger: Option<Arc<crate::ledger::FileLedger>>,
}

/// Admit a request for `host`, or the status (`429`) to answer.
fn admit<D>(app: &App<D>, what: &str, host: &str, headers: &HeaderMap) -> Result<(), StatusCode> {
    admit_for(app, what, Some(host), headers)
}

/// Whether `name` is shaped like a host name or Kerberos principal:
/// not empty, not absurdly long, no control characters or whitespace.
/// Only the shape: whether the name is real is the directory's question,
/// asked after authentication.
fn plausible_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// As [`admit`]; with no `host`, only the source's bucket is used: for
/// operations that are only ever Kerberos-authenticated (registration,
/// vault operations), where there is nothing to guess, and whose many
/// users on one host must not share that host's allowance.
fn admit_for<D>(
    app: &App<D>,
    what: &str,
    host: Option<&str>,
    headers: &HeaderMap,
) -> Result<(), StatusCode> {
    if host.is_some_and(|h| !plausible_name(h)) {
        return Err(StatusCode::FORBIDDEN);
    }
    let source =
        limit::forwarded_source(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()));
    match host {
        Some(host) => app.limiter.check(host, source.as_deref()),
        None => app.limiter.check_source(source.as_deref()),
    }
    .map_err(|limited| {
        eprintln!(
            "kuipad: {what}: rate limited ({limited:?}, source {})",
            source.as_deref().unwrap_or("unknown")
        );
        StatusCode::TOO_MANY_REQUESTS
    })
}

/// The router.
pub fn router<D: Directory + Send + Sync + 'static>(app: Arc<App<D>>) -> Router {
    Router::new()
        .route("/ipa/ku/adv", get(advertisement::<D>))
        .route("/ipa/ku/join/{kid}", post(join::<D>))
        .route("/ipa/ku/rekey/{kid}", post(rekey::<D>))
        .route("/ipa/ku/stage/{kid}", post(stage::<D>))
        .route("/ipa/ku/register/{kid}", post(register::<D>))
        .route("/ipa/ku/vault/{kid}", post(vault::<D>))
        .route("/ipa/ku/keys/{kid}", post(keys::<D>))
        .route("/ipa/ku/rec/{kid}", post(recover::<D>))
        .route("/ipa/ku/peer/sync", post(peer_sync::<D>))
        .route("/ipa/ku/anchor-log", get(anchor_log::<D>))
        .route("/ipa/ku/claim-log/{anchor}", get(claim_log::<D>))
        .route("/ipa/ku/tlog/{id}", post(tlog::<D>))
        .route("/ipa/ku/sign/{kid}", post(sign::<D>))
        .route("/ipa/ku/tlog/{id}/head", get(log_head::<D>))
        .route("/ipa/ku/tlog/{id}/cosign", post(log_cosign::<D>))
        .route("/ipa/ku/tlog/{id}/leaves", get(log_leaves::<D>))
        .route("/ipa/ku/tlog/{id}/proof", get(log_proof::<D>))
        .route("/ipa/ku/tlog/{id}/consistency", get(log_consistency::<D>))
        .route("/ipa/ku/trust/{kid}", post(establish_trust::<D>))
        .route("/ipa/ku/tang/adv", get(tang_advertisement::<D>))
        .route("/ipa/ku/tang/adv/{thp}", get(tang_advertisement_for::<D>))
        .route("/ipa/ku/tang/key/{kid}", get(tang_exchange_key::<D>))
        .route("/ipa/ku/tang/rec/{kid}", post(tang_recover::<D>))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(app)
}

fn refused(what: &str, reason: &dyn std::fmt::Display) -> Response {
    eprintln!("kuipad: {what}: {reason}");
    StatusCode::FORBIDDEN.into_response()
}

fn binary(body: Vec<u8>, content_type: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

/// The anchors a client asks for: `?anchor=<thumbprint>`, repeated, in
/// order of preference; unparsable ones are ignored.
fn wanted_anchors(query: Option<&str>) -> Vec<Thumbprint> {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|p| p.strip_prefix("anchor=")?.parse().ok())
        .take(MAX_WANTED_ANCHORS)
        .collect()
}

/// The vouch heads a client pins (§4.9): `?head=<thumbprint>.<size>.
/// <root>`, repeated; unparsable ones are ignored.  The root is a
/// base64url tree hash, the size a decimal leaf count; a size of zero
/// names no head and is ignored.
fn wanted_heads(query: Option<&str>) -> Vec<HeadPin> {
    query
        .unwrap_or_default()
        .split('&')
        .filter_map(|p| p.strip_prefix("head="))
        .filter_map(|h| {
            let (anchor, rest) = h.split_once('.')?;
            let (size, root) = rest.split_once('.')?;
            Some(HeadPin {
                anchor: anchor.parse().ok()?,
                size: size.parse().ok()?,
                root: b64::decode(root).ok().and_then(|r| r.try_into().ok())?,
            })
        })
        // A zero-size log has no head: no proof backs it (§4.9).
        .filter(|h| h.size > 0)
        .take(MAX_WANTED_ANCHORS)
        .collect()
}

async fn advertisement<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    RawQuery(query): RawQuery,
) -> Response {
    match app.server.advertisement_with_heads(
        &wanted_anchors(query.as_deref()),
        &wanted_heads(query.as_deref()),
    ) {
        Ok(adv) => (
            [(header::CONTENT_TYPE, "application/jose+json")],
            adv.to_json(),
        )
            .into_response(),
        Err(e) => {
            eprintln!("kuipad: advertisement: {e}");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// A fetched piece of the anchor epoch log (§4.8): `?from=<seq>`, the
/// entries after that sequence number, oldest first.  Public, like the
/// advertisement.
async fn anchor_log<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    RawQuery(query): RawQuery,
) -> Response {
    let from = query
        .unwrap_or_default()
        .split('&')
        .find_map(|p| p.strip_prefix("from="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let heads: Vec<_> = app
        .server
        .heads()
        .into_iter()
        .map(|h| h.to_json())
        .collect();
    match serde_json::to_vec(&json!({ "entries": app.server.epoch_log(from), "heads": heads })) {
        Ok(body) => binary(body, "application/json"),
        Err(e) => {
            eprintln!("kuipad: anchor log: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// One anchor's claim log (§4.9): `?from=<index>`, the leaves after that
/// index, oldest first, with the head they lead to.  Public, like the
/// anchor log: leaves are content-addressed claims, verifiable against
/// any head that follows them.
async fn claim_log<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(anchor): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let from = query
        .unwrap_or_default()
        .split('&')
        .find_map(|p| p.strip_prefix("from="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let Ok(anchor) = anchor.parse() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(page) = app.server.claim_log(&anchor, from) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match serde_json::to_vec(&page) {
        Ok(body) => binary(body, "application/json"),
        Err(e) => {
            eprintln!("kuipad: claim log: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The `u64` query parameters `names`, in order; `None` if one is missing
/// or not a number.
fn numbers<const N: usize>(query: Option<&str>, names: [&str; N]) -> Option<[u64; N]> {
    let query = query.unwrap_or_default();
    let mut out = [0; N];
    for (slot, name) in out.iter_mut().zip(names) {
        *slot = query
            .split('&')
            .find_map(|p| p.strip_prefix(name)?.strip_prefix('='))?
            .parse()
            .ok()?;
    }
    Some(out)
}

/// This server's log, if `id` names it.
fn ledger_for<'a, D>(app: &'a App<D>, id: &str) -> Option<&'a crate::ledger::FileLedger> {
    let ledger = app.ledger.as_deref()?;
    (id.parse::<kuipa_enroll::tlog::LogId>().ok()? == ledger.id()).then_some(ledger)
}

fn hashes_json(what: &str, hashes: &[kuipa_enroll::merkle::Hash]) -> Response {
    let hashes: Vec<String> = hashes.iter().map(|h| b64::encode(h)).collect();
    match serde_json::to_vec(&json!({ what: hashes })) {
        Ok(body) => binary(body, "application/json"),
        Err(e) => {
            eprintln!("kuipad: log {what}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The log's current signed head (`IPLS`, DESIGN-tlog.md §3).  Public:
/// heads and leaves are what monitors and witnesses check.
async fn log_head<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(id): Path<String>,
) -> Response {
    let Some(ledger) = ledger_for(&app, &id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
    match ledger.signed_head(&app.server.keys().signing, now) {
        Ok(Some(head)) => binary(head.to_bytes(), "application/octet-stream"),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            eprintln!("kuipad: log head: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// A witness's cosignature on the head being served (`IPLS` with its
/// cosignature, DESIGN-tlog.md §4): JSON `{cosignatures}` (the trusted
/// ones the served head now carries) when one was added, `409` for a head no longer served (fetch it again), `403` for
/// no trusted cosignature.  Rate limited by source like vault operations.
async fn log_cosign<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(status) = admit_for(&app, "tlog cosign", None, &headers) {
        return status.into_response();
    }
    let Some(ledger) = ledger_for(&app, &id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(submitted) = kuipa_enroll::tlog::SignedHead::from_bytes(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let policy = match tang_pqc::Policy::from_system() {
        Ok(p) => p,
        Err(e) => return refused("tlog cosign", &e),
    };
    match ledger.cosign(&submitted, &policy) {
        crate::ledger::Cosigned::Accepted(n) => {
            eprintln!(
                "kuipad: tlog cosign: head of {} leaves now has {n} trusted cosignatures",
                submitted.head.size
            );
            binary(
                json!({ "cosignatures": n }).to_string().into_bytes(),
                "application/json",
            )
        }
        crate::ledger::Cosigned::Stale => StatusCode::CONFLICT.into_response(),
        crate::ledger::Cosigned::Untrusted => {
            refused("tlog cosign", &"no cosignature by a trusted witness")
        }
    }
}

/// `?from=<index>`: up to [`MAX_LOG_PAGE`] leaves (`IPLF`, base64url),
/// oldest first.  Leaves name no subject, only its index.
async fn log_leaves<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(ledger) = ledger_for(&app, &id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let [from] = numbers(query.as_deref(), ["from"]).unwrap_or([0]);
    let leaves: Vec<String> = ledger
        .leaves(from, MAX_LOG_PAGE)
        .iter()
        .map(|l| b64::encode(&l.to_bytes()))
        .collect();
    match serde_json::to_vec(&json!({ "from": from, "leaves": leaves })) {
        Ok(body) => binary(body, "application/json"),
        Err(e) => {
            eprintln!("kuipad: log leaves: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `?index=<i>&size=<n>`: the inclusion path of leaf `i` in the tree of
/// `n` leaves — the size of a head the client holds.
async fn log_proof<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(ledger) = ledger_for(&app, &id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some([index, size]) = numbers(query.as_deref(), ["index", "size"]) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match ledger.inclusion(index, size) {
        Ok(path) => hashes_json("path", &path),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `?from=<m>&size=<n>`: the proof that the tree of `m` leaves is a
/// prefix of the tree of `n`.
async fn log_consistency<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(ledger) = ledger_for(&app, &id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some([from, size]) = numbers(query.as_deref(), ["from", "size"]) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match ledger.consistency(from, size) {
        Ok(proof) => hashes_json("proof", &proof),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn jose(adv: &tang_pqc::SignedAdvertisement) -> Response {
    (
        [(header::CONTENT_TYPE, "application/jose+json")],
        adv.to_json(),
    )
        .into_response()
}

async fn tang_advertisement<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
) -> Response {
    let Some(tang) = &app.tang else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tang.advertisement() {
        Ok(adv) => jose(&adv),
        Err(e) => {
            eprintln!("kuipad: tang advertisement: {e}");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

async fn tang_advertisement_for<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(thp): Path<String>,
) -> Response {
    let (Some(tang), Ok(thp)) = (&app.tang, thp.parse::<Thumbprint>()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tang.advertisement_for(&thp) {
        Ok(Some(adv)) => jose(&adv),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            eprintln!("kuipad: tang advertisement for {thp}: {e}");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// The public exchange key `kid`, advertised or retired, as a JWK; `404`
/// for a key this server does not have.
async fn tang_exchange_key<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
) -> Response {
    let (Some(tang), Ok(kid)) = (&app.tang, kid.parse::<Thumbprint>()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match tang.exchange_key(&kid) {
        Ok(key) => (
            [(header::CONTENT_TYPE, "application/jwk+json")],
            key.to_jwk_json(),
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Tang's answers: `404` for a key this server does not have, `400` for a
/// request that does not parse, match or open under it, `429` when rate
/// limited.
async fn tang_recover<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(tang) = app.tang.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let source =
        limit::forwarded_source(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()));
    if app.limiter.check_source(source.as_deref()).is_err() {
        eprintln!(
            "kuipad: tang recovery: rate limited (source {})",
            source.as_deref().unwrap_or("unknown")
        );
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let request = match tang_pqc::RecoveryRequest::from_bytes(&body) {
        Ok(r) if r.kid().to_string() == kid => r,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || tang.recover(&request)).await;
    match result {
        Ok(Ok(response)) => binary(response.to_bytes(), "application/vnd.tang-pqc.rec-rsp"),
        Ok(Err(tang_pqc::Error::UnknownKey(_))) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(e)) => {
            eprintln!("kuipad: tang recovery: {e}");
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(e) => {
            eprintln!("kuipad: tang recovery: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Decode, check the path `kid`, and run the (blocking) handler.
async fn exchange<D: Directory + Send + Sync + 'static>(
    app: Arc<App<D>>,
    op: Operation,
    kid: String,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let request = match Request::from_bytes(op, &body) {
        Ok(r) if r.kid().to_string() == kid => r,
        Ok(_) => return refused("request", &"kid does not match the path"),
        Err(e) => return refused("request", &e),
    };
    let what = format!("{op:?} {}", request.fqdn());
    let host = match op {
        Operation::Register
        | Operation::Vault
        | Operation::Keys
        | Operation::Tlog
        | Operation::Sign => None,
        _ => Some(request.fqdn()),
    };
    if let Err(status) = admit_for(&app, &what, host, headers) {
        return status.into_response();
    }
    let result = tokio::task::spawn_blocking(move || {
        app.server
            .handle(&request, &app.directory)
            .map(|r| r.to_bytes())
            .map_err(|e| e.to_string())
    })
    .await;
    match result {
        Ok(Ok(body)) => {
            eprintln!("kuipad: {what}: ok");
            binary(body, "application/vnd.ipa-ku.join-rsp")
        }
        Ok(Err(reason)) => refused(&what, &reason),
        Err(e) => refused(&what, &e),
    }
}

async fn join<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    exchange(app, Operation::Join, kid, &headers, body).await
}

async fn rekey<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    exchange(app, Operation::Rekey, kid, &headers, body).await
}

async fn stage<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    exchange(app, Operation::Stage, kid, &headers, body).await
}

async fn register<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    exchange(app, Operation::Register, kid, &headers, body).await
}

async fn vault<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    exchange(app, Operation::Vault, kid, &headers, body).await
}

async fn keys<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Like registration and vault operations: only ever
    // Kerberos-authenticated, so only the source's bucket applies.
    exchange(app, Operation::Keys, kid, &headers, body).await
}

async fn tlog<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // A lookup of the caller's own entries: Kerberos-only, like vault
    // operations.
    exchange(app, Operation::Tlog, kid, &headers, body).await
}

async fn sign<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Kerberos-only, like vault operations: the source's bucket applies.
    exchange(app, Operation::Sign, kid, &headers, body).await
}

async fn recover<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request = match EscrowRequest::from_bytes(&body) {
        Ok(r) if r.recovery().kid().to_string() == kid => r,
        Ok(_) => return refused("recover", &"kid does not match the path"),
        Err(e) => return refused("recover", &e),
    };
    let what = format!("recover {}", request.principal());
    // A machine vault is opened by its principal, limited before anything
    // is decapsulated.  A user vault's `P` is its owner, whoever opens it:
    // only the source is limited first, and the opener once known, so a
    // shared vault's members each have their own allowance (§7.6.12).
    let machine = app.server.is_machine_request(&request);
    let principal = request.principal().to_string();
    let host = machine.then_some(principal.as_str());
    if let Err(status) = admit_for(&app, &what, host, &headers) {
        return status.into_response();
    }
    let result = tokio::task::spawn_blocking(move || {
        let limited = std::cell::Cell::new(false);
        let admit = |opener: &kuipa_enroll::keytab::Principal| {
            let ok = app.limiter.check(&opener.to_string(), None).is_ok();
            limited.set(!ok);
            ok
        };
        app.server
            .recover_admitted(&request, &app.directory, &admit)
            .map(|r| r.to_bytes())
            .map_err(|e| (e.to_string(), limited.get()))
    })
    .await;
    match result {
        Ok(Ok(body)) => binary(body, "application/vnd.ipa-ku.rec-rsp"),
        Ok(Err((reason, true))) => {
            eprintln!("kuipad: {what}: rate limited ({reason})");
            StatusCode::TOO_MANY_REQUESTS.into_response()
        }
        Ok(Err((reason, false))) => refused(&what, &reason),
        Err(e) => refused(&what, &e),
    }
}

async fn establish_trust<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    Path(kid): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request = match TrustRequest::from_bytes(&body) {
        Ok(r) if r.kid().to_string() == kid => r,
        Ok(_) => return refused("trust", &"kid does not match the path"),
        Err(e) => return refused("trust", &e),
    };
    let what = format!("trust with {}", request.initiator());
    if let Err(status) = admit(&app, &what, request.initiator(), &headers) {
        return status.into_response();
    }
    let result = tokio::task::spawn_blocking(move || {
        app.server
            .establish_trust(&request, &app.directory)
            .map(|r| r.to_bytes())
            .map_err(|e| e.to_string())
    })
    .await;
    match result {
        Ok(Ok(body)) => {
            eprintln!("kuipad: {what}: established");
            binary(body, "application/vnd.ipa-ku.trust-rsp")
        }
        Ok(Err(reason)) => refused(&what, &reason),
        Err(e) => refused(&what, &e),
    }
}

async fn peer_sync<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Syncs arrive from other servers, which the GSS-API token check in
    // `handle` authenticates; the cost of that check is still bounded by
    // the per-source rate limit, like every other route.
    let source =
        limit::forwarded_source(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()));
    if app.limiter.check_source(source.as_deref()).is_err() {
        eprintln!("kuipad: peer sync: rate limited");
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Some(peers) = &app.peers else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match peers.handle(&body).await {
        Ok(state) => binary(state, "application/vnd.ipa-ku.peer-sync"),
        Err(e) => refused("peer sync", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_from_the_query() {
        let a = Thumbprint::from_bytes([1; 32]);
        let b = Thumbprint::from_bytes([2; 32]);
        assert_eq!(
            wanted_anchors(Some(&format!("anchor={a}&x=1&anchor=junk&anchor={b}"))),
            [a, b]
        );
        assert_eq!(wanted_anchors(None).len(), 0);
        let many = format!("anchor={a}&").repeat(40);
        assert_eq!(wanted_anchors(Some(&many)).len(), MAX_WANTED_ANCHORS);
    }

    #[test]
    fn heads_from_the_query() {
        let a = Thumbprint::from_bytes([1; 32]);
        // A SHA-384 root: a head names either length.
        let root = kuipa_enroll::merkle::Hash::from_slice(&[7; 48]).unwrap();
        let head = format!("head={a}.12.{}", b64::encode(&root));
        assert_eq!(
            wanted_heads(Some(&format!("{head}&head=junk&head={a}."))),
            [HeadPin {
                anchor: a,
                size: 12,
                root,
            }]
        );
        assert_eq!(wanted_heads(None).len(), 0);
        // Unparsable heads are ignored, not fatal.
        assert_eq!(wanted_heads(Some("head=not-a-head&head=x.y.z")).len(), 0);
        // A size of zero names no head — no proof backs it — and is
        // ignored like junk.
        assert_eq!(
            wanted_heads(Some(&format!("head={a}.0.{}", b64::encode(&root)))).len(),
            0,
        );
    }

    #[test]
    fn numbers_from_the_query() {
        assert_eq!(
            numbers(Some("size=5&x=1&index=2"), ["index", "size"]),
            Some([2, 5])
        );
        assert_eq!(numbers(Some("index=2"), ["index", "size"]), None);
        assert_eq!(numbers(Some("index=-1&size=2"), ["index", "size"]), None);
        // A name must match whole: `sizes` is not `size`.
        assert_eq!(numbers(Some("sizes=3"), ["size"]), None);
        assert_eq!(numbers(None, ["from"]), None);
    }

    #[test]
    fn implausible_names_are_refused_outright() {
        assert!(plausible_name("web1.example.test"));
        assert!(plausible_name("host/web1.example.test@EXAMPLE.TEST"));
        assert!(!plausible_name(""), "empty");
        assert!(!plausible_name(&"h".repeat(MAX_NAME + 1)), "too long");
        assert!(!plausible_name("web1\n.example"), "control character");
        assert!(!plausible_name("web1 example"), "whitespace");
    }
}
