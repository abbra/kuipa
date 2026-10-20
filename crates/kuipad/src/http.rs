//! HTTP routes (§11).  The daemon sits behind httpd, which proxies
//! `/ipa/ku/` to a Unix socket.
//!
//! Every refusal is an empty `403`; the reason goes to the log only.
//! Requests over the rate limits are answered `429` before any work is done
//! (§5.1).

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use kuipa_enroll::EnrollServer;
use kuipa_enroll::escrow::EscrowRequest;
use kuipa_enroll::join::{Operation, Request};
use kuipa_enroll::server::Directory;
use kuipa_enroll::trust::TrustRequest;
use serde_json::json;
use tang_pqc::Thumbprint;

use crate::limit::{self, Limiter};
use crate::peers::Peers;
use crate::tang::Tang;

/// Largest accepted request body.
const BODY_LIMIT: usize = 64 * 1024;

/// Most anchors a client may name in `GET adv`.
const MAX_WANTED_ANCHORS: usize = 16;

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
}

/// Admit a request for `host`, or the status (`429`) to answer.
fn admit<D>(app: &App<D>, what: &str, host: &str, headers: &HeaderMap) -> Result<(), StatusCode> {
    let source =
        limit::forwarded_source(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()));
    app.limiter
        .check(host, source.as_deref())
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
        .route("/ipa/ku/rec/{kid}", post(recover::<D>))
        .route("/ipa/ku/peer/sync", post(peer_sync::<D>))
        .route("/ipa/ku/anchor-log", get(anchor_log::<D>))
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

async fn advertisement<D: Directory + Send + Sync + 'static>(
    State(app): State<Arc<App<D>>>,
    RawQuery(query): RawQuery,
) -> Response {
    match app.server.advertisement(&wanted_anchors(query.as_deref())) {
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
    match serde_json::to_vec(&json!({ "entries": app.server.epoch_log(from) })) {
        Ok(body) => binary(body, "application/json"),
        Err(e) => {
            eprintln!("kuipad: anchor log: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
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
    if let Some(source) = &source
        && app.limiter.check_source(source).is_err()
    {
        eprintln!("kuipad: tang recovery: rate limited (source {source})");
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
    if let Err(status) = admit(&app, &what, request.fqdn(), headers) {
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
    if let Err(status) = admit(&app, &what, &request.principal().to_string(), &headers) {
        return status.into_response();
    }
    let result = tokio::task::spawn_blocking(move || {
        app.server
            .recover(&request, &app.directory)
            .map(|r| r.to_bytes())
            .map_err(|e| e.to_string())
    })
    .await;
    match result {
        Ok(Ok(body)) => binary(body, "application/vnd.ipa-ku.rec-rsp"),
        Ok(Err(reason)) => refused(&what, &reason),
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
    body: Bytes,
) -> Response {
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
}
