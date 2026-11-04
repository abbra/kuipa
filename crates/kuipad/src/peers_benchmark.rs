//! Opt-in loopback measurement of the bounded-concurrency repair scheduler.

use super::*;
use kuipa_enroll::escrow::{self, BindingHash};
use kuipa_enroll::join::KerberosBinding;
use kuipa_enroll::keytab::{Enctype, Keytab, Principal};
use kuipa_enroll::realm::{RealmInfo, ServerKeys};
use kuipa_enroll::server::{DirectoryError, Staged};
use std::pin::Pin;
use std::sync::atomic::AtomicU64;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct DirectoryStub;
impl Directory for DirectoryStub {
    fn join_with_otp(&self, _: &str, _: &[u8], _: &[Enctype]) -> Result<Keytab, DirectoryError> {
        unreachable!()
    }
    fn join_with_gss(
        &self,
        _: &str,
        _: &[u8],
        _: &[u8; 32],
        _: &[Enctype],
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        unreachable!()
    }
    fn rekey_with_gss(
        &self,
        _: &str,
        _: &[u8],
        _: &[u8; 32],
        _: &[Enctype],
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        unreachable!()
    }
    fn stage_with_gss(
        &self,
        _: &str,
        _: &[u8],
        _: &[u8; 32],
        _: &[Enctype],
        _: &Staged,
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        unreachable!()
    }
    fn register_escrow(&self, _: &Principal, _: &[BindingHash]) -> Result<(), DirectoryError> {
        unreachable!()
    }
    fn escrow_allowed(
        &self,
        _: &Principal,
        _: escrow::Kind,
        _: &BindingHash,
    ) -> Result<bool, DirectoryError> {
        unreachable!()
    }
    fn ca_certificates(&self) -> Result<Vec<Vec<u8>>, DirectoryError> {
        unreachable!()
    }
    fn servers(&self) -> Result<Vec<String>, DirectoryError> {
        unreachable!()
    }
    fn accept_peer(&self, token: &[u8], cb: &[u8; 32]) -> Result<String, DirectoryError> {
        if token.len() < 32 || &token[..32] != cb {
            return Err("bad channel binding".into());
        }
        Ok(std::str::from_utf8(&token[32..])?.to_owned())
    }
}

struct Identity(String);
impl Initiator for Identity {
    fn token(&self, _: &str, cb: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let mut token = cb.to_vec();
        token.extend_from_slice(self.0.as_bytes());
        Ok(token)
    }
}

#[derive(Default)]
struct Counts {
    requests: AtomicU64,
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    rejected: AtomicU64,
    fetch_chunks: AtomicU64,
    upload_chunks: AtomicU64,
    data_chunks: AtomicU64,
    http_request_bytes: AtomicU64,
    http_response_bytes: AtomicU64,
    /// Messages and body bytes per request or response kind.
    kinds: Mutex<BTreeMap<String, (u64, u64)>>,
}

fn request_kind(request: &RequestBody) -> &'static str {
    match request {
        RequestBody::Repair(repair::Request::Probe { .. }) => "probe",
        RequestBody::Repair(repair::Request::Buckets { .. }) => "buckets",
        RequestBody::Repair(repair::Request::Exchange { .. }) => "exchange",
        RequestBody::Snapshot(SnapshotRequest::Fetch { .. }) => "fetch",
        RequestBody::Snapshot(SnapshotRequest::Upload { .. }) => "upload",
    }
}

fn response_kind(response: &ResponseBody) -> &'static str {
    match response {
        ResponseBody::Repair(repair::Response::Probe { .. }) => "probe",
        ResponseBody::Repair(repair::Response::Buckets { .. }) => "buckets",
        ResponseBody::Repair(repair::Response::Exchange { .. }) => "exchange",
        ResponseBody::Snapshot(SnapshotResponse::Equal) => "equal",
        ResponseBody::Snapshot(SnapshotResponse::Data { .. }) => "data",
        ResponseBody::Snapshot(SnapshotResponse::Changed) => "changed",
        ResponseBody::Snapshot(SnapshotResponse::Accepted { .. }) => "accepted",
        ResponseBody::Snapshot(SnapshotResponse::Merged { .. }) => "merged",
        ResponseBody::Snapshot(SnapshotResponse::Busy) => "busy",
    }
}

fn count_kind(counts: &Counts, direction: &str, kind: &str, bytes: usize) {
    let mut kinds = lock(&counts.kinds);
    let entry = kinds.entry(format!("{direction}_{kind}")).or_default();
    entry.0 += 1;
    entry.1 += bytes as u64;
}

struct MeasuredListener {
    inner: tokio::net::TcpListener,
    counts: Arc<Counts>,
}

struct MeasuredStream {
    inner: tokio::net::TcpStream,
    counts: Arc<Counts>,
}

impl axum::serve::Listener for MeasuredListener {
    type Io = MeasuredStream;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (inner, addr) = axum::serve::Listener::accept(&mut self.inner).await;
        (
            MeasuredStream {
                inner,
                counts: self.counts.clone(),
            },
            addr,
        )
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl AsyncRead for MeasuredStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_ready() {
            self.counts
                .http_request_bytes
                .fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        }
        result
    }
}

impl AsyncWrite for MeasuredStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.counts
                .http_response_bytes
                .fetch_add(n as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
fn round_drained(completed_round: usize, target_round: usize, idle: bool) -> bool {
    completed_round >= target_round && idle
}

#[test]
fn round_completion_requires_command_and_quiescence() {
    assert!(
        !round_drained(0, 1, true),
        "an unprocessed tick is not complete"
    );
    assert!(
        !round_drained(1, 1, false),
        "pending or retrying work is not complete"
    );
    assert!(round_drained(1, 1, true), "a drained round is complete");
}

#[test]
fn live_state_discards_unreferenced_keys() {
    let clock = GenerationClock::new();
    let at = now();
    let key = SigningKey::generate_preferred().unwrap();
    let mut state = AnchorState::default();
    assert!(
        state
            .put(
                Entry::Key(key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                at,
                &clock
            )
            .unwrap()
    );
    state.retain(&BTreeSet::new(), "R", &Policy::default(), at);
    assert_eq!(
        state,
        AnchorState::default(),
        "unreferenced keys are not live state"
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "benchmark measures a complete multi-node scheduler lifecycle"
)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "loopback measurement"]
async fn measure_scheduler_repair() {
    let sizes =
        std::env::var("KUIPA_REPLICAS").unwrap_or_else(|_| "10,20,40,60,100,200,300".into());
    let rounds: usize = std::env::var("KUIPA_ROUNDS")
        .unwrap_or_else(|_| "20".into())
        .parse()
        .expect("KUIPA_ROUNDS must be an integer");
    let timeout_secs: u64 = std::env::var("KUIPA_PHASE_TIMEOUT_SECS")
        .unwrap_or_else(|_| "1800".into())
        .parse()
        .expect("KUIPA_PHASE_TIMEOUT_SECS must be an integer");
    let extra_keys: usize = std::env::var("KUIPA_EXTRA_KEYS")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .expect("KUIPA_EXTRA_KEYS must be an integer");
    let anchor_setting = std::env::var("KUIPA_ANCHORS").unwrap_or_else(|_| "0".into());
    assert!(
        anchor_setting == "all" || anchor_setting.parse::<usize>().is_ok(),
        "KUIPA_ANCHORS must be a count or all"
    );
    assert!(
        anchor_setting == "0" || extra_keys == 0,
        "KUIPA_EXTRA_KEYS is a separate synthetic workload; use it only with KUIPA_ANCHORS=0"
    );
    let busy: usize = std::env::var("KUIPA_BUSY_PER_NODE")
        .unwrap_or_else(|_| "0".into())
        .parse()
        .expect("KUIPA_BUSY_PER_NODE must be an integer");
    assert!(
        rounds > 0 && timeout_secs > 0,
        "rounds and timeout must be positive"
    );
    for n in sizes.split(',').map(|s| {
        s.parse::<usize>()
            .expect("KUIPA_REPLICAS must contain integers")
    }) {
        assert!(n >= 2, "at least two replicas are required");
        let anchor_count = if anchor_setting == "all" {
            n
        } else {
            anchor_setting.parse::<usize>().unwrap()
        };
        assert!(
            anchor_count <= n,
            "KUIPA_ANCHORS cannot exceed KUIPA_REPLICAS"
        );
        let root = std::env::temp_dir().join(format!(
            "kuipa-digest-bench-{}-{}-{}",
            std::process::id(),
            n,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let names: Vec<String> = (0..n).map(|i| format!("node{i:04}")).collect();
        let members: BTreeSet<String> = names.iter().cloned().collect();
        let targets: Arc<Mutex<BTreeMap<String, Arc<Peers>>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let counts = Arc::new(Counts::default());
        let app = axum::Router::new().route(
            "/ipa/ku/peer/sync",
            axum::routing::post({
                let targets = targets.clone();
                let counts = counts.clone();
                move |body: axum::body::Bytes| {
                    let targets = targets.clone();
                    let counts = counts.clone();
                    async move {
                        counts.requests.fetch_add(1, Ordering::Relaxed);
                        counts
                            .request_bytes
                            .fetch_add(body.len() as u64, Ordering::Relaxed);
                        let sync = PeerSync::from_bytes(&body).ok();
                        if let Some(request) = sync
                            .as_ref()
                            .and_then(|sync| decode::<Message<RequestBody>>(&sync.payload).ok())
                        {
                            count_kind(&counts, "request", request_kind(&request.body), body.len());
                            match request.body {
                                RequestBody::Snapshot(SnapshotRequest::Fetch { .. }) => {
                                    counts.fetch_chunks.fetch_add(1, Ordering::Relaxed);
                                }
                                RequestBody::Snapshot(SnapshotRequest::Upload { .. }) => {
                                    counts.upload_chunks.fetch_add(1, Ordering::Relaxed);
                                }
                                _ => {}
                            }
                        }
                        let target =
                            sync.and_then(|sync| lock(&targets).get(&sync.receiver).cloned());
                        let result = match target {
                            Some(target) => target.handle(&body).await,
                            None => Err("unknown receiver".into()),
                        };
                        match result {
                            Ok(bytes) => {
                                if let Ok(response) = decode::<Message<ResponseBody>>(&bytes) {
                                    count_kind(
                                        &counts,
                                        "response",
                                        response_kind(&response.body),
                                        bytes.len(),
                                    );
                                    if matches!(
                                        response.body,
                                        ResponseBody::Snapshot(SnapshotResponse::Data { .. })
                                    ) {
                                        counts.data_chunks.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                counts
                                    .response_bytes
                                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                                (axum::http::StatusCode::OK, bytes)
                            }
                            Err(error) => {
                                counts.rejected.fetch_add(1, Ordering::Relaxed);
                                eprintln!("benchmark receiver: {error}");
                                let status = match error.downcast_ref::<PeerError>() {
                                    Some(PeerError::Busy) => {
                                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                                    }
                                    Some(PeerError::NeedContext) => {
                                        axum::http::StatusCode::CONFLICT
                                    }
                                    _ => axum::http::StatusCode::BAD_REQUEST,
                                };
                                (status, Vec::new())
                            }
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let listener = MeasuredListener {
            inner: listener,
            counts: counts.clone(),
        };
        let server_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let at = now();
        let clock = GenerationClock::new();
        let mut initial = AnchorState::default();
        let mut keys = Vec::new();
        let mut claims = Vec::new();
        let mut anchors: Vec<Option<SigningKey>> = (0..n)
            .map(|i| (i < anchor_count).then(|| SigningKey::generate_preferred().unwrap()))
            .collect();
        for anchor in anchors.iter().flatten() {
            assert!(
                initial
                    .put(
                        Entry::Key(anchor.public().to_jwk_json()),
                        "R",
                        &Policy::default(),
                        at,
                        &clock
                    )
                    .unwrap()
            );
        }
        for (name, anchor) in names.iter().zip(&anchors) {
            let key = SigningKey::generate_preferred().unwrap();
            let claim = Claim {
                realm: "R".into(),
                server: name.clone(),
                anchor: anchor.as_ref().map(|key| *key.public().thumbprint()),
                key: *key.public().thumbprint(),
                iat: at.saturating_sub(60),
                exp: at + DEFAULT_VALIDITY,
            };
            initial
                .put(
                    Entry::Claim(claim.clone()),
                    "R",
                    &Policy::default(),
                    at,
                    &clock,
                )
                .unwrap();
            keys.push(key);
            claims.push(claim);
        }
        for anchor in anchors.iter().flatten() {
            let leaves: Vec<_> = claims
                .iter()
                .map(|claim| {
                    claim
                        .leaf(TreeHash::for_signer(anchor.public().alg()))
                        .unwrap()
                })
                .collect();
            let vouch = SignedVouch::issue(
                anchor,
                "R",
                leaves,
                at.saturating_sub(1),
                at + VOUCH_VALIDITY,
                None,
            )
            .unwrap();
            assert!(
                initial
                    .put(Entry::Vouch(vouch), "R", &Policy::default(), at, &clock)
                    .unwrap()
            );
        }
        assert_eq!(initial.claims().count(), n);
        assert_eq!(initial.vouches().count(), anchor_count);
        for _ in 0..extra_keys {
            let key = SigningKey::generate_preferred().unwrap();
            initial
                .put(
                    Entry::Key(key.public().to_jwk_json()),
                    "R",
                    &Policy::default(),
                    at,
                    &clock,
                )
                .unwrap();
        }
        let endpoints: BTreeMap<String, String> = names
            .iter()
            .map(|name| (name.clone(), url.clone()))
            .collect();
        let mut nodes = Vec::new();
        let mut initial_store_ns = 0u128;
        for (i, ((name, key), claim)) in names
            .iter()
            .zip(keys)
            .zip(claims.iter().cloned())
            .enumerate()
        {
            let path = root.join(name);
            std::fs::create_dir(&path).unwrap();
            let store = KeyStore::new(path);
            let started = Instant::now();
            store.store_peer_state(&initial).unwrap();
            initial_store_ns += started.elapsed().as_nanos();
            let info = RealmInfo {
                realm: "R".into(),
                domain: "example.test".into(),
                basedn: "dc=example,dc=test".into(),
                server: name.clone(),
                servers: vec![],
                ca_certs: vec![],
                pkinit_anchors: vec![],
                anchors: vec![],
                heads: vec![],
                trusts: vec![],
                kdc_proxy: None,
            };
            let server = Arc::new(EnrollServer::new(
                ServerKeys {
                    signing: key,
                    join: vec![],
                    escrow: vec![],
                    trust: vec![],
                    vouchers: vec![],
                    retired: vec![],
                },
                info,
                Delegation::new(&claim),
            ));
            let settings = Settings {
                me: name.clone(),
                realm: "R".into(),
                peers: names.clone(),
                discover: false,
                endpoints: endpoints.clone(),
                interval: Duration::from_secs(3600),
                ca_certs: vec![],
                vouch_interval: Duration::ZERO,
            };
            let node = Peers::new(
                settings,
                anchors[i].take(),
                server,
                Arc::new(DirectoryStub),
                Arc::new(Identity(format!("ipa-ku/{name}@R"))),
                store,
            )
            .unwrap();
            lock(&targets).insert(name.clone(), node.clone());
            nodes.push(node);
        }
        println!(
            "{}",
            serde_json::json!({
                "benchmark": "kuipad_initial_persistence",
                "replicas": n,
                "anchors": anchor_count, "extra_keys": extra_keys,
                "state_bytes": initial.to_bytes().len(),
                "writes": n,
                "total_ns": initial_store_ns
            })
        );
        let mut controls = Vec::new();
        let mut tasks = Vec::new();
        for node in &nodes {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            *lock(&node.bench_control) = Some(rx);
            controls.push(tx);
            let node = node.clone();
            tasks.push(tokio::spawn(async move { node.repair_loop().await }));
        }
        for phase in ["idle", "update"] {
            if phase == "update" {
                let node = &nodes[0];
                let mut state = node.exchange.state.write().await;
                if let Some(anchor) = &node.exchange.anchor {
                    let mut renewed = claims[0].clone();
                    renewed.iat = at;
                    renewed.exp = at + DEFAULT_VALIDITY;
                    assert!(
                        state
                            .put(
                                Entry::Claim(renewed.clone()),
                                "R",
                                &Policy::default(),
                                at,
                                &node.exchange.clock
                            )
                            .unwrap()
                    );
                    let leaves: Vec<_> = std::iter::once(&renewed)
                        .chain(claims.iter().skip(1))
                        .map(|claim| {
                            claim
                                .leaf(TreeHash::for_signer(anchor.public().alg()))
                                .unwrap()
                        })
                        .collect();
                    let previous = state.vouch(anchor.public().thumbprint()).unwrap().clone();
                    let vouch = SignedVouch::issue(
                        anchor,
                        "R",
                        leaves,
                        at,
                        at + VOUCH_VALIDITY,
                        Some(&previous),
                    )
                    .unwrap();
                    assert!(
                        state
                            .put(
                                Entry::Vouch(vouch),
                                "R",
                                &Policy::default(),
                                at,
                                &node.exchange.clock
                            )
                            .unwrap()
                    );
                } else {
                    let key = SigningKey::generate_preferred().unwrap();
                    assert!(
                        state
                            .put(
                                Entry::Key(key.public().to_jwk_json()),
                                "R",
                                &Policy::default(),
                                at,
                                &node.exchange.clock
                            )
                            .unwrap()
                    );
                }
                node.exchange.store.store_peer_state(&state).unwrap();
            }
            let source = nodes[0].engine.durable_snapshot().await.unwrap();
            let source_digest = source.digest().unwrap();
            let mut expected = source;
            if anchor_count > 0 {
                expected.retain(&members, "R", &Policy::default(), at);
            }
            if phase == "update" && anchor_count > 0 {
                let anchor = nodes[0].exchange.anchor.as_ref().unwrap();
                let claim = expected
                    .latest_claim(&names[0], Some(anchor.public().thumbprint()))
                    .unwrap();
                assert_eq!(claim.iat, at, "renewed claim must remain in live state");
                assert!(
                    expected
                        .vouch(anchor.public().thumbprint())
                        .unwrap()
                        .covers(claim)
                        .unwrap(),
                    "renewed claim must be covered by its anchor's live vouch"
                );
            }
            for node in &nodes {
                node.bench_busy.store(busy, Ordering::Relaxed);
            }
            let mut routine_converged = false;
            for round in 1..=rounds + 1 {
                let sweep = round == rounds + 1 || routine_converged;
                for node in &nodes {
                    node.repair_started.store(0, Ordering::Relaxed);
                    node.repair_completed.store(0, Ordering::Relaxed);
                    node.repair_failed.store(0, Ordering::Relaxed);
                    node.repair_peak.store(0, Ordering::Relaxed);
                    node.bench_retries.store(0, Ordering::Relaxed);
                }
                for counter in [
                    &counts.requests,
                    &counts.request_bytes,
                    &counts.response_bytes,
                    &counts.rejected,
                    &counts.fetch_chunks,
                    &counts.upload_chunks,
                    &counts.data_chunks,
                    &counts.http_request_bytes,
                    &counts.http_response_bytes,
                ] {
                    counter.store(0, Ordering::Relaxed);
                }
                lock(&counts.kinds).clear();
                let targets: Vec<_> = nodes
                    .iter()
                    .map(|node| node.bench_rounds.load(Ordering::Acquire) + 1)
                    .collect();
                let started = Instant::now();
                for control in &controls {
                    control.send(sweep).expect("repair scheduler stopped");
                }
                tokio::time::timeout(Duration::from_secs(timeout_secs), async {
                    loop {
                        if nodes.iter().zip(&targets).all(|(node, target)| {
                            round_drained(
                                node.bench_rounds.load(Ordering::Acquire),
                                *target,
                                node.bench_idle.load(Ordering::Acquire),
                            )
                        }) {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("scheduler round did not drain within KUIPA_PHASE_TIMEOUT_SECS");
                let elapsed = started.elapsed();
                let mut converged = 0;
                for node in &nodes {
                    let mut actual = node.engine.durable_snapshot().await.unwrap();
                    // An identical snapshot normalizes identically; skip its signature checks.
                    if actual.digest().unwrap() == source_digest {
                        converged += 1;
                        continue;
                    }
                    if anchor_count > 0 {
                        actual.retain(&members, "R", &Policy::default(), at);
                    }
                    if actual == expected {
                        converged += 1;
                    }
                }
                let attempts: usize = nodes
                    .iter()
                    .map(|node| node.repair_started.load(Ordering::Relaxed))
                    .sum();
                let completed: usize = nodes
                    .iter()
                    .map(|node| node.repair_completed.load(Ordering::Acquire))
                    .sum();
                let failures: usize = nodes
                    .iter()
                    .map(|node| node.repair_failed.load(Ordering::Relaxed))
                    .sum();
                let retries: usize = nodes
                    .iter()
                    .map(|node| node.bench_retries.load(Ordering::Relaxed))
                    .sum();
                let peak = nodes
                    .iter()
                    .map(|node| node.repair_peak.load(Ordering::Relaxed))
                    .max()
                    .unwrap();
                println!(
                    "{}",
                    serde_json::json!({
                        "benchmark": "kuipad_scheduler_repair", "replicas": n, "phase": phase,
                        "schedule": if sweep { "sweep" } else { "routine" }, "round": round,
                        "repair_attempts": attempts, "repair_completed": completed,
                        "repair_failures": failures, "repair_retries": retries, "peak_per_node": peak,
                        "http_requests": counts.requests.load(Ordering::Relaxed),
                        "http_request_bytes": counts.http_request_bytes.load(Ordering::Relaxed),
                        "http_response_bytes": counts.http_response_bytes.load(Ordering::Relaxed),
                        "request_body_bytes": counts.request_bytes.load(Ordering::Relaxed),
                        "response_body_bytes": counts.response_bytes.load(Ordering::Relaxed),
                        "handler_rejections": counts.rejected.load(Ordering::Relaxed),
                        "fetch_chunk_requests": counts.fetch_chunks.load(Ordering::Relaxed),
                        "upload_chunks": counts.upload_chunks.load(Ordering::Relaxed),
                        "download_chunks": counts.data_chunks.load(Ordering::Relaxed),
                        "elapsed_ns": elapsed.as_nanos(), "converged_replicas": converged,
                        "converged": converged == n, "state_bytes": expected.to_bytes().len(),
                        "anchors": anchor_count, "extra_keys": extra_keys, "busy_per_node": busy,
                        "kinds": lock(&counts.kinds).iter()
                            .map(|(k, (n, b))| (k.clone(), serde_json::json!({"messages": n, "bytes": b})))
                            .collect::<serde_json::Map<_, _>>()
                    })
                );
                assert_eq!(
                    completed, attempts,
                    "unfinished repairs in {phase} round {round}"
                );
                assert!(
                    failures <= completed && retries <= attempts,
                    "invalid repair accounting"
                );
                assert!(
                    counts.http_request_bytes.load(Ordering::Relaxed)
                        >= counts.request_bytes.load(Ordering::Relaxed),
                    "HTTP request bytes smaller than bodies"
                );
                assert!(
                    counts.http_response_bytes.load(Ordering::Relaxed)
                        >= counts.response_bytes.load(Ordering::Relaxed),
                    "HTTP response bytes smaller than bodies"
                );
                assert!(
                    peak <= MAX_CONCURRENT_REPAIRS,
                    "scheduler exceeded its concurrency limit"
                );
                if sweep {
                    assert_eq!(
                        converged, n,
                        "replicas diverged after sweep for {n} nodes in {phase}"
                    );
                    break;
                }
                routine_converged = converged == n;
            }
        }
        drop(controls);
        for task in tasks {
            task.await.expect("repair scheduler task failed");
        }
        server_task.abort();
        drop(nodes);
        drop(targets);
        std::fs::remove_dir_all(root).unwrap();
    }
}
