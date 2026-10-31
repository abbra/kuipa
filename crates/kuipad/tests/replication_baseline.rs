//! In-process agirru scheduling baseline. This is not a kuipad wire benchmark.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use agirru_crdt::{GenerationClock, Merge};
use agirru_engine::{
    CborCodec, Codec, Envelope, GossipConfig, GossipEngine, GossipRuntime, Membership, NoopHooks,
    Storage, Transport,
};
use kuipa_enroll::anchors::{AnchorState, Entry};
use kuipa_enroll::delegation::SignedVouch;
use kuipa_enroll::merkle::{Hash, TreeHash};
use tang_pqc::{Policy, SigningKey};
use tokio::sync::{RwLock, mpsc};

type Node = GossipEngine<AnchorState, usize, Runtime>;

#[derive(Default)]
struct Counts {
    requests: AtomicU64,
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    delivered_request_bytes: AtomicU64,
    dropped_response_bytes: AtomicU64,
    round: AtomicU64,
    failures: AtomicU64,
}

struct Runtime {
    id: usize,
    nodes: Arc<Mutex<Vec<Weak<Node>>>>,
    counts: Arc<Counts>,
    partitioned: Arc<AtomicBool>,
    lossy: Arc<AtomicBool>,
    response_loss: Arc<AtomicBool>,
    codec: CborCodec,
    hooks: NoopHooks,
}

fn should_drop(sender: usize, receiver: usize, round: u64) -> bool {
    let mut x = 2119_u64
        ^ (sender as u64).wrapping_mul(0x9e3779b97f4a7c15)
        ^ (receiver as u64).wrapping_mul(0xbf58476d1ce4e5b9)
        ^ round.wrapping_mul(0x94d049bb133111eb);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    (x ^ (x >> 31)) % 10 == 0
}

impl Transport<usize> for Runtime {
    type Error = std::io::Error;

    async fn send_recv(&self, peer: &usize, request: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        let node = self.nodes.lock().unwrap()[*peer].upgrade().unwrap();
        self.counts.requests.fetch_add(1, Ordering::Relaxed);
        self.counts
            .request_bytes
            .fetch_add(request.len() as u64, Ordering::Relaxed);
        let split = self.nodes.lock().unwrap().len() / 2;
        if self.partitioned.load(Ordering::Relaxed) && (self.id < split) != (*peer < split) {
            self.counts.failures.fetch_add(1, Ordering::Relaxed);
            return Err(std::io::Error::other("simulated partition"));
        }
        if self.lossy.load(Ordering::Relaxed)
            && should_drop(self.id, *peer, self.counts.round.load(Ordering::Relaxed))
        {
            self.counts.failures.fetch_add(1, Ordering::Relaxed);
            return Err(std::io::Error::other("simulated request loss"));
        }
        self.counts
            .delivered_request_bytes
            .fetch_add(request.len() as u64, Ordering::Relaxed);
        let response = node.handle_inbound(&self.id, request).await?;
        if self.response_loss.load(Ordering::Relaxed)
            && should_drop(self.id, *peer, self.counts.round.load(Ordering::Relaxed))
        {
            self.counts.failures.fetch_add(1, Ordering::Relaxed);
            self.counts
                .dropped_response_bytes
                .fetch_add(response.len() as u64, Ordering::Relaxed);
            return Err(std::io::Error::other("simulated response loss"));
        }
        self.counts
            .response_bytes
            .fetch_add(response.len() as u64, Ordering::Relaxed);
        Ok(response)
    }
}

impl Membership<usize> for Runtime {
    async fn peers(&self) -> Vec<usize> {
        (0..self.nodes.lock().unwrap().len())
            .filter(|id| *id != self.id)
            .collect()
    }
}

impl Storage<AnchorState> for Runtime {
    type Error = std::io::Error;

    async fn load(&self) -> Result<AnchorState, Self::Error> {
        Ok(AnchorState::default())
    }

    async fn persist_full(&self, _: &AnchorState) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl GossipRuntime<AnchorState, usize> for Runtime {
    type Transport = Self;
    type Membership = Self;
    type Storage = Self;
    type Hooks = NoopHooks;
    type Codec = CborCodec;

    fn transport(&self) -> &Self {
        self
    }
    fn membership(&self) -> &Self {
        self
    }
    fn storage(&self) -> &Self {
        self
    }
    fn hooks(&self) -> &NoopHooks {
        &self.hooks
    }
    fn codec(&self) -> &CborCodec {
        &self.codec
    }
}

#[tokio::test]
async fn reloaded_state_is_included_in_bounded_engine_response() {
    let mut saved = AnchorState::default();
    let old_clock = GenerationClock::new();
    for _ in 0..2 {
        let key = SigningKey::generate_preferred().unwrap();
        saved
            .put(
                Entry::Key(key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                0,
                &old_clock,
            )
            .unwrap();
    }
    let mut loaded = AnchorState::from_bytes(&saved.to_bytes()).unwrap();
    let engine_clock = GenerationClock::new();
    loaded.rebase_generations(&engine_clock);
    let runtime = Runtime {
        id: 0,
        nodes: Arc::new(Mutex::new(Vec::new())),
        counts: Arc::new(Counts::default()),
        partitioned: Arc::new(AtomicBool::new(false)),
        lossy: Arc::new(AtomicBool::new(false)),
        response_loss: Arc::new(AtomicBool::new(false)),
        codec: CborCodec,
        hooks: NoopHooks,
    };
    let engine = GossipEngine::bootstrap_with_state(
        engine_clock,
        runtime,
        GossipConfig::default(),
        Arc::new(RwLock::new(loaded)),
    );
    let incoming_key = SigningKey::generate_preferred().unwrap();
    let mut incoming = AnchorState::default();
    incoming
        .put(
            Entry::Key(incoming_key.public().to_jwk_json()),
            "R",
            &Policy::default(),
            0,
            &GenerationClock::new(),
        )
        .unwrap();
    saved.merge(&incoming, &GenerationClock::new());
    let request = Envelope {
        state: incoming,
        issued_at: 0,
        is_delta: true,
        sender_gen: 1,
        request_delta_since: Some(u64::MAX),
        sender_observed_clock: None,
    };
    let bytes = CborCodec.encode(&request).unwrap();
    let response = engine.handle_inbound(&1, bytes).await.unwrap();
    let response: Envelope<AnchorState> = CborCodec.decode(&response).unwrap();
    assert_eq!(
        response.state, saved,
        "loaded entries must survive a stale pre-restart watermark"
    );
    assert_eq!(
        response.sender_gen, 3,
        "the inbound merge must advance the shared clock"
    );
}

async fn round(
    nodes: &[Arc<Node>],
    rx: &mut mpsc::UnboundedReceiver<usize>,
    counts: &Counts,
) -> (u64, u64, u64) {
    counts.requests.store(0, Ordering::Relaxed);
    counts.request_bytes.store(0, Ordering::Relaxed);
    counts.response_bytes.store(0, Ordering::Relaxed);
    counts.failures.store(0, Ordering::Relaxed);
    counts.delivered_request_bytes.store(0, Ordering::Relaxed);
    counts.dropped_response_bytes.store(0, Ordering::Relaxed);
    counts.round.fetch_add(1, Ordering::Relaxed);
    for node in nodes {
        node.notify_local_change();
    }
    for _ in nodes {
        tokio::time::timeout(Duration::from_secs(300), rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    (
        counts.requests.load(Ordering::Relaxed),
        counts.request_bytes.load(Ordering::Relaxed),
        counts.response_bytes.load(Ordering::Relaxed),
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement"]
async fn measure_replication_baseline() {
    let sizes = std::env::var("KUIPA_REPLICAS").unwrap_or_else(|_| "60,100,200,300".into());
    for n in sizes
        .split(',')
        .map(|value| value.parse::<usize>().unwrap())
    {
        assert!(n >= 2);
        let nodes_ref = Arc::new(Mutex::new(Vec::new()));
        let counts = Arc::new(Counts::default());
        let partitioned = Arc::new(AtomicBool::new(false));
        let lossy = Arc::new(AtomicBool::new(false));
        let response_loss = Arc::new(AtomicBool::new(false));
        let key = SigningKey::generate_preferred().unwrap();
        let initial_clock = GenerationClock::new();
        let mut initial = AnchorState::default();
        initial
            .put(
                Entry::Key(key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                0,
                &initial_clock,
            )
            .unwrap();
        let mut nodes = Vec::new();
        let mut clocks = Vec::new();
        let mut tasks = Vec::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        for id in 0..n {
            let clock = GenerationClock::new();
            clock.bump();
            let runtime = Runtime {
                id,
                nodes: nodes_ref.clone(),
                counts: counts.clone(),
                partitioned: partitioned.clone(),
                lossy: lossy.clone(),
                response_loss: response_loss.clone(),
                codec: CborCodec,
                hooks: NoopHooks,
            };
            let cfg = GossipConfig {
                round_interval: Duration::from_secs(3600),
                ..GossipConfig::default()
            };
            let node = Arc::new(GossipEngine::bootstrap_with_state(
                clock.clone(),
                runtime,
                cfg,
                Arc::new(RwLock::new(initial.clone())),
            ));
            nodes.push(node);
            clocks.push(clock);
        }
        *nodes_ref.lock().unwrap() = nodes.iter().map(Arc::downgrade).collect();
        for (id, node) in nodes.iter().enumerate() {
            let node = node.clone();
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                node.run_with(|_| {
                    let _ = tx.send(id);
                })
                .await
            }));
        }
        let startup = round(&nodes, &mut rx, &counts).await;
        let idle = round(&nodes, &mut rx, &counts).await;
        assert_eq!(startup.0, (n * (n - 1)) as u64);
        assert_eq!(idle.0, 0);
        let new_key = SigningKey::generate_preferred().unwrap();
        nodes[0]
            .state()
            .write()
            .await
            .put(
                Entry::Key(new_key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                0,
                &clocks[0],
            )
            .unwrap();
        let mut update = Vec::new();
        for _ in 0..8 {
            let result = round(&nodes, &mut rx, &counts).await;
            update.push(result);
            if result.0 == 0 {
                break;
            }
        }
        assert_eq!(update.last().unwrap().0, 0, "gossip did not quiesce");
        let expected = nodes[0].state().read().await.clone();
        assert_eq!(expected.len(), 2);
        for node in &nodes {
            assert_eq!(*node.state().read().await, expected, "replicas diverged");
        }
        println!("replicas={n} startup={startup:?} idle={idle:?} update_rounds={update:?}");
        partitioned.store(true, Ordering::Relaxed);
        let partition_key = SigningKey::generate_preferred().unwrap();
        nodes[0]
            .state()
            .write()
            .await
            .put(
                Entry::Key(partition_key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                0,
                &clocks[0],
            )
            .unwrap();
        let mut during_partition = Vec::new();
        for _ in 0..2 {
            let counts_for_round = round(&nodes, &mut rx, &counts).await;
            during_partition.push((counts_for_round, counts.failures.load(Ordering::Relaxed)));
        }
        assert!(during_partition.iter().any(|(_, failures)| *failures > 0));
        for node in nodes.iter().skip(n / 2) {
            assert_eq!(
                node.state().read().await.len(),
                2,
                "partition leaked update"
            );
        }
        partitioned.store(false, Ordering::Relaxed);
        let mut healing = Vec::new();
        for _ in 0..8 {
            let result = round(&nodes, &mut rx, &counts).await;
            assert_eq!(counts.failures.load(Ordering::Relaxed), 0);
            healing.push(result);
            if result.0 == 0 {
                break;
            }
        }
        assert_eq!(healing.last().unwrap().0, 0, "healing did not quiesce");
        let expected = nodes[0].state().read().await.clone();
        assert_eq!(expected.len(), 3);
        for node in &nodes {
            assert_eq!(
                *node.state().read().await,
                expected,
                "partition did not heal"
            );
        }
        println!("replicas={n} partition_rounds={during_partition:?} healing_rounds={healing:?}");
        partitioned.store(true, Ordering::Relaxed);
        let left_key = SigningKey::generate_preferred().unwrap();
        let right_key = SigningKey::generate_preferred().unwrap();
        for (id, key) in [(0, &left_key), (n - 1, &right_key)] {
            nodes[id]
                .state()
                .write()
                .await
                .put(
                    Entry::Key(key.public().to_jwk_json()),
                    "R",
                    &Policy::default(),
                    0,
                    &clocks[id],
                )
                .unwrap();
        }
        let mut concurrent_partition = Vec::new();
        for _ in 0..2 {
            let result = round(&nodes, &mut rx, &counts).await;
            concurrent_partition.push((result, counts.failures.load(Ordering::Relaxed)));
        }
        assert!(
            concurrent_partition
                .iter()
                .any(|(_, failures)| *failures > 0)
        );
        for (id, node) in nodes.iter().enumerate() {
            let state = node.state();
            let state = state.read().await;
            let left = state.key(left_key.public().thumbprint()).is_some();
            let right = state.key(right_key.public().thumbprint()).is_some();
            assert_eq!((left, right), (id < n / 2, id >= n / 2));
        }
        partitioned.store(false, Ordering::Relaxed);
        let mut concurrent_healing = Vec::new();
        for _ in 0..8 {
            let result = round(&nodes, &mut rx, &counts).await;
            assert_eq!(counts.failures.load(Ordering::Relaxed), 0);
            concurrent_healing.push(result);
            if result.0 == 0 {
                break;
            }
        }
        assert_eq!(
            concurrent_healing.last().unwrap().0,
            0,
            "healing did not quiesce"
        );
        let expected = nodes[0].state().read().await.clone();
        assert_eq!(expected.len(), 5);
        for node in &nodes {
            assert_eq!(
                *node.state().read().await,
                expected,
                "concurrent updates diverged"
            );
        }
        println!(
            "replicas={n} concurrent_partition={concurrent_partition:?} concurrent_healing={concurrent_healing:?}"
        );
        let hash_len = TreeHash::for_signer(key.public().alg()).output_len();
        for (kind, left_iat, right_iat, left_byte, right_byte) in [
            ("different_time", 1000, 1001, 1, 2),
            ("equal_time", 1002, 1002, 3, 4),
        ] {
            partitioned.store(true, Ordering::Relaxed);
            let left = SignedVouch::issue(
                &key,
                "R",
                [Hash::from_slice(&[left_byte; 48][..hash_len]).unwrap()],
                left_iat,
                2000,
                None,
            )
            .unwrap();
            let right = SignedVouch::issue(
                &key,
                "R",
                [Hash::from_slice(&[right_byte; 48][..hash_len]).unwrap()],
                right_iat,
                2000,
                None,
            )
            .unwrap();
            let winner = if (left_iat, left.to_bytes()) > (right_iat, right.to_bytes()) {
                &left
            } else {
                &right
            };
            for (id, vouch) in [(0, &left), (n - 1, &right)] {
                nodes[id]
                    .state()
                    .write()
                    .await
                    .put(
                        Entry::Vouch(vouch.clone()),
                        "R",
                        &Policy::default(),
                        right_iat,
                        &clocks[id],
                    )
                    .unwrap();
            }
            let mut conflict_partition = Vec::new();
            for _ in 0..2 {
                let result = round(&nodes, &mut rx, &counts).await;
                conflict_partition.push((result, counts.failures.load(Ordering::Relaxed)));
            }
            assert!(conflict_partition.iter().any(|(_, failures)| *failures > 0));
            for (id, node) in nodes.iter().enumerate() {
                let state = node.state();
                let state = state.read().await;
                let expected = if id < n / 2 { &left } else { &right };
                assert_eq!(state.vouch(key.public().thumbprint()), Some(expected));
            }
            partitioned.store(false, Ordering::Relaxed);
            let mut conflict_healing = Vec::new();
            for _ in 0..8 {
                let result = round(&nodes, &mut rx, &counts).await;
                assert_eq!(counts.failures.load(Ordering::Relaxed), 0);
                conflict_healing.push(result);
                if result.0 == 0 {
                    break;
                }
            }
            assert_eq!(
                conflict_healing.last().unwrap().0,
                0,
                "conflict repair did not quiesce"
            );
            let expected = nodes[0].state().read().await.clone();
            assert_eq!(expected.vouch(key.public().thumbprint()), Some(winner));
            for node in &nodes {
                assert_eq!(
                    *node.state().read().await,
                    expected,
                    "vouch conflict diverged"
                );
            }
            println!(
                "replicas={n} conflict_kind={kind} conflict_partition={conflict_partition:?} conflict_healing={conflict_healing:?}"
            );
        }
        lossy.store(true, Ordering::Relaxed);
        let loss_key = SigningKey::generate_preferred().unwrap();
        nodes[0]
            .state()
            .write()
            .await
            .put(
                Entry::Key(loss_key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                0,
                &clocks[0],
            )
            .unwrap();
        let mut loss_rounds = Vec::new();
        for _ in 0..3 {
            let result = round(&nodes, &mut rx, &counts).await;
            loss_rounds.push((
                result,
                counts.failures.load(Ordering::Relaxed),
                counts.delivered_request_bytes.load(Ordering::Relaxed),
            ));
        }
        let mut informed_after_loss = 0;
        for node in &nodes {
            if node
                .state()
                .read()
                .await
                .key(loss_key.public().thumbprint())
                .is_some()
            {
                informed_after_loss += 1;
            }
        }
        lossy.store(false, Ordering::Relaxed);
        let mut loss_recovery = Vec::new();
        for _ in 0..8 {
            let result = round(&nodes, &mut rx, &counts).await;
            assert_eq!(counts.failures.load(Ordering::Relaxed), 0);
            loss_recovery.push(result);
            if result.0 == 0 {
                break;
            }
        }
        assert_eq!(
            loss_recovery.last().unwrap().0,
            0,
            "loss recovery did not quiesce"
        );
        let expected = nodes[0].state().read().await.clone();
        assert!(expected.key(loss_key.public().thumbprint()).is_some());
        for node in &nodes {
            assert_eq!(
                *node.state().read().await,
                expected,
                "loss recovery diverged"
            );
        }
        println!(
            "replicas={n} loss_rounds={loss_rounds:?} informed_after_loss={informed_after_loss} loss_recovery={loss_recovery:?}"
        );
        response_loss.store(true, Ordering::Relaxed);
        let response_key = SigningKey::generate_preferred().unwrap();
        nodes[0]
            .state()
            .write()
            .await
            .put(
                Entry::Key(response_key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                0,
                &clocks[0],
            )
            .unwrap();
        let mut response_loss_rounds = Vec::new();
        for _ in 0..3 {
            let result = round(&nodes, &mut rx, &counts).await;
            response_loss_rounds.push((
                result,
                counts.failures.load(Ordering::Relaxed),
                counts.dropped_response_bytes.load(Ordering::Relaxed),
            ));
        }
        let mut informed_after_response_loss = 0;
        for node in &nodes {
            if node
                .state()
                .read()
                .await
                .key(response_key.public().thumbprint())
                .is_some()
            {
                informed_after_response_loss += 1;
            }
        }
        response_loss.store(false, Ordering::Relaxed);
        let mut response_recovery = Vec::new();
        for _ in 0..8 {
            let result = round(&nodes, &mut rx, &counts).await;
            assert_eq!(counts.failures.load(Ordering::Relaxed), 0);
            response_recovery.push(result);
            if result.0 == 0 {
                break;
            }
        }
        assert_eq!(
            response_recovery.last().unwrap().0,
            0,
            "response loss recovery did not quiesce"
        );
        let expected = nodes[0].state().read().await.clone();
        assert!(expected.key(response_key.public().thumbprint()).is_some());
        for node in &nodes {
            assert_eq!(
                *node.state().read().await,
                expected,
                "response loss recovery diverged"
            );
        }
        println!(
            "replicas={n} response_loss_rounds={response_loss_rounds:?} informed_after_response_loss={informed_after_response_loss} response_recovery={response_recovery:?}"
        );
        for task in tasks {
            task.abort();
        }
    }
}
