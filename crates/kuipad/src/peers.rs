//! The anchor exchange (§4.2): agirru gossip between servers over
//! `POST /ipa/ku/peer/sync`, each request authenticated with the sending
//! server's `ipa-ku/<fqdn>` Kerberos key.
//!
//! Members are the IPA servers in LDAP (`cn=masters`) plus configured
//! peers; outbound repair targets topology neighbors and configured peers.
//! After every change the exchange renews this server's claim when
//! due, has its anchor vouch for every claim it trusts (one signature over
//! a Merkle tree), and publishes its claim, with every trusted anchor's
//! proof, and the trusted anchors to the [`EnrollServer`].

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use agirru_crdt::GenerationClock;
use agirru_engine::context::{Attached, Context, ContextError, ContextReceiver, ContextSender};
use agirru_engine::repair::{self, IndexCache, RepairError, Replica};
use agirru_engine::snapshot::{
    self, SnapshotLimits, SnapshotReplica, SnapshotRequest, SnapshotResponse, SnapshotServer,
};
use agirru_engine::{
    CborCodec, DurableState, GossipConfig, GossipEngine, GossipHooks, GossipRuntime, Membership,
    SendOutcome, Storage, Transport,
};
use kuipa_enroll::EnrollServer;
use kuipa_enroll::anchors::{self, AnchorState, Entry, PeerSync, Trust};
use kuipa_enroll::delegation::{
    Claim, DEFAULT_VALIDITY, Delegation, SignedSuccession, SignedVouch, VOUCH_VALIDITY,
};
use kuipa_enroll::epoch::{self, AnchorEpoch, SignedEpoch};
use kuipa_enroll::merkle::TreeHash;
use kuipa_enroll::server::Directory;
use tang_pqc::{Policy, SigningKey, Thumbprint, unix_seconds};
use tokio::sync::{Notify, RwLock};

use crate::keystore::KeyStore;

/// Errors from the exchange.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Produces GSS-API tokens from this server's `ipa-ku/<fqdn>` key.
pub trait Initiator: Send + Sync {
    /// An initial token for `ipa-ku@<peer>` with channel binding `cb`.
    ///
    /// # Errors
    ///
    /// Any GSS-API failure.
    fn token(&self, peer: &str, cb: &[u8; 32]) -> Result<Vec<u8>, Error>;
}

/// An [`Initiator`] using a keytab.  Its ccache is private to it (one per
/// principal) and used by one thread at a time.
#[derive(Debug)]
pub struct KeytabInitiator {
    keytab: String,
    principal: String,
    lock: Mutex<()>,
}

impl KeytabInitiator {
    /// Tokens for `principal` (`ipa-ku/<fqdn>@REALM`) from `keytab`.
    #[must_use]
    pub fn new(keytab: impl Into<String>, principal: impl Into<String>) -> Self {
        Self {
            keytab: keytab.into(),
            principal: principal.into(),
            lock: Mutex::new(()),
        }
    }
}

impl Initiator for KeytabInitiator {
    fn token(&self, peer: &str, cb: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let _guard = lock(&self.lock);
        let cred = kuipa_gssapi::GssClientCred::from_client_keytab(
            &self.keytab,
            Some(&self.principal),
            Some(&format!("MEMORY:kuipa-peer-{}", self.principal)),
        )?;
        match kuipa_gssapi::init_token(&cred, &format!("ipa-ku@{peer}"), Some(cb))? {
            kuipa_gssapi::InitStep::Complete(t) => Ok(t),
            kuipa_gssapi::InitStep::Continue { .. } => {
                Err("GSS-API exchange needs more than one token".into())
            }
        }
    }
}

/// Exchange settings.
#[derive(Clone, Debug)]
pub struct Settings {
    /// This server's FQDN.
    pub me: String,
    /// Kerberos realm.
    pub realm: String,
    /// Configured peers.
    pub peers: Vec<String>,
    /// Also use the IPA servers listed in the directory.
    pub discover: bool,
    /// Base URLs by FQDN, instead of `https://<fqdn>`.
    pub endpoints: BTreeMap<String, String>,
    /// Time between rounds.
    pub interval: Duration,
    /// IPA CA certificates (DER) for the peers' TLS certificates.
    pub ca_certs: Vec<Vec<u8>>,
    /// Least time between vouches that only add claims (removals and
    /// this server's own renewals are vouched for at once).
    pub vouch_interval: Duration,
}

/// A failed send, classified for the gossip engine.
#[derive(Debug)]
pub enum PeerError {
    /// The peer refused the sync (`401`/`403`).
    Rejected,
    /// The peer temporarily cannot accept another repair.
    Busy,
    /// The peer does not hold the delegation or epoch window a sync left
    /// out (`409`); resend them.
    NeedContext,
    /// Anything else.
    Failed(String),
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => f.write_str("the peer refused the sync"),
            Self::Busy => f.write_str("the peer is busy"),
            Self::NeedContext => {
                f.write_str("the peer needs the sync's delegation and epoch window")
            }
            Self::Failed(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for PeerError {}

fn failed(e: impl fmt::Display) -> PeerError {
    PeerError::Failed(e.to_string())
}

fn now() -> u64 {
    unix_seconds(SystemTime::now())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

const MAX_SYNC_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_REPAIRS: usize = 16;

const GOSSIP_FANOUT: usize = 4;
const REPAIR_SWEEP_ROUNDS: u32 = 10;
const MAX_BUSY_RETRIES: u8 = 3;
const REPAIR_STALL_DELAY: Duration = Duration::from_secs(1);
/// Bytes per snapshot chunk.
const CHUNK_BYTES: usize = 128 * 1024;
/// States differing by more than this many entries are transferred whole
/// rather than entry by entry.
const BULK_ABOVE: usize = 4096;
/// Entry-wise repairs tried per peer before reporting a concurrent change.
const MAX_SELECTIVE_ATTEMPTS: usize = 2;
/// Domain of the repair index digest.
const INDEX_DOMAIN: &[u8] = b"ipa-ku/anchor-repair/v1\0";

/// Entry-wise repair bounds, within [`MAX_SYNC_BYTES`] per message.
fn repair_limits() -> repair::Limits {
    repair::Limits {
        message_budget: 256 * 1024,
        max_want_per_request: 8192,
        bulk_above: Some(BULK_ABOVE),
        ..repair::Limits::default()
    }
}

/// Whole-state transfer bounds.
fn snapshot_limits() -> SnapshotLimits {
    SnapshotLimits {
        chunk_bytes: CHUNK_BYTES,
        max_snapshot_bytes: 64 * 1024 * 1024,
        max_uploading_bytes: 64 * 1024 * 1024,
        upload_lifetime: Duration::from_secs(120),
        ..SnapshotLimits::default()
    }
}

/// SHA-256 through native-ossl, for the repair index.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256;

impl repair::Hasher for Sha256 {
    fn hash(&self, parts: &[&[u8]]) -> Result<repair::Hash, Error> {
        Ok(tang_pqc::primitives::sha256(parts)?)
    }
}

/// One entry as it travels: an [`AnchorState`] encoding holding it (and,
/// for a vouch, the anchor key it is checked against).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct WireEntry(#[serde(with = "repair::cbor_bytes")] Vec<u8>);

/// The reconciliation message a sync carries, bound to the sync by its
/// nonce: the answer echoes it.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Message<B> {
    #[serde(rename = "n", with = "repair::cbor_bytes::array")]
    nonce: [u8; 32],
    #[serde(rename = "b")]
    body: B,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum RequestBody {
    #[serde(rename = "r")]
    Repair(repair::Request<WireEntry>),
    #[serde(rename = "s")]
    Snapshot(SnapshotRequest),
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
enum ResponseBody {
    #[serde(rename = "r")]
    Repair(repair::Response<WireEntry>),
    #[serde(rename = "s")]
    Snapshot(SnapshotResponse),
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    Ok(ciborium::from_reader(bytes)?)
}

/// A sender's own delegation, as sync context.
#[derive(Clone, PartialEq)]
struct OwnContext(Delegation);

impl Context for OwnContext {
    fn context_hash(&self) -> Result<repair::Hash, Error> {
        Ok(PeerSync::delegation_hash(&self.0)?)
    }
}

/// A sender's epoch window, as sync context.
#[derive(Clone, PartialEq)]
struct ChainContext(Vec<Vec<u8>>);

impl Context for ChainContext {
    fn context_hash(&self) -> Result<repair::Hash, Error> {
        Ok(PeerSync::chain_hash(&self.0)?)
    }
}

/// A [`RepairError`] as an exchange error, keeping a transport
/// [`PeerError`] downcastable.
fn from_repair(e: RepairError) -> Error {
    match e {
        RepairError::Busy => PeerError::Busy.into(),
        RepairError::Transport(inner) => inner,
        other => other.into(),
    }
}

fn to_storage(e: impl Into<Error>) -> RepairError {
    RepairError::Storage(e.into())
}

fn to_entry(e: impl Into<Error>) -> RepairError {
    RepairError::Entry(e.into())
}

fn repair_concurrency(members: usize) -> usize {
    (MAX_CONCURRENT_REPAIRS / members.saturating_sub(1).max(1)).max(1)
}

fn selected_peers<'a>(
    members: &'a BTreeSet<String>,
    me: &str,
    cursor: &mut Option<usize>,
    sweep: bool,
) -> Vec<&'a String> {
    let mut peers: Vec<_> = members.iter().filter(|peer| peer.as_str() != me).collect();
    if !peers.is_empty() {
        let len = peers.len();
        let start = *cursor
            .get_or_insert_with(|| members.iter().position(|peer| peer == me).unwrap_or(0) % len);
        let count = if sweep { len } else { GOSSIP_FANOUT.min(len) };
        peers.rotate_left(start % len);
        peers.truncate(count);
        *cursor = Some((start + count) % len);
    }
    peers
}

/// The state shared by the gossip engine, the maintenance task and the
/// sync route.  Implements agirru's transport, membership, storage and
/// hooks.
pub struct Exchange {
    settings: Settings,
    /// This server's anchor; `None` without the anchor role.
    anchor: Option<SigningKey>,
    policy: Policy,
    server: Arc<EnrollServer>,
    directory: Arc<dyn Directory + Send + Sync>,
    initiator: Arc<dyn Initiator>,
    store: KeyStore,
    state: Arc<RwLock<AnchorState>>,
    clock: GenerationClock,
    /// Every member, this server included, and when the directory was last
    /// asked.
    members: Mutex<(BTreeSet<String>, Option<Instant>)>,
    /// Outbound targets, independently refreshed from replication topology.
    neighbors: Mutex<BTreeSet<String>>,
    /// Peers' own delegations from authenticated syncs.
    attested: Mutex<BTreeMap<String, Delegation>>,
    /// The anchor epoch log (§4.8).
    epoch: Mutex<Vec<SignedEpoch>>,
    /// The log of another server disagrees with ours at a sequence both
    /// have: appending is paused until the two are reconciled.
    forked: AtomicBool,
    /// The contents the next epoch entry would carry and when they
    /// were first seen: minting waits for a full round of stability.
    settling: Mutex<Option<(kuipa_enroll::epoch::EpochHead, Instant)>>,
    changed: Notify,
    repair_trigger: Notify,
    repair_permits: tokio::sync::Semaphore,
    /// Snapshot downloads in progress and unfinished uploads.
    snapshots: SnapshotServer<String>,
    /// Each member's last delegation and epoch window from an
    /// authenticated sync, so its later syncs can leave them out.
    own_seen: ContextReceiver<String, OwnContext>,
    chain_seen: ContextReceiver<String, ChainContext>,
    /// Per peer, the delegation and window it last accepted from this
    /// server.
    own_sent: ContextSender<String, OwnContext>,
    chain_sent: ContextSender<String, ChainContext>,
    client: reqwest::Client,
    /// The last failure per peer, so each is logged once.
    failures: Mutex<BTreeMap<String, String>>,
}

type Engine = GossipEngine<AnchorState, String, Runtime, Arc<Exchange>>;

/// The running exchange.
pub struct Peers {
    exchange: Arc<Exchange>,
    engine: Arc<Engine>,
    /// The repair index of the durable state, kept current incrementally.
    index: IndexCache<anchors::EntryId, Sha256>,
    #[cfg(test)]
    repair_started: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    repair_completed: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    repair_failed: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    repair_peak: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    bench_control: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<bool>>>,
    #[cfg(test)]
    bench_rounds: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    bench_idle: AtomicBool,
    #[cfg(test)]
    bench_retries: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    bench_busy: std::sync::atomic::AtomicUsize,
}

/// The delegation to start with: the stored one if it is still for this
/// server's `signing` key and, with an `anchor`, still verifies under it;
/// else a new claim, proven by the anchor if there is one (a server without
/// the anchor role waits for other servers' anchors to vouch for it).  It
/// carries the successions of this server's rotated anchors (§4.7).
///
/// # Errors
///
/// Key store or signing errors.
pub fn initial_delegation(
    store: &KeyStore,
    anchor: Option<&SigningKey>,
    realm: &str,
    fqdn: &str,
    signing: &tang_pqc::VerifyingKey,
) -> Result<Delegation, Error> {
    let at = now();
    if let Some(d) = store.delegation()? {
        let usable = match anchor {
            Some(a) => d
                .verify_at(&[*a.public().thumbprint()], &Policy::from_system()?, at)
                .is_ok_and(|v| v.key == *signing.thumbprint() && v.server == fqdn),
            None => d.claim().is_ok_and(|c| {
                c.key == *signing.thumbprint() && c.server == fqdn && c.anchor.is_none()
            }),
        };
        if usable {
            let mut d = d;
            d.add_successions(store.successions()?);
            return Ok(d);
        }
    }
    let mut d = match anchor {
        Some(a) => Delegation::issue(a, realm, fqdn, signing, at, at + DEFAULT_VALIDITY)?,
        None => Delegation::new(&Claim {
            realm: realm.into(),
            server: fqdn.into(),
            anchor: None,
            key: *signing.thumbprint(),
            iat: at,
            exp: at + DEFAULT_VALIDITY,
        }),
    };
    d.add_successions(store.successions()?);
    Ok(d)
}

fn http_client(settings: &Settings) -> Result<reqwest::Client, Error> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls_native_ossl::default_provider().install_default();
    });
    let provider = Arc::new(rustls_native_ossl::default_provider());
    let verifier = kuipa_enroll::tls::server_verifier(&settings.ca_certs)?;
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .tls_backend_preconfigured(tls)
        .build()?)
}

impl Peers {
    /// Set up the exchange for `server`, with the state from `store`.
    ///
    /// # Errors
    ///
    /// Key store errors or an unusable CA.
    pub fn new(
        settings: Settings,
        anchor: Option<SigningKey>,
        server: Arc<EnrollServer>,
        directory: Arc<dyn Directory + Send + Sync>,
        initiator: Arc<dyn Initiator>,
        store: KeyStore,
    ) -> Result<Arc<Self>, Error> {
        let clock = GenerationClock::new();
        let mut loaded = store.peer_state()?;
        loaded.rebase_generations(&clock);
        let state = Arc::new(RwLock::new(loaded));
        let chain = store.epoch()?;
        let neighbors: BTreeSet<String> = settings
            .peers
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let mut members = neighbors.clone();
        members.insert(settings.me.clone());
        let exchange = Arc::new(Exchange {
            client: http_client(&settings)?,
            settings,
            anchor,
            policy: Policy::from_system()?,
            server,
            directory,
            initiator,
            store,
            state: state.clone(),
            clock: clock.clone(),
            members: Mutex::new((members, None)),
            neighbors: Mutex::new(neighbors),
            attested: Mutex::new(BTreeMap::new()),
            epoch: Mutex::new(chain.clone()),
            forked: AtomicBool::new(false),
            settling: Mutex::new(None),
            changed: Notify::new(),
            repair_trigger: Notify::new(),
            repair_permits: tokio::sync::Semaphore::new(MAX_CONCURRENT_REPAIRS),
            snapshots: SnapshotServer::new(),
            own_seen: ContextReceiver::new(),
            chain_seen: ContextReceiver::new(),
            own_sent: ContextSender::new(),
            chain_sent: ContextSender::new(),
            failures: Mutex::new(BTreeMap::new()),
        });
        exchange.server.publish_epoch(chain);
        let config = GossipConfig {
            round_interval: exchange.settings.interval,
            ..GossipConfig::default()
        };
        let durable = DurableState::new(state, clock, exchange.clone());
        let engine = Arc::new(GossipEngine::new(
            Arc::new(durable),
            Runtime(exchange.clone(), CborCodec),
            config,
        ));
        Ok(Arc::new(Self {
            exchange,
            engine,
            index: IndexCache::new(),
            #[cfg(test)]
            repair_started: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            repair_completed: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            repair_failed: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            repair_peak: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            bench_control: Mutex::new(None),
            #[cfg(test)]
            bench_rounds: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            bench_idle: AtomicBool::new(false),
            #[cfg(test)]
            bench_retries: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            bench_busy: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    /// Run the gossip rounds and the maintenance loop forever.
    pub async fn run(self: Arc<Self>) {
        let worker = self.clone();
        tokio::spawn(async move { worker.repair_loop().await });
        loop {
            if let Err(e) = self.refresh().await {
                eprintln!("kuipad: anchor exchange: {e}");
            }
            tokio::select! {
                () = self.exchange.changed.notified() => {}
                () = tokio::time::sleep(self.exchange.settings.interval) => {}
            }
        }
    }

    async fn repair_loop(self: Arc<Self>) {
        #[cfg(test)]
        let mut control = lock(&self.bench_control).take();
        #[cfg(not(test))]
        let mut control: Option<tokio::sync::mpsc::UnboundedReceiver<bool>> = None;
        #[cfg(test)]
        let automatic = control.is_none();
        #[cfg(not(test))]
        let automatic = true;
        let mut ordinary = tokio::time::interval(self.exchange.settings.interval);
        let mut comprehensive = tokio::time::interval(
            self.exchange
                .settings
                .interval
                .saturating_mul(REPAIR_SWEEP_ROUNDS),
        );
        let mut retry_tick = tokio::time::interval(Duration::from_millis(250));
        for timer in [&mut ordinary, &mut comprehensive, &mut retry_tick] {
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        }
        let mut pending: VecDeque<String> = VecDeque::new();
        let mut running = tokio::task::JoinSet::new();
        let mut active: HashMap<tokio::task::Id, (String, Instant)> = HashMap::new();
        let mut retries: HashMap<String, (Instant, u8)> = HashMap::new();
        let mut cursor = None;
        let mut base_concurrency = 1;
        loop {
            #[cfg(test)]
            self.bench_idle.store(
                pending.is_empty() && running.is_empty() && retries.is_empty(),
                Ordering::Release,
            );
            let stalled = active
                .values()
                .filter(|(_, started)| started.elapsed() >= REPAIR_STALL_DELAY)
                .count();
            let concurrency = (base_concurrency + stalled).min(MAX_CONCURRENT_REPAIRS);
            while running.len() < concurrency {
                let Some(peer) = pending.pop_front() else {
                    break;
                };
                let worker = self.clone();
                let name = peer.clone();
                let task = running.spawn(async move { worker.repair_peer(&name).await });
                #[cfg(test)]
                {
                    self.repair_started.fetch_add(1, Ordering::Relaxed);
                    if retries.contains_key(&peer) {
                        self.bench_retries.fetch_add(1, Ordering::Relaxed);
                    }
                    self.repair_peak.fetch_max(running.len(), Ordering::Relaxed);
                }
                active.insert(task.id(), (peer, Instant::now()));
            }
            let sweep = tokio::select! {
                _ = ordinary.tick(), if automatic => Some(false),
                _ = comprehensive.tick(), if automatic => Some(true),
                () = self.exchange.repair_trigger.notified(), if automatic => Some(false),
                command = async { control.as_mut().expect("manual control").recv().await }, if !automatic => {
                    match command {
                        Some(sweep) => {
                            #[cfg(test)]
                            self.bench_idle.store(false, Ordering::Release);
                            Some(sweep)
                        }
                        None => return,
                    }
                },
                _ = retry_tick.tick() => None,
                Some(result) = running.join_next_with_id(), if !running.is_empty() => {
                    self.finish_repair(result, &mut active, &mut retries);
                    continue;
                }
            };
            self.exchange.refresh_members().await;
            let members = self.exchange.members();
            base_concurrency = repair_concurrency(members.len());
            self.exchange
                .snapshots
                .retain(|peer| members.contains(peer));
            let neighbors = self.exchange.neighbors();
            pending.retain(|peer| neighbors.contains(peer));
            retries.retain(|peer, _| neighbors.contains(peer));
            self.queue_repairs(
                &neighbors,
                &mut pending,
                &active,
                &retries,
                &mut cursor,
                sweep,
            );
            #[cfg(test)]
            if !automatic && sweep.is_some() {
                self.bench_rounds.fetch_add(1, Ordering::Release);
            }
        }
    }

    fn queue_repairs(
        &self,
        members: &BTreeSet<String>,
        pending: &mut VecDeque<String>,
        active: &HashMap<tokio::task::Id, (String, Instant)>,
        retries: &HashMap<String, (Instant, u8)>,
        cursor: &mut Option<usize>,
        sweep: Option<bool>,
    ) {
        let mut enqueue = |peer: &String| {
            if peer != &self.exchange.settings.me
                && !pending.contains(peer)
                && !active.values().any(|(running, _)| running == peer)
            {
                pending.push_back(peer.clone());
            }
        };
        for (peer, (at, _)) in retries {
            if *at <= Instant::now() {
                enqueue(peer);
            }
        }
        if let Some(sweep) = sweep {
            for peer in selected_peers(members, &self.exchange.settings.me, cursor, sweep) {
                if !retries.contains_key(peer) {
                    enqueue(peer);
                }
            }
        }
    }

    fn finish_repair(
        &self,
        result: Result<(tokio::task::Id, Result<(), Error>), tokio::task::JoinError>,
        active: &mut HashMap<tokio::task::Id, (String, Instant)>,
        retries: &mut HashMap<String, (Instant, u8)>,
    ) {
        let id = match &result {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        #[cfg(test)]
        {
            if !matches!(&result, Ok((_, Ok(())))) {
                self.repair_failed.fetch_add(1, Ordering::Relaxed);
            }
            self.repair_completed.fetch_add(1, Ordering::Release);
        }
        if let Some((peer, _)) = active.remove(&id) {
            match result {
                Ok((_, result)) => {
                    let busy = result.as_ref().err().is_some_and(|error| {
                        matches!(error.downcast_ref::<PeerError>(), Some(PeerError::Busy))
                    });
                    if busy {
                        let attempts = retries.get(&peer).map_or(0, |(_, n)| *n);
                        if attempts < MAX_BUSY_RETRIES {
                            use std::hash::{Hash, Hasher};
                            let mut hash = std::collections::hash_map::DefaultHasher::new();
                            (&self.exchange.settings.me, &peer, attempts).hash(&mut hash);
                            let delay = 250 * (1u64 << attempts) + hash.finish() % 250;
                            retries.insert(
                                peer.clone(),
                                (Instant::now() + Duration::from_millis(delay), attempts + 1),
                            );
                        } else {
                            retries.remove(&peer);
                        }
                    } else {
                        retries.remove(&peer);
                    }
                    self.exchange
                        .note(&peer, &result.map(|()| Vec::new()).map_err(failed));
                }
                Err(error) => self.exchange.note(&peer, &Err(failed(error))),
            }
        }
    }

    /// Repair with `peer` entry by entry (`agirru_engine::repair`), or by
    /// whole-state transfer (`agirru_engine::snapshot`) when the two states
    /// differ by more than [`BULK_ABOVE`] entries. A concurrent write on
    /// either side repeats the entry-wise repair.
    async fn repair_peer(&self, peer: &str) -> Result<(), Error> {
        let limits = repair_limits();
        for _ in 0..MAX_SELECTIVE_ATTEMPTS {
            let stats = repair::repair(self, peer, &limits, |request| async move {
                match self.call(peer, RequestBody::Repair(request)).await? {
                    ResponseBody::Repair(response) => Ok(response),
                    ResponseBody::Snapshot(_) => {
                        Err(RepairError::Protocol("unexpected peer snapshot answer"))
                    }
                }
            })
            .await
            .map_err(from_repair)?;
            if stats.converged {
                return Ok(());
            }
            if stats.bulk {
                return self.transfer_snapshot(peer).await;
            }
        }
        Err("peer repair state changed concurrently".into())
    }

    async fn transfer_snapshot(&self, peer: &str) -> Result<(), Error> {
        let stats = snapshot::transfer(self, peer, &snapshot_limits(), |request| async move {
            match self.call(peer, RequestBody::Snapshot(request)).await? {
                ResponseBody::Snapshot(response) => Ok(response),
                ResponseBody::Repair(_) => {
                    Err(RepairError::Protocol("unexpected peer repair answer"))
                }
            }
        })
        .await
        .map_err(from_repair)?;
        if stats.converged {
            Ok(())
        } else {
            Err("peer repair remains unreconciled".into())
        }
    }

    /// One authenticated round trip with `peer`.
    async fn call(&self, peer: &str, body: RequestBody) -> Result<ResponseBody, RepairError> {
        let mut nonce = [0; 32];
        native_ossl::rand::Rand::fill_private(&mut nonce).map_err(to_storage)?;
        let payload = encode(&Message { nonce, body }).map_err(to_entry)?;
        let own = {
            let state = self.exchange.state.read().await;
            self.exchange.own_delegation(&state)
        }
        .map_err(|e| RepairError::Transport(Box::new(e)))?;
        let response = self
            .exchange
            .sync(peer, payload, own)
            .await
            .map_err(|e| RepairError::Transport(Box::new(e)))?;
        let response: Message<ResponseBody> = decode(&response).map_err(to_entry)?;
        if response.nonce != nonce {
            return Err(RepairError::Protocol("peer repair response nonce mismatch"));
        }
        Ok(response.body)
    }

    /// Drop expired entries and those of removed servers from `state`.
    fn retain_live(&self, state: &mut AnchorState, members: &BTreeSet<String>, at: u64) {
        let x = &self.exchange;
        let before = state.len();
        state.retain(members, &x.settings.realm, &x.policy, at);
        if state.len() < before {
            // Dropped without a new generation: the repair index must not
            // keep listing them.
            self.index.invalidate();
        }
    }

    /// One maintenance pass: drop expired and removed entries, renew this
    /// server's delegation when due, cosign what it trusts, and publish.
    ///
    /// # Errors
    ///
    /// Signing or key store errors.
    pub async fn refresh(&self) -> Result<(), Error> {
        let x = &self.exchange;
        x.refresh_members().await;
        let (me, realm) = (&x.settings.me, &x.settings.realm);
        let at = now();
        let members = x.members();
        let attested: Vec<Delegation> = {
            let mut a = lock(&x.attested);
            a.retain(|server, _| members.contains(server));
            a.values().cloned().collect()
        };
        let own_anchor = x.anchor.as_ref().map(|a| *a.public().thumbprint());
        let signing = x.server.keys().signing.public().clone();
        let put = |state: &mut AnchorState, entry| state.put(entry, realm, &x.policy, at, &x.clock);

        let mut guard = x.state.write().await;
        let mut state = guard.clone();
        self.retain_live(&mut state, &members, at);
        let mut wrote = false;
        if let Some(anchor) = &x.anchor {
            wrote |= put(&mut state, Entry::Key(anchor.public().to_jwk_json()))?;
        }
        // This server is the source of its rotated anchors' successions.
        for s in x.store.successions()? {
            if s.check(realm, &x.policy, at).is_ok() {
                wrote |= put(&mut state, Entry::Succession(s))?;
            }
        }
        let own = match state.latest_claim(me, own_anchor.as_ref()) {
            Some(c) if !anchors::needs_renewal(Some(c), signing.thumbprint(), at) => c.clone(),
            _ => {
                let c = Claim {
                    realm: realm.clone(),
                    server: me.clone(),
                    anchor: own_anchor,
                    key: *signing.thumbprint(),
                    iat: at,
                    exp: at + DEFAULT_VALIDITY,
                };
                wrote |= put(&mut state, Entry::Claim(c.clone()))?;
                c
            }
        };
        let trust = Trust::compute(&state, &own, &attested, &members, &x.policy, at)?;
        if let Some(anchor) = &x.anchor {
            let leaves = trust.leaves(TreeHash::for_signer(anchor.public().alg()))?;
            let current_vouch = state.vouch(anchor.public().thumbprint());
            let interval = x.settings.vouch_interval.as_secs();
            if anchors::needs_vouch(current_vouch, &leaves, at, interval) {
                let iat = anchors::next_vouch_iat(current_vouch, at);
                let previous = current_vouch.cloned();
                eprintln!(
                    "kuipad: anchor exchange: vouching for {} claim(s) of {:?}",
                    leaves.len(),
                    trust.servers().collect::<Vec<_>>()
                );
                let vouch = SignedVouch::issue(
                    anchor,
                    realm,
                    leaves,
                    iat,
                    iat + VOUCH_VALIDITY,
                    previous.as_ref(),
                )?;
                wrote |= put(&mut state, Entry::Vouch(vouch))?;
            }
        }
        let candidate = trust.own_delegation(&state)?;
        let epoch_successions: Vec<SignedSuccession> = state.successions().cloned().collect();
        let published_vouches: HashMap<Thumbprint, SignedVouch> = state
            .vouches()
            .filter(|v| trust.anchors().contains(&v.vouch().anchor))
            .map(|v| (v.vouch().anchor, v.clone()))
            .collect();
        x.store.store_peer_state(&state)?;
        *guard = state;
        drop(guard);
        if wrote {
            x.repair_trigger.notify_one();
        }

        let current = x.server.delegation();
        let advertised = anchors::prefer(Some(current.clone()), candidate, at);
        let trusted = trust.anchors();
        let vouches = published_vouches;
        if advertised != current {
            x.store.store_delegation(&advertised)?;
        }
        if advertised != current || trusted != x.server.anchors() || x.server.vouches() != vouches {
            eprintln!(
                "kuipad: anchor exchange: trusted anchors: {}, proofs for this server's claim: {}",
                trusted.len(),
                advertised.proof_count()
            );
            x.server.publish(advertised, trusted.clone(), vouches);
        }
        // §4.8: with the anchor role, keep the anchor epoch log current.
        if let Some(anchor) = &x.anchor {
            mint_epoch(x, realm, anchor, &trusted, &epoch_successions)?;
        }
        Ok(())
    }

    /// `POST /ipa/ku/peer/sync`: authenticate the sender, record its own
    /// delegation as attested, and answer with this server's state.
    ///
    /// # Errors
    ///
    /// A malformed request, a token that does not authenticate the sender,
    /// or a sender that is not a member.
    pub async fn handle(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        if body.len() > MAX_SYNC_BYTES {
            return Err("peer repair request exceeds size limit".into());
        }
        let x = &self.exchange;
        let _permit = x
            .repair_permits
            .try_acquire()
            .map_err(|_| PeerError::Busy)?;
        let (sync, own, sync_chain) = self.authenticate_sync(body).await?;
        #[cfg(test)]
        let busy = {
            let mut remaining = self.bench_busy.load(Ordering::Relaxed);
            loop {
                if remaining == 0 {
                    break false;
                }
                match self.bench_busy.compare_exchange_weak(
                    remaining,
                    remaining - 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break true,
                    Err(actual) => remaining = actual,
                }
            }
        };
        #[cfg(test)]
        if busy {
            return Err(PeerError::Busy.into());
        }
        let message: Message<RequestBody> = decode(&sync.payload)?;
        let fresh = lock(&x.attested).insert(sync.sender.clone(), own.clone()) != Some(own);
        if fresh {
            x.changed.notify_one();
        }
        self.merge_peer_epoch(&sync, &sync_chain).await?;
        let body = match message.body {
            RequestBody::Repair(request) => ResponseBody::Repair(
                repair::respond(self, sync.sender.as_str(), request, &repair_limits())
                    .await
                    .map_err(from_repair)?,
            ),
            RequestBody::Snapshot(request) => ResponseBody::Snapshot(
                x.snapshots
                    .respond(self, sync.sender.as_str(), request, &snapshot_limits())
                    .await
                    .map_err(from_repair)?,
            ),
        };
        let bytes = encode(&Message {
            nonce: message.nonce,
            body,
        })?;
        if bytes.len() > MAX_SYNC_BYTES {
            return Err("peer repair response exceeds size limit".into());
        }
        Ok(bytes)
    }

    async fn authenticate_sync(
        &self,
        body: &[u8],
    ) -> Result<(PeerSync, Delegation, Vec<Vec<u8>>), Error> {
        let x = &self.exchange;
        let sync = PeerSync::from_bytes(body)?;
        let cb = PeerSync::channel_binding(
            &sync.sender,
            &sync.receiver,
            &sync.own_hash,
            &sync.payload,
            &sync.chain_hash,
        )?;
        let directory = x.directory.clone();
        let token = sync.token.clone();
        let principal =
            tokio::task::spawn_blocking(move || directory.accept_peer(&token, &cb)).await??;
        x.refresh_members().await;
        // Left-out content comes from this sender's earlier authenticated
        // syncs, and is then checked exactly as if it had been sent.
        let needed = |e: ContextError| -> Error {
            match e {
                ContextError::Needed => PeerError::NeedContext.into(),
                other => other.into(),
            }
        };
        let own = x
            .own_seen
            .resolve(
                &sync.sender,
                Attached {
                    hash: sync.own_hash,
                    value: sync.own.clone().map(OwnContext),
                },
            )
            .map_err(needed)?;
        let sync_chain = x
            .chain_seen
            .resolve(
                &sync.sender,
                Attached {
                    hash: sync.chain_hash,
                    value: sync.chain.clone().map(ChainContext),
                },
            )
            .map_err(needed)?;
        let members = x.members();
        let own_attested = sync.attest(
            &own.value().0,
            &principal,
            &anchors::PeerAttestation {
                me: &x.settings.me,
                servers: &members,
                realm: &x.settings.realm,
                policy: &x.policy,
                now: now(),
            },
        )?;
        x.own_seen.retain(|peer| members.contains(peer));
        x.chain_seen.retain(|peer| members.contains(peer));
        let sync_chain_value = sync_chain.value().0.clone();
        x.own_seen.accept(&sync.sender, own);
        x.chain_seen.accept(&sync.sender, sync_chain);
        Ok((sync, own_attested, sync_chain_value))
    }

    async fn merge_peer_epoch(&self, sync: &PeerSync, sync_chain: &[Vec<u8>]) -> Result<(), Error> {
        let x = &self.exchange;
        // §4.8: merge the peer's window of the anchor epoch log:
        // shared entries keep both signature sets, a window that
        // continues our log is adopted, a window that jumps past our
        // end is fetched, and a disagreement on a sequence both have
        // pauses appending — two servers must not keep extending
        // divergent histories.
        let theirs: Vec<SignedEpoch> = sync_chain
            .iter()
            .map(|b| epoch::decode(b))
            .collect::<std::result::Result<_, _>>()?;
        let mut gap = false;
        if !theirs.is_empty() {
            let mut chain = lock(&x.epoch);
            let (merged, outcome) = merge_chain(&x.settings.realm, &x.policy, &chain, &theirs);
            if merged != *chain {
                // Store before committing in memory: an unstored log is
                // not a record, and a failed write then retries next
                // round instead of advertising from memory alone.
                x.store.store_epoch(&merged).map_err(failed)?;
                *chain = merged;
                x.server.publish_epoch(chain.clone());
                x.changed.notify_one();
            }
            drop(chain);
            match outcome {
                Merge::Conflict => {
                    if !x.forked.swap(true, Ordering::Relaxed) {
                        eprintln!(
                            "kuipad: anchor exchange: {}'s anchor log disagrees with ours at a sequence both have; this server will not extend its own until they are reconciled",
                            sync.sender
                        );
                    }
                    return Err("peer anchor log conflicts with local log".into());
                }
                Merge::Gap => gap = true,
                Merge::Invalid => return Err("invalid peer anchor log window".into()),
                Merge::Kept | Merge::Extended => {}
            }
        }
        if gap {
            let expected = theirs
                .first()
                .ok_or("missing anchor log window")?
                .statement()?;
            x.catch_up(&sync.sender).await?;
            let chain = lock(&x.epoch);
            let found = chain.iter().find_map(|entry| {
                entry
                    .statement()
                    .ok()
                    .filter(|statement| statement.seq() == expected.seq())
            });
            if found.as_ref() != Some(&expected) {
                return Err("anchor log catch-up did not reach the advertised entry".into());
            }
        }
        Ok(())
    }
}

/// The repair summary of every entry of `state`.
fn summaries(state: &AnchorState) -> Result<Vec<(repair::Summary, anchors::EntryId)>, RepairError> {
    Ok(state
        .entry_versions()
        .map_err(to_entry)?
        .into_iter()
        .map(|(id, version, kind)| {
            (
                repair::Summary {
                    id,
                    hash: version.hash,
                    // A vouch's or succession's signed `iat` (0 for keys and
                    // claims): only a newer version is sent, and on equal
                    // orders both, for the merge to break the tie.
                    order: Some((i64::try_from(version.order).unwrap_or(i64::MAX), 0, [0; 16])),
                    kind,
                },
                id,
            )
        })
        .collect())
}

/// This server as the local side of an entry-wise repair. Entries are
/// [`AnchorState`] entries by [`anchors::EntryId`]; their kind is the entry
/// tag, so keys arrive before the entries checked against them.
impl Replica<str> for Peers {
    type Entry = WireEntry;
    type Location = anchors::EntryId;
    type Hasher = Sha256;

    async fn index(&self) -> Result<repair::SharedIndex<anchors::EntryId, Sha256>, RepairError> {
        self.index
            .get(
                self.engine.durable(),
                || repair::Index::new(Sha256, INDEX_DOMAIN),
                |state: &AnchorState, since| match since {
                    None => state.clone(),
                    Some(since) => agirru_crdt::Delta::delta_since(state, since),
                },
                |part| summaries(&part),
            )
            .await
    }

    async fn admit(&self, peer: &str, entries: Vec<WireEntry>) -> Result<(), RepairError> {
        let clock = GenerationClock::new();
        let mut inbound = AnchorState::default();
        for e in &entries {
            let part = AnchorState::from_bytes(&e.0).map_err(to_entry)?;
            agirru_crdt::Merge::merge(&mut inbound, &part, &clock);
        }
        self.engine
            .merge_inbound(&peer.to_owned(), inbound)
            .await
            .map_err(to_storage)?;
        Ok(())
    }

    async fn entries(
        &self,
        ids: Vec<anchors::EntryId>,
    ) -> Result<Vec<Option<WireEntry>>, RepairError> {
        self.engine
            .durable()
            .read(|state, _| {
                ids.iter()
                    .map(|id| {
                        let one = state.entries(&BTreeSet::from([*id]))?;
                        Ok((!one.is_empty()).then(|| WireEntry(one.to_bytes())))
                    })
                    .collect::<Result<Vec<_>, Error>>()
            })
            .await
            .map_err(to_storage)?
            .map_err(to_entry)
    }

    fn entry_size(entry: &WireEntry) -> usize {
        entry.0.len()
    }
}

/// This server as the local side of a whole-state transfer: the encoded
/// [`AnchorState`] with its own digest.
impl SnapshotReplica<str> for Peers {
    async fn snapshot(&self) -> Result<(repair::Hash, Arc<Vec<u8>>), RepairError> {
        let bytes = self
            .engine
            .durable()
            .read(|state, _| state.to_bytes())
            .await
            .map_err(to_storage)?;
        let digest = anchors::state_digest(&bytes).map_err(to_entry)?;
        Ok((digest, Arc::new(bytes)))
    }

    fn digest(&self, bytes: &[u8]) -> Result<repair::Hash, RepairError> {
        anchors::state_digest(bytes).map_err(to_entry)
    }

    async fn admit_snapshot(&self, peer: &str, bytes: Vec<u8>) -> Result<(), RepairError> {
        let inbound = AnchorState::from_bytes(&bytes).map_err(to_entry)?;
        self.engine
            .merge_inbound(&peer.to_owned(), inbound)
            .await
            .map_err(to_storage)?;
        Ok(())
    }
}

impl Exchange {
    /// Every member, this server included.
    fn members(&self) -> BTreeSet<String> {
        lock(&self.members).0.clone()
    }

    fn neighbors(&self) -> BTreeSet<String> {
        lock(&self.neighbors).clone()
    }

    /// Refresh membership and topology independently; retain either on failure.
    async fn refresh_members(&self) {
        if !self.settings.discover {
            return;
        }
        {
            let mut members = lock(&self.members);
            if members
                .1
                .is_some_and(|t| t.elapsed() < self.settings.interval * 5)
            {
                return;
            }
            members.1 = Some(Instant::now());
        }
        let directory = self.directory.clone();
        let hostname = self.settings.me.clone();
        let result = tokio::task::spawn_blocking(move || {
            (directory.servers(), directory.topology_peers(&hostname))
        })
        .await;
        let mut members = lock(&self.members);
        match result {
            Ok((servers, topology)) => {
                if let Ok(servers) = servers {
                    let mut set: BTreeSet<String> = servers
                        .into_iter()
                        .chain(self.settings.peers.iter().cloned())
                        .map(|s| s.to_ascii_lowercase())
                        .collect();
                    set.insert(self.settings.me.clone());
                    members.0 = set;
                } else if let Err(e) = servers {
                    eprintln!("kuipad: anchor exchange: cannot list servers: {e}");
                }
                match topology {
                    Ok(peers) => {
                        *lock(&self.neighbors) = peers
                            .into_iter()
                            .chain(self.settings.peers.iter().cloned())
                            .map(|s| s.to_ascii_lowercase())
                            .collect();
                    }
                    Err(e) => eprintln!("kuipad: anchor exchange: cannot list topology peers: {e}"),
                }
                members.1 = Some(Instant::now());
            }
            Err(e) => {
                eprintln!("kuipad: anchor exchange: {e}");
                members.1 = Some(Instant::now());
            }
        }
    }

    fn base(&self, peer: &str) -> String {
        let origin = self.settings.endpoints.get(peer).map_or_else(
            || format!("https://{peer}"),
            |b| b.trim_end_matches('/').to_owned(),
        );
        format!("{origin}/ipa/ku")
    }

    fn url(&self, peer: &str) -> String {
        format!("{}/peer/sync", self.base(peer))
    }
}

impl Exchange {
    /// Log a failed sync once per distinct failure, and the recovery.
    fn note(&self, peer: &str, result: &Result<Vec<u8>, PeerError>) {
        let mut failures = lock(&self.failures);
        match result {
            Ok(_) => {
                if failures.remove(peer).is_some() {
                    eprintln!("kuipad: anchor exchange: {peer} reachable again");
                }
            }
            Err(e) => {
                let e = e.to_string();
                if failures.get(peer) != Some(&e) {
                    eprintln!("kuipad: anchor exchange: sync with {peer} failed: {e}");
                    failures.insert(peer.to_owned(), e);
                }
            }
        }
    }

    /// This server's own delegation in `state`, as it introduces itself
    /// to peers.
    fn own_delegation(&self, state: &AnchorState) -> Result<Delegation, PeerError> {
        let me = &self.settings.me;
        match &self.anchor {
            Some(a) => state.own_delegation(me, a.public()).map_err(failed)?,
            None => state.latest_claim(me, None).map(Delegation::new),
        }
        .ok_or_else(|| failed("no own claim yet"))
    }

    /// Send one reconciliation message to `peer`, with this server's
    /// delegation `own` and epoch window as context: each left out while the
    /// peer holds it, and sent again once if the peer answers that it needs
    /// them.
    async fn sync(
        &self,
        peer: &str,
        payload: Vec<u8>,
        own: Delegation,
    ) -> Result<Vec<u8>, PeerError> {
        static MEASURE: std::sync::LazyLock<bool> =
            std::sync::LazyLock::new(|| std::env::var_os("KUIPA_REPLICATION_SIZES").is_some());
        let measure = *MEASURE;
        let started = measure.then(Instant::now);
        let payload_bytes = payload.len();
        let me = self.settings.me.clone();
        let target = peer.to_owned();
        let own = OwnContext(own);
        let chain = ChainContext(self.epoch_bytes().map_err(failed)?);
        let mut resent = false;
        loop {
            let own_attached = self.own_sent.attach(&target, &own).map_err(failed)?;
            let chain_attached = self.chain_sent.attach(&target, &chain).map_err(failed)?;
            let elided = own_attached.value.is_none() || chain_attached.value.is_none();
            let (own_hash, chain_hash) = (own_attached.hash, chain_attached.hash);
            let cb = PeerSync::channel_binding(&me, peer, &own_hash, &payload, &chain_hash)
                .map_err(failed)?;
            let initiator = self.initiator.clone();
            let token_target = target.clone();
            let token = tokio::task::spawn_blocking(move || initiator.token(&token_target, &cb))
                .await
                .map_err(failed)?
                .map_err(failed)?;
            let own_bytes = own_attached
                .value
                .as_ref()
                .map_or(0, |o| o.0.to_json().len());
            let chain_bytes: usize = chain_attached
                .value
                .as_ref()
                .map_or(0, |c| c.0.iter().map(Vec::len).sum());
            let token_bytes = token.len();
            let body = PeerSync {
                sender: me.clone(),
                receiver: target.clone(),
                own_hash,
                own: own_attached.value.map(|o| o.0),
                payload: payload.clone(),
                token,
                chain_hash,
                chain: chain_attached.value.map(|c| c.0),
            }
            .to_bytes();
            if body.len() > MAX_SYNC_BYTES {
                return Err(failed("peer repair request exceeds size limit"));
            }
            let request_bytes = body.len();
            let result = self.post_sync(peer, body).await;
            match &result {
                Ok(response) => {
                    self.own_sent.delivered(&target, own_hash);
                    self.chain_sent.delivered(&target, chain_hash);
                    if let Some(started) = started {
                        eprintln!(
                            "kuipad: peer sync size: peer={peer} request={request_bytes} payload={payload_bytes} delegation={own_bytes} token={token_bytes} epochs={chain_bytes} response={} elapsed_ms={}",
                            response.len(),
                            started.elapsed().as_millis()
                        );
                    }
                }
                // The peer restarted or forgot this server: send everything once.
                Err(PeerError::NeedContext) if elided && !resent => {
                    self.own_sent.forget(&target);
                    self.chain_sent.forget(&target);
                    resent = true;
                    continue;
                }
                Err(_) => {}
            }
            return result;
        }
    }

    async fn post_sync(&self, peer: &str, body: Vec<u8>) -> Result<Vec<u8>, PeerError> {
        let mut response = self
            .client
            .post(self.url(peer))
            .header("content-type", "application/vnd.ipa-ku.peer-sync")
            .body(body)
            .send()
            .await
            .map_err(failed)?;
        match response.status() {
            reqwest::StatusCode::OK => {
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(failed)? {
                    if chunk.len() > MAX_SYNC_BYTES.saturating_sub(body.len()) {
                        return Err(failed("peer repair response exceeds size limit"));
                    }
                    body.extend_from_slice(&chunk);
                }
                if body.is_empty() {
                    return Err(failed("the peer answered with no state"));
                }
                Ok(body)
            }
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                Err(PeerError::Rejected)
            }
            reqwest::StatusCode::SERVICE_UNAVAILABLE | reqwest::StatusCode::TOO_MANY_REQUESTS => {
                Err(PeerError::Busy)
            }
            reqwest::StatusCode::CONFLICT => Err(PeerError::NeedContext),
            status => Err(PeerError::Failed(format!("HTTP {status}"))),
        }
    }

    /// A bounded tail window of the chain, encoded for the wire (§4.8).
    fn epoch_bytes(&self) -> Result<Vec<Vec<u8>>, Error> {
        epoch_window(&lock(&self.epoch))
    }

    /// §4.8: our sync window left a gap for this peer: page the
    /// missing entries from its public anchor log and append them,
    /// storing each page before publishing it.
    async fn catch_up(&self, peer: &str) -> Result<(), Error> {
        let (mut seq, mut head) = lock(&self.epoch)
            .last()
            .and_then(|t| t.statement().ok())
            .map_or((0, epoch::GENESIS), |t| {
                (t.seq(), t.head().unwrap_or(epoch::GENESIS))
            });
        loop {
            let mut response = self
                .client
                .get(format!("{}/anchor-log?from={}", self.base(peer), seq))
                .send()
                .await?;
            if !response.status().is_success() {
                return Err(format!("HTTP {}", response.status()).into());
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if chunk.len() > MAX_SYNC_BYTES.saturating_sub(body.len()) {
                    return Err("anchor log page exceeds size limit".into());
                }
                body.extend_from_slice(&chunk);
            }
            let body: serde_json::Value = serde_json::from_slice(&body)?;
            let entries: Vec<SignedEpoch> = serde_json::from_value(body["entries"].clone())?;
            if entries.len() > epoch::MAX_EPOCH_FETCH {
                return Err("anchor log page has too many entries".into());
            }
            if entries.is_empty() {
                return Ok(()); // they hold nothing past our head after all
            }
            let reached = epoch::verify_chain(
                &entries,
                &self.settings.realm,
                &self.server.anchors(),
                Some((seq, head)),
                &self.policy,
            )
            .map_err(|e| format!("{peer}: {e}"))?;
            store_epoch_page(&self.store, &self.epoch, (seq, head), entries, |chain| {
                self.server.publish_epoch(chain);
            })?;
            self.changed.notify_one();
            (seq, head) = reached;
        }
    }
}

fn store_epoch_page(
    store: &KeyStore,
    current: &Mutex<Vec<SignedEpoch>>,
    expected: (u64, epoch::EpochHead),
    entries: Vec<SignedEpoch>,
    publish: impl FnOnce(Vec<SignedEpoch>),
) -> Result<(), Error> {
    let mut current = lock(current);
    let actual = match current.last() {
        Some(last) => {
            let statement = last.statement()?;
            (statement.seq(), statement.head()?)
        }
        None => (0, epoch::GENESIS),
    };
    if actual != expected {
        return Err("anchor log changed during catch-up".into());
    }
    let mut candidate = current.clone();
    candidate.extend(entries);
    store.store_epoch(&candidate)?;
    current.clone_from(&candidate);
    publish(candidate);
    Ok(())
}

impl Transport<String> for Exchange {
    type Error = PeerError;

    async fn send_recv(&self, peer: &String, envelope: Vec<u8>) -> Result<Vec<u8>, PeerError> {
        let own = {
            let state = self.state.read().await;
            self.own_delegation(&state)?
        };
        let result = self.sync(peer, envelope, own).await;
        self.note(peer, &result);
        result
    }

    fn classify_error(&self, err: &PeerError) -> SendOutcome {
        match err {
            PeerError::Rejected => SendOutcome::AuthRejected,
            PeerError::Busy | PeerError::NeedContext | PeerError::Failed(_) => SendOutcome::Failed,
        }
    }
}

impl Membership<String> for Exchange {
    fn peers(&self) -> impl Future<Output = Vec<String>> + Send {
        let me = &self.settings.me;
        std::future::ready(self.members().into_iter().filter(|m| m != me).collect())
    }
}

impl Storage<AnchorState> for Exchange {
    type Error = PeerError;

    fn load(&self) -> impl Future<Output = Result<AnchorState, PeerError>> + Send {
        std::future::ready(
            self.store
                .peer_state()
                .map(|mut state| {
                    state.rebase_generations(&self.clock);
                    state
                })
                .map_err(failed),
        )
    }

    fn persist_full(
        &self,
        state: &AnchorState,
    ) -> impl Future<Output = Result<(), PeerError>> + Send {
        std::future::ready(self.store.store_peer_state(state).map_err(failed))
    }
}

impl GossipHooks<String, AnchorState> for Exchange {
    /// Keep only entries that check against the keys received and known,
    /// for members, and no vouch by this server's own anchor: it is the
    /// only source of those.
    async fn filter_inbound(&self, _sender: &String, inbound: &mut AnchorState) {
        let local = self.state.read().await.clone();
        inbound.admit(
            &local,
            &self.members(),
            self.anchor.as_ref().map(|a| a.public().thumbprint()),
            &self.settings.realm,
            &self.policy,
            now(),
        );
    }

    async fn on_merged(&self, _peer: &String, _changes: &AnchorState) {
        self.changed.notify_one();
    }

    async fn on_auth_rejected(&self, peer: &String) {
        eprintln!("kuipad: anchor exchange: {peer} refused our sync");
    }
}

/// §4.8: mint the next entry of the anchor epoch log when the trusted
/// anchor keys or their proofs change, and publish the log.  Entries
/// compare in their canonical form: the state's own order says nothing,
/// only the entry's does.  A fresh entry commits to the head of its
/// predecessor; while a fork with a peer is unreconciled the log is
/// left alone.
fn mint_epoch(
    x: &Exchange,
    realm: &str,
    anchor: &SigningKey,
    trusted: &[Thumbprint],
    successions: &[SignedSuccession],
) -> Result<(), Error> {
    if x.forked.load(Ordering::Relaxed) {
        return Ok(()); // handle() said why; reconciling is an operator's job
    }
    let mut chain = lock(&x.epoch);
    let current = chain.last().and_then(|e| e.statement().ok());
    let prev = match current.as_ref() {
        None => epoch::GENESIS,
        Some(last) => last.head()?,
    };
    let seq = current.as_ref().map_or(0, AnchorEpoch::seq);
    let entry = AnchorEpoch::new(
        realm,
        seq + 1,
        prev,
        trusted.iter().copied(),
        successions.iter().cloned(),
    );
    let fresh = current
        .as_ref()
        .is_none_or(|s| s.anchors() != entry.anchors() || s.successions() != entry.successions());
    if !fresh {
        *lock(&x.settling) = None;
        return Ok(());
    }
    // Mint only once the state an entry would carry has stood unchanged
    // for a full exchange round: two servers that hear about a change
    // at different moments then extend the same entry, not divergent
    // ones that neither can rejoin.
    let head = entry.head()?;
    let seen = {
        let mut settling = lock(&x.settling);
        match settling.as_ref() {
            Some((h, t)) if *h == head => Some(*t),
            _ => {
                *settling = Some((head, Instant::now()));
                None
            }
        }
    };
    let Some(seen) = seen else {
        return Ok(());
    };
    if seen.elapsed() < x.settings.interval {
        return Ok(());
    }
    eprintln!(
        "kuipad: anchor exchange: recording anchor epoch {}",
        seq + 1
    );
    let mut candidate = chain.clone();
    candidate.push(SignedEpoch::issue(anchor, &entry)?);
    // Store before committing in memory: a log that was not written
    // down is not a record, and a failed write then retries next
    // round rather than being advertised from memory alone.
    x.store.store_epoch(&candidate)?;
    chain.clone_from(&candidate);
    *lock(&x.settling) = None;
    x.server.publish_epoch(candidate);
    Ok(())
}

/// What a peer's window of the anchor epoch log means for ours.
enum Merge {
    /// Nothing to adopt; shared entries, if any, merged signatures.
    Kept,
    /// The window failed signature, realm, or continuity validation.
    Invalid,
    /// The window vouched for itself and continued our log: adopted.
    Extended,
    /// The window jumps past our end; fetch what lies between first.
    Gap,
    /// At a sequence both hold, the statements differ: the logs have
    /// forked, and appending must pause until an operator reconciles.
    Conflict,
}

/// Merge a peer's window of the anchor epoch log with ours (§4.8).
/// Entries both servers hold merge signature sets whatever follows.  A
/// window is adopted only when it vouches for itself — signatures from
/// the anchors each entry names, contiguous sequences, and every entry
/// committing to the one before it — and continues our log: at the
/// junction its entry's predecessor must be our head.  A window that
/// reaches past our end without a shared entry leaves a gap for the
/// caller to fetch; a statement that disagrees with a sequence we
/// already have is a fork, and our log stands.
fn merge_chain(
    realm: &str,
    policy: &Policy,
    ours: &[SignedEpoch],
    theirs: &[SignedEpoch],
) -> (Vec<SignedEpoch>, Merge) {
    // Check the whole window before trusting any of it: a half-vouched
    // chain proves nothing, and a window that breaks inside cannot link.
    let mut window: Vec<(u64, AnchorEpoch, &SignedEpoch)> = Vec::new();
    let mut expect = None; // (next sequence, head the next entry must name)
    for signed in theirs {
        let Ok(epoch) = signed.statement() else {
            return (ours.to_vec(), Merge::Invalid);
        };
        if epoch.realm() != realm || !signed.verify(&epoch, policy).is_ok_and(|v| !v.is_empty()) {
            return (ours.to_vec(), Merge::Invalid);
        }
        if let Some((seq, head)) = expect
            && (epoch.seq() != seq || epoch.prev() != head)
        {
            return (ours.to_vec(), Merge::Invalid);
        }
        let Ok(head) = epoch.head() else {
            return (ours.to_vec(), Merge::Invalid);
        };
        expect = Some((epoch.seq() + 1, head));
        window.push((epoch.seq(), epoch, signed));
    }
    // Shared range: signatures always merge; a different statement at
    // the same sequence is the fork itself.
    let mut chain = ours.to_vec();
    let mut conflict = false;
    for (seq, epoch, signed) in &window {
        let Some(pos) = chain
            .iter()
            .position(|o| o.statement().is_ok_and(|s| s.seq() == *seq))
        else {
            continue;
        };
        if chain[pos].statement().is_ok_and(|s| s == *epoch) {
            let _ = chain[pos].merge(signed);
        } else {
            conflict = true;
        }
    }
    if conflict {
        return (chain, Merge::Conflict);
    }
    // Past our end: link or leave a gap.
    let (last_seq, last_head) = match chain.last().and_then(|t| t.statement().ok()) {
        None => (0, epoch::GENESIS),
        Some(t) => (t.seq(), t.head().unwrap_or(epoch::GENESIS)),
    };
    match window.iter().find(|(seq, _, _)| *seq > last_seq) {
        None => (chain, Merge::Kept), // the window is fully shared
        Some((first, _, _)) if *first > last_seq + 1 => (chain, Merge::Gap),
        Some((_, epoch, _)) if epoch.prev() != last_head => (chain, Merge::Conflict),
        Some(_) => {
            for (_, _, signed) in window.iter().filter(|(seq, _, _)| *seq > last_seq) {
                chain.push((*signed).clone());
            }
            (chain, Merge::Extended)
        }
    }
}

/// The most chain bytes a sync carries; a receiver left further behind
/// catches up through the public anchor log ([`Exchange::catch_up`]).
const MAX_SYNC_EPOCH_BYTES: usize = 32 * 1024;

/// A bounded window of the chain for the wire: the newest entries, in
/// order, up to the byte budget and one page of the anchor log, and
/// always the newest entry itself.
fn epoch_window(chain: &[SignedEpoch]) -> Result<Vec<Vec<u8>>, Error> {
    let mut window: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0;
    for entry in chain.iter().rev() {
        let encoded = epoch::encode(entry)?;
        if !window.is_empty()
            && (bytes + encoded.len() > MAX_SYNC_EPOCH_BYTES
                || window.len() >= epoch::MAX_EPOCH_FETCH)
        {
            break;
        }
        bytes += encoded.len();
        window.push(encoded);
    }
    window.reverse();
    Ok(window)
}

/// The agirru runtime: every part is the [`Exchange`].
pub struct Runtime(Arc<Exchange>, CborCodec);

impl GossipRuntime<AnchorState, String> for Runtime {
    type Transport = Exchange;
    type Membership = Exchange;
    type Hooks = Exchange;
    type Codec = CborCodec;

    fn transport(&self) -> &Exchange {
        &self.0
    }
    fn membership(&self) -> &Exchange {
        &self.0
    }
    fn hooks(&self) -> &Exchange {
        &self.0
    }
    fn codec(&self) -> &CborCodec {
        &self.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotating_fanout_is_bounded_and_sweeps_retain_membership() {
        assert_eq!(repair_concurrency(300), 1);
        assert_eq!(repair_concurrency(9), 2);
        assert_eq!(repair_concurrency(1), MAX_CONCURRENT_REPAIRS);
        let members: BTreeSet<_> = (0..13).map(|i| format!("node-{i:02}")).collect();
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        for _ in 0..4 {
            let selected = selected_peers(&members, "node-00", &mut cursor, false);
            assert_eq!(selected.len(), GOSSIP_FANOUT);
            seen.extend(selected.into_iter().cloned());
        }
        assert_eq!(seen.len(), members.len() - 1);
        let sweep = selected_peers(&members, "node-00", &mut cursor, true);
        assert_eq!(sweep.len(), members.len() - 1);
        assert_eq!(members.len(), 13);
        let unequal: BTreeSet<_> = members.iter().skip(3).cloned().collect();
        let sweep = selected_peers(&unequal, "node-00", &mut cursor, true);
        assert_eq!(sweep.len(), unequal.len());
    }

    #[test]
    fn topology_neighbors_propagate_state_across_multiple_hops() {
        use agirru_crdt::Merge;

        let clock = GenerationClock::new();
        let key = SigningKey::generate_preferred().unwrap();
        let mut states = [
            AnchorState::default(),
            AnchorState::default(),
            AnchorState::default(),
        ];
        states[0]
            .put(
                Entry::Key(key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                now(),
                &clock,
            )
            .unwrap();
        let neighbors = [
            BTreeSet::from(["b".to_string()]),
            BTreeSet::from(["a".to_string(), "c".to_string()]),
            BTreeSet::from(["b".to_string()]),
        ];
        let names = ["a", "b", "c"];
        for source in 0..2 {
            let mut cursor = None;
            let targets = selected_peers(&neighbors[source], names[source], &mut cursor, true);
            assert!(
                targets
                    .iter()
                    .all(|target| target.as_str() != "c" || source == 1)
            );
            let snapshot = states[source].clone();
            for target in targets {
                let index = names
                    .iter()
                    .position(|name| *name == target.as_str())
                    .unwrap();
                states[index].merge(&snapshot, &clock);
            }
        }
        assert_eq!(
            states[0], states[2],
            "the update must reach the non-neighbor through b"
        );
    }

    /// The repair index of `state`, as a peer computes it.
    fn index_of(state: &AnchorState) -> repair::Index<anchors::EntryId, Sha256> {
        let mut index = repair::Index::new(Sha256, INDEX_DOMAIN).unwrap();
        index.apply(summaries(state).unwrap()).unwrap();
        index
    }

    fn payload(body: RequestBody) -> Vec<u8> {
        encode(&Message {
            nonce: [7; 32],
            body,
        })
        .unwrap()
    }

    fn answer(bytes: &[u8]) -> ResponseBody {
        let message: Message<ResponseBody> = decode(bytes).unwrap();
        assert_eq!(message.nonce, [7; 32], "the answer echoes the nonce");
        message.body
    }

    fn probe(state: &AnchorState) -> RequestBody {
        RequestBody::Repair(repair::Request::Probe {
            digest: index_of(state).digest(),
        })
    }

    fn upload(digest: [u8; 32], offset: usize, total: usize, part: &[u8]) -> RequestBody {
        RequestBody::Snapshot(SnapshotRequest::Upload {
            digest,
            offset: offset as u64,
            total: total as u64,
            bytes: part.to_vec(),
        })
    }

    fn vouched_state() -> AnchorState {
        let anchor = SigningKey::generate_preferred().unwrap();
        let mut state = AnchorState::default();
        state
            .put(
                Entry::Key(anchor.public().to_jwk_json()),
                "R",
                &Policy::default(),
                now(),
                &GenerationClock::new(),
            )
            .unwrap();
        let signing = SigningKey::generate_preferred().unwrap();
        let claim = Claim {
            realm: "R".into(),
            server: "s".into(),
            anchor: Some(*anchor.public().thumbprint()),
            key: *signing.public().thumbprint(),
            iat: now(),
            exp: now() + 100,
        };
        let vouch = SignedVouch::issue(
            &anchor,
            "R",
            [claim.leaf(kuipa_enroll::merkle::TreeHash::Sha256).unwrap()],
            now(),
            now() + 100,
            None,
        )
        .unwrap();
        for e in [Entry::Claim(claim), Entry::Vouch(vouch)] {
            state
                .put(e, "R", &Policy::default(), now(), &GenerationClock::new())
                .unwrap();
        }
        state
    }

    /// Entries larger than CBOR's 4 KiB scratch buffer travel intact, and a
    /// vouch carries the key it is checked against.
    #[test]
    fn repair_messages_round_trip_large_entries() {
        let state = vouched_state();
        let entries: Vec<WireEntry> = summaries(&state)
            .unwrap()
            .into_iter()
            .map(|(_, id)| WireEntry(state.entries(&BTreeSet::from([id])).unwrap().to_bytes()))
            .collect();
        assert!(entries.iter().any(|e| e.0.len() > 4096), "a large entry");
        let bytes = payload(RequestBody::Repair(repair::Request::Exchange {
            push: entries,
            want: Vec::new(),
        }));
        let message: Message<RequestBody> = decode(&bytes).unwrap();
        let RequestBody::Repair(repair::Request::Exchange { push, .. }) = message.body else {
            panic!("expected an exchange")
        };
        let mut back = AnchorState::default();
        for e in &push {
            agirru_crdt::Merge::merge(
                &mut back,
                &AnchorState::from_bytes(&e.0).unwrap(),
                &GenerationClock::new(),
            );
        }
        assert_eq!(back, state);
    }

    /// Keys are sent before the claims and vouches checked against them.
    #[test]
    fn entry_kinds_put_keys_first() {
        let state = vouched_state();
        let mut kinds: Vec<u8> = summaries(&state)
            .unwrap()
            .iter()
            .map(|(s, _)| s.kind)
            .collect();
        kinds.sort_unstable();
        assert_eq!(kinds, vec![1, 2, 3]);
    }

    #[test]
    fn malformed_repair_messages_are_rejected() {
        let bytes = payload(probe(&AnchorState::default()));
        assert!(decode::<Message<RequestBody>>(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode::<Message<RequestBody>>(&[0xff; 8]).is_err());
    }

    fn epoch_at(
        prev: kuipa_enroll::epoch::EpochHead,
        seq: u64,
        signers: &[&SigningKey],
    ) -> kuipa_enroll::epoch::SignedEpoch {
        let named: Vec<tang_pqc::Thumbprint> =
            signers.iter().map(|k| *k.public().thumbprint()).collect();
        let entry =
            kuipa_enroll::epoch::AnchorEpoch::new("R", seq, prev, named.iter().copied(), []);
        kuipa_enroll::epoch::SignedEpoch::issue(signers[0], &entry).unwrap()
    }

    fn head_of(signed: &kuipa_enroll::epoch::SignedEpoch) -> kuipa_enroll::epoch::EpochHead {
        signed.statement().unwrap().head().unwrap()
    }

    use kuipa_enroll::escrow::{self, BindingHash};
    use kuipa_enroll::join::KerberosBinding;
    use kuipa_enroll::keytab::{Enctype, Keytab, Principal};
    use kuipa_enroll::server::{DirectoryError, Staged};
    struct UnusedDirectory;
    impl Directory for UnusedDirectory {
        fn join_with_otp(
            &self,
            _: &str,
            _: &[u8],
            _: &[Enctype],
        ) -> Result<Keytab, DirectoryError> {
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
            if token != cb {
                return Err("bad channel binding".into());
            }
            Ok("ipa-ku/peer@R".into())
        }
    }

    #[derive(Default)]
    struct TopologyDirectory {
        servers: Mutex<Vec<String>>,
        peers: Mutex<Option<Vec<String>>>,
    }

    impl Directory for TopologyDirectory {
        fn join_with_otp(
            &self,
            _: &str,
            _: &[u8],
            _: &[Enctype],
        ) -> Result<Keytab, DirectoryError> {
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
            Ok(lock(&self.servers).clone())
        }
        fn topology_peers(&self, _: &str) -> Result<Vec<String>, DirectoryError> {
            lock(&self.peers)
                .clone()
                .ok_or_else(|| "topology unavailable".into())
        }
    }
    struct UnusedInitiator;
    impl Initiator for UnusedInitiator {
        fn token(&self, _: &str, cb: &[u8; 32]) -> Result<Vec<u8>, Error> {
            Ok(cb.to_vec())
        }
    }
    async fn check_context(
        peers: &Peers,
        sync_of: &impl Fn(RequestBody, bool) -> Vec<u8>,
        message: &impl Fn(RequestBody) -> Vec<u8>,
        inbound: &AnchorState,
        saved: &AnchorState,
    ) {
        let need = peers
            .handle(&sync_of(probe(inbound), false))
            .await
            .unwrap_err();
        assert!(
            matches!(
                need.downcast_ref::<PeerError>(),
                Some(PeerError::NeedContext)
            ),
            "left-out context needs an earlier authenticated sync"
        );
        let probe_sync = message(probe(inbound));
        let permits = peers
            .exchange
            .repair_permits
            .try_acquire_many(u32::try_from(MAX_CONCURRENT_REPAIRS).unwrap())
            .unwrap();
        let busy = peers.handle(&probe_sync).await.unwrap_err();
        assert!(matches!(
            busy.downcast_ref::<PeerError>(),
            Some(PeerError::Busy)
        ));
        drop(permits);
        let mut tampered = PeerSync::from_bytes(&probe_sync).unwrap();
        tampered.payload[5] ^= 1;
        assert!(
            peers.handle(&tampered.to_bytes()).await.is_err(),
            "payload must be authenticated"
        );
        assert!(peers.handle(&vec![0; MAX_SYNC_BYTES + 1]).await.is_err());
        let ResponseBody::Repair(response) = answer(&peers.handle(&probe_sync).await.unwrap())
        else {
            panic!("expected a repair answer")
        };
        assert_eq!(
            response,
            repair::Response::Probe {
                equal: false,
                entries: Some(index_of(saved).len() as u64),
            }
        );
        let ResponseBody::Repair(elided) =
            answer(&peers.handle(&sync_of(probe(inbound), false)).await.unwrap())
        else {
            panic!("expected a repair answer")
        };
        assert_eq!(
            elided, response,
            "left-out context resolves from the sender's last sync"
        );
        let mut other = PeerSync::from_bytes(&sync_of(probe(inbound), false)).unwrap();
        other.own_hash[0] ^= 1;
        other.token = PeerSync::channel_binding(
            "peer",
            "local",
            &other.own_hash,
            &other.payload,
            &other.chain_hash,
        )
        .unwrap()
        .to_vec();
        let need = peers.handle(&other.to_bytes()).await.unwrap_err();
        assert!(
            matches!(
                need.downcast_ref::<PeerError>(),
                Some(PeerError::NeedContext)
            ),
            "a different delegation hash is not resolved from the old one"
        );
    }

    /// The first-nibble bucket request for `state`.
    fn root_buckets(state: &AnchorState) -> RequestBody {
        let index = index_of(state);
        RequestBody::Repair(repair::Request::Buckets {
            buckets: (0..16u8)
                .map(|n| repair::Bucket {
                    prefix: vec![n],
                    hash: index.bucket_hash(&[n]).unwrap(),
                })
                .collect(),
        })
    }

    /// The receiver's summaries in each differing bucket of a bucket answer.
    fn differing(response: ResponseBody) -> BTreeMap<Vec<u8>, Vec<repair::Summary>> {
        let ResponseBody::Repair(repair::Response::Buckets {
            differing, descend, ..
        }) = response
        else {
            panic!("expected bucket summaries")
        };
        assert!(descend.is_empty(), "small buckets are summarised");
        differing
            .into_iter()
            .map(|b| (b.prefix, b.summaries))
            .collect()
    }

    async fn check_summary(
        peers: &Peers,
        message: &impl Fn(RequestBody) -> Vec<u8>,
        inbound: &AnchorState,
        saved: &AnchorState,
    ) -> Vec<u8> {
        let ResponseBody::Repair(response) =
            answer(&peers.handle(&message(probe(saved))).await.unwrap())
        else {
            panic!("expected a repair answer")
        };
        assert!(
            matches!(response, repair::Response::Probe { equal: true, .. }),
            "a probe compares digests only"
        );
        let buckets_sync = message(root_buckets(inbound));
        let got = differing(answer(&peers.handle(&buckets_sync).await.unwrap()));
        let first_nibble = |id: &anchors::EntryId| vec![id[0] >> 4];
        let expected: BTreeSet<Vec<u8>> = index_of(saved)
            .bucket_summaries(&[])
            .iter()
            .chain(index_of(inbound).bucket_summaries(&[]).iter())
            .map(|s| first_nibble(&s.id))
            .collect();
        assert_eq!(
            got.keys().cloned().collect::<BTreeSet<_>>(),
            expected,
            "exactly the buckets holding entries one side lacks differ"
        );
        for (prefix, summaries) in &got {
            assert_eq!(*summaries, index_of(saved).bucket_summaries(prefix));
        }
        let mut tampered = PeerSync::from_bytes(&buckets_sync).unwrap();
        *tampered.payload.last_mut().unwrap() ^= 1;
        assert!(
            peers.handle(&tampered.to_bytes()).await.is_err(),
            "summaries must be authenticated"
        );
        buckets_sync
    }

    async fn check_upload(
        peers: &Peers,
        message: &impl Fn(RequestBody) -> Vec<u8>,
        inbound: &AnchorState,
        mut saved: AnchorState,
        dir: &std::path::Path,
        buckets_sync: &[u8],
    ) -> AnchorState {
        let bytes = inbound.to_bytes();
        let digest = anchors::state_digest(&bytes).unwrap();
        let split = bytes.len() / 2;
        let chunk = |offset, part: &[u8]| message(upload(digest, offset, bytes.len(), part));
        let first = chunk(0, &bytes[..split]);
        let response = answer(&peers.handle(&first).await.unwrap());
        assert!(matches!(
            response,
            ResponseBody::Snapshot(SnapshotResponse::Accepted { next }) if next == split as u64
        ));
        assert_eq!(
            KeyStore::new(dir).peer_state().unwrap(),
            saved,
            "partial uploads must not merge"
        );
        assert!(
            peers
                .handle(&chunk(split + 1, &bytes[split..]))
                .await
                .is_err()
        );
        let last = chunk(split, &bytes[split..]);
        let mut bad = PeerSync::from_bytes(&last).unwrap();
        *bad.payload.last_mut().unwrap() ^= 1;
        assert!(
            peers.handle(&bad.to_bytes()).await.is_err(),
            "chunks must be authenticated"
        );
        let mut altered = bytes[split..].to_vec();
        *altered.last_mut().unwrap() ^= 1;
        assert!(
            peers.handle(&chunk(split, &altered)).await.is_err(),
            "a complete upload must match its digest"
        );
        assert_eq!(KeyStore::new(dir).peer_state().unwrap(), saved);
        peers.handle(&first).await.unwrap();
        peers.handle(&last).await.unwrap();
        agirru_crdt::Merge::merge(&mut saved, inbound, &GenerationClock::new());
        assert_eq!(KeyStore::new(dir).peer_state().unwrap(), saved);
        // A bucket answer reflects the receiver's current state, even after
        // it changed since the sender's earlier request.
        let got = differing(answer(&peers.handle(buckets_sync).await.unwrap()));
        let mut plan = repair::Plan::default();
        for (prefix, theirs) in &got {
            assert_eq!(*theirs, index_of(&saved).bucket_summaries(prefix));
            repair::plan_bucket(&index_of(inbound), prefix, theirs, &mut plan);
        }
        let lacking: BTreeSet<anchors::EntryId> = index_of(&saved)
            .bucket_summaries(&[])
            .iter()
            .map(|s| s.id)
            .filter(|id| index_of(inbound).summary(id).is_none())
            .collect();
        assert_eq!(
            plan.want.iter().map(|(_, id)| *id).collect::<BTreeSet<_>>(),
            lacking,
            "the sender wants exactly what it lacks"
        );
        let wanted: Vec<anchors::EntryId> = index_of(&saved)
            .bucket_summaries(&[])
            .iter()
            .map(|s| s.id)
            .collect();
        let exchange = message(RequestBody::Repair(repair::Request::Exchange {
            push: vec![WireEntry(inbound.to_bytes())],
            want: wanted,
        }));
        let ResponseBody::Repair(repair::Response::Exchange {
            entries,
            later,
            digest,
        }) = answer(&peers.handle(&exchange).await.unwrap())
        else {
            panic!("expected wanted entries")
        };
        assert_eq!(later, Vec::<anchors::EntryId>::new());
        let mut got = AnchorState::default();
        for e in &entries {
            agirru_crdt::Merge::merge(
                &mut got,
                &AnchorState::from_bytes(&e.0).unwrap(),
                &GenerationClock::new(),
            );
        }
        assert_eq!(got, saved, "the exchange answers with the wanted entries");
        assert_eq!(
            digest,
            index_of(&KeyStore::new(dir).peer_state().unwrap()).digest(),
            "an exchange acknowledgement must describe durable state"
        );
        saved
    }

    async fn check_persistence(
        peers: &Peers,
        message: &impl Fn(RequestBody) -> Vec<u8>,
        inbound: &AnchorState,
        mut saved: AnchorState,
        dir: &std::path::Path,
        exchange: &Arc<Exchange>,
        server: &Arc<EnrollServer>,
    ) {
        let whole = |state: &AnchorState| {
            let bytes = state.to_bytes();
            message(upload(
                anchors::state_digest(&bytes).unwrap(),
                0,
                bytes.len(),
                &bytes,
            ))
        };
        let merged = |response: ResponseBody| match response {
            ResponseBody::Snapshot(SnapshotResponse::Merged { digest }) => digest,
            other => panic!("expected a merged upload, got {other:?}"),
        };
        let digest = merged(answer(&peers.handle(&whole(inbound)).await.unwrap()));
        agirru_crdt::Merge::merge(&mut saved, inbound, &GenerationClock::new());
        assert_eq!(digest, anchors::state_digest(&saved.to_bytes()).unwrap());
        assert_eq!(KeyStore::new(dir).peer_state().unwrap(), saved);
        let equal = message(RequestBody::Snapshot(SnapshotRequest::Fetch {
            mine: anchors::state_digest(&saved.to_bytes()).unwrap(),
            pinned: None,
            offset: 0,
        }));
        assert!(matches!(
            answer(&peers.handle(&equal).await.unwrap()),
            ResponseBody::Snapshot(SnapshotResponse::Equal)
        ));
        let mut next = AnchorState::default();
        let next_key = SigningKey::generate_preferred().unwrap();
        next.put(
            Entry::Key(next_key.public().to_jwk_json()),
            "R",
            &Policy::default(),
            now(),
            &GenerationClock::new(),
        )
        .unwrap();
        let request = whole(&next);
        agirru_crdt::Merge::merge(&mut saved, &next, &GenerationClock::new());
        let obstruction = dir.join("peers.tmp");
        std::fs::create_dir(&obstruction).unwrap();
        assert!(peers.handle(&request).await.is_err());
        assert!(
            peers.handle(&equal).await.is_err(),
            "dirty state must not be acknowledged"
        );
        assert_ne!(KeyStore::new(dir).peer_state().unwrap(), saved);
        std::fs::remove_dir(obstruction).unwrap();
        let digest = merged(answer(&peers.handle(&request).await.unwrap()));
        assert_eq!(digest, anchors::state_digest(&saved.to_bytes()).unwrap());
        assert_eq!(KeyStore::new(dir).peer_state().unwrap(), saved);
        let digest = merged(answer(&peers.handle(&whole(inbound)).await.unwrap()));
        assert_ne!(
            digest,
            anchors::state_digest(&inbound.to_bytes()).unwrap(),
            "a concurrent update must remain unreconciled"
        );
        let reopened = Peers::new(
            exchange.settings.clone(),
            None,
            server.clone(),
            Arc::new(UnusedDirectory),
            Arc::new(UnusedInitiator),
            KeyStore::new(dir),
        )
        .unwrap();
        assert_eq!(reopened.engine.durable_snapshot().await.unwrap(), saved);
    }

    struct PeerTestRoutes {
        target: Arc<Mutex<Option<Arc<Peers>>>>,
        partitioned: Arc<AtomicBool>,
        healthy_requests: Arc<std::sync::atomic::AtomicUsize>,
        busy_requests: Arc<std::sync::atomic::AtomicUsize>,
        selective_pushes: Arc<std::sync::atomic::AtomicUsize>,
        summary_requests: Arc<std::sync::atomic::AtomicUsize>,
        pause_chunk: Arc<std::sync::atomic::AtomicU8>,
        chunk_started: Arc<Notify>,
        chunk_resume: Arc<Notify>,
        pages: Arc<Mutex<Vec<SignedEpoch>>>,
        requested: Arc<Mutex<Vec<usize>>>,
        pause: Arc<AtomicBool>,
        started: Arc<Notify>,
        resume: Arc<Notify>,
        stalled: Arc<Notify>,
        release: Arc<Notify>,
    }

    fn peer_test_routes(routes: &PeerTestRoutes) -> axum::Router {
        let PeerTestRoutes {
            target,
            partitioned,
            healthy_requests,
            busy_requests,
            selective_pushes,
            summary_requests,
            pause_chunk,
            chunk_started,
            chunk_resume,
            ..
        } = routes;
        axum::Router::new().route(
            "/ipa/ku/peer/sync",
            axum::routing::post({
                let target = target.clone();
                let partitioned = partitioned.clone();
                let healthy_requests = healthy_requests.clone();
                let busy_requests = busy_requests.clone();
                let selective_pushes = selective_pushes.clone();
                let summary_requests = summary_requests.clone();
                let pause_chunk = pause_chunk.clone();
                let chunk_started = chunk_started.clone();
                let chunk_resume = chunk_resume.clone();
                move |body: axum::body::Bytes| {
                    let target = target.clone();
                    let blocked = partitioned.load(Ordering::SeqCst);
                    let healthy_requests = healthy_requests.clone();
                    let busy_requests = busy_requests.clone();
                    let selective_pushes = selective_pushes.clone();
                    let summary_requests = summary_requests.clone();
                    let pause_chunk = pause_chunk.clone();
                    let chunk_started = chunk_started.clone();
                    let chunk_resume = chunk_resume.clone();
                    async move {
                        let local =
                            PeerSync::from_bytes(&body).is_ok_and(|sync| sync.receiver == "local");
                        if blocked {
                            if local {
                                busy_requests.fetch_add(1, Ordering::SeqCst);
                            }
                            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new());
                        }
                        if local {
                            healthy_requests.fetch_add(1, Ordering::SeqCst);
                        }
                        let request = PeerSync::from_bytes(&body).ok().and_then(|sync| {
                            decode::<Message<RequestBody>>(&sync.payload)
                                .ok()
                                .map(|m| m.body)
                        });
                        if matches!(
                            request,
                            Some(RequestBody::Repair(repair::Request::Buckets { .. }))
                        ) {
                            summary_requests.fetch_add(1, Ordering::SeqCst);
                        }
                        if matches!(
                            &request,
                            Some(RequestBody::Repair(repair::Request::Exchange { push, .. }))
                                if !push.is_empty()
                        ) {
                            selective_pushes.fetch_add(1, Ordering::SeqCst);
                        }
                        let pause = match request {
                            Some(RequestBody::Snapshot(SnapshotRequest::Fetch {
                                offset, ..
                            })) if offset > 0 => 1,
                            Some(RequestBody::Snapshot(SnapshotRequest::Upload {
                                offset, ..
                            })) if offset > 0 => 2,
                            _ => 0,
                        };
                        if pause != 0
                            && pause_chunk
                                .compare_exchange(pause, 0, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                        {
                            chunk_started.notify_one();
                            chunk_resume.notified().await;
                        }
                        let target = lock(&target).clone();
                        match target.unwrap().handle(&body).await {
                            Ok(bytes) => (axum::http::StatusCode::OK, bytes),
                            Err(e)
                                if matches!(
                                    e.downcast_ref::<PeerError>(),
                                    Some(PeerError::NeedContext)
                                ) =>
                            {
                                (axum::http::StatusCode::CONFLICT, Vec::new())
                            }
                            Err(_) => (axum::http::StatusCode::BAD_REQUEST, Vec::new()),
                        }
                    }
                }
            }),
        )
    }

    fn bootstrap_test_routes(routes: &PeerTestRoutes) -> axum::Router {
        let PeerTestRoutes {
            pages,
            requested,
            pause,
            started,
            resume,
            stalled,
            release,
            ..
        } = routes;
        axum::Router::new()
            .route(
                "/ipa/ku/anchor-log",
                axum::routing::get({
                    let pages = pages.clone();
                    let requested = requested.clone();
                    let pause = pause.clone();
                    let started = started.clone();
                    let resume = resume.clone();
                    move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                        let pages = pages.clone();
                        let requested = requested.clone();
                        let pause = pause.clone();
                        let started = started.clone();
                        let resume = resume.clone();
                        async move {
                            let from: usize = query
                                .unwrap()
                                .strip_prefix("from=")
                                .unwrap()
                                .parse()
                                .unwrap();
                            lock(&requested).push(from);
                            let entries = lock(&pages)
                                .get(from)
                                .cloned()
                                .into_iter()
                                .collect::<Vec<_>>();
                            if pause.load(Ordering::Relaxed) {
                                started.notify_one();
                                resume.notified().await;
                            }
                            serde_json::json!({ "entries": entries }).to_string()
                        }
                    }
                }),
            )
            .merge(peer_test_routes(routes))
            .route(
                "/stall/ipa/ku/peer/sync",
                axum::routing::post({
                    let stalled = stalled.clone();
                    let release = release.clone();
                    move || {
                        let stalled = stalled.clone();
                        let release = release.clone();
                        async move {
                            stalled.notify_one();
                            release.notified().await;
                            axum::http::StatusCode::SERVICE_UNAVAILABLE
                        }
                    }
                }),
            )
    }

    fn bootstrap_exchange(
        anchor: &SigningKey,
        address: std::net::SocketAddr,
        dir: &std::path::Path,
    ) -> (Arc<EnrollServer>, Arc<Exchange>) {
        use kuipa_enroll::realm::{RealmInfo, ServerKeys};
        let signing = SigningKey::generate_preferred().unwrap();
        let claim = Claim {
            realm: "R".into(),
            server: "local".into(),
            anchor: Some(*anchor.public().thumbprint()),
            key: *signing.public().thumbprint(),
            iat: 1,
            exp: 1000,
        };
        let info = RealmInfo {
            realm: "R".into(),
            domain: "example.test".into(),
            basedn: "dc=example,dc=test".into(),
            server: "local".into(),
            servers: vec![],
            ca_certs: vec![],
            pkinit_anchors: vec![],
            anchors: vec![*anchor.public().thumbprint()],
            heads: vec![],
            trusts: vec![],
            kdc_proxy: None,
        };
        let server = Arc::new(EnrollServer::new(
            ServerKeys {
                signing,
                join: vec![],
                escrow: vec![],
                trust: vec![],
                vouchers: vec![],
                retired: vec![],
            },
            info,
            Delegation::new(&claim),
        ));
        let _ = rustls_native_ossl::default_provider().install_default();
        let exchange = Arc::new(Exchange {
            settings: Settings {
                me: "local".into(),
                realm: "R".into(),
                peers: vec!["peer".into()],
                discover: false,
                endpoints: BTreeMap::from([("peer".into(), format!("http://{address}"))]),
                interval: Duration::from_secs(1),
                ca_certs: vec![],
                vouch_interval: Duration::ZERO,
            },
            anchor: None,
            policy: Policy::default(),
            server: server.clone(),
            directory: Arc::new(UnusedDirectory),
            initiator: Arc::new(UnusedInitiator),
            store: KeyStore::new(dir),
            state: Arc::new(RwLock::new(AnchorState::default())),
            clock: GenerationClock::new(),
            members: Mutex::new((BTreeSet::new(), None)),
            neighbors: Mutex::new(BTreeSet::new()),
            attested: Mutex::new(BTreeMap::new()),
            epoch: Mutex::new(Vec::new()),
            forked: AtomicBool::new(false),
            settling: Mutex::new(None),
            changed: Notify::new(),
            repair_trigger: Notify::new(),
            repair_permits: tokio::sync::Semaphore::new(MAX_CONCURRENT_REPAIRS),
            snapshots: SnapshotServer::new(),
            own_seen: ContextReceiver::new(),
            chain_seen: ContextReceiver::new(),
            own_sent: ContextSender::new(),
            chain_sent: ContextSender::new(),
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            failures: Mutex::new(BTreeMap::new()),
        });
        (server, exchange)
    }

    #[tokio::test]
    async fn topology_refresh_keeps_membership_and_preserves_failed_selection() {
        let anchor = SigningKey::generate_preferred().unwrap();
        let address = "127.0.0.1:1".parse().unwrap();
        let (_, mut exchange) = bootstrap_exchange(&anchor, address, &std::env::temp_dir());
        let directory = Arc::new(TopologyDirectory::default());
        *lock(&directory.servers) = vec!["LOCAL".into(), "near".into(), "far".into()];
        let x = Arc::get_mut(&mut exchange).unwrap();
        x.settings.discover = true;
        x.directory = directory.clone();
        *lock(&x.members) = (BTreeSet::from(["local".into(), "peer".into()]), None);
        *lock(&x.neighbors) = BTreeSet::from(["peer".into()]);

        exchange.refresh_members().await;
        assert_eq!(
            exchange.members(),
            BTreeSet::from(["local".into(), "near".into(), "far".into(), "peer".into()])
        );
        assert_eq!(
            exchange.neighbors(),
            BTreeSet::from(["peer".into()]),
            "initial failure must not select all masters"
        );

        *lock(&directory.peers) = Some(vec!["NEAR".into()]);
        lock(&exchange.members).1 = None;
        exchange.refresh_members().await;
        assert_eq!(
            exchange.neighbors(),
            BTreeSet::from(["near".into(), "peer".into()])
        );
        let mut cursor = None;
        let neighbors = exchange.neighbors();
        let selected = selected_peers(&neighbors, "local", &mut cursor, true)
            .into_iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(selected, BTreeSet::from(["near".into(), "peer".into()]));
        assert!(
            exchange.members().contains("far"),
            "non-neighbor remains admitted"
        );

        *lock(&directory.peers) = None;
        lock(&exchange.members).1 = None;
        exchange.refresh_members().await;
        assert_eq!(
            exchange.neighbors(),
            selected,
            "failure preserves the previous neighbors"
        );

        *lock(&directory.peers) = Some(vec![]);
        lock(&exchange.members).1 = None;
        exchange.refresh_members().await;
        assert_eq!(
            exchange.neighbors(),
            BTreeSet::from(["peer".into()]),
            "successful empty topology removes old neighbors"
        );
        assert!(exchange.members().contains("far"));
    }

    async fn check_epoch_catch_up(
        anchor: &SigningKey,
        first: SignedEpoch,
        second: SignedEpoch,
        dir: &std::path::Path,
        server: &Arc<EnrollServer>,
        exchange: &Arc<Exchange>,
        routes: &PeerTestRoutes,
    ) {
        let PeerTestRoutes {
            pages,
            requested,
            pause,
            started,
            resume,
            ..
        } = routes;
        exchange.catch_up("peer").await.unwrap();
        let stored_after_restart = KeyStore::new(dir).epoch().unwrap();
        assert_eq!(*lock(requested), vec![0, 1, 2]);
        assert_eq!(*lock(&exchange.epoch), *lock(pages));
        assert_eq!(stored_after_restart, *lock(pages));
        assert_eq!(server.epoch_head(), Some((2, head_of(&second))));
        let remote_third = epoch_at(head_of(&second), 3, &[anchor]);
        assert_eq!(
            epoch::verify_chain(
                std::slice::from_ref(&remote_third),
                "R",
                &server.anchors(),
                Some((2, head_of(&second))),
                &Policy::default(),
            )
            .unwrap(),
            (3, head_of(&remote_third)),
            "the stale response must otherwise be valid"
        );
        lock(pages).push(remote_third);
        let other = SigningKey::generate_preferred().unwrap();
        let local_third = epoch_at(head_of(&second), 3, &[anchor, &other]);
        pause.store(true, Ordering::Relaxed);
        let catch_up = {
            let exchange = exchange.clone();
            tokio::spawn(async move { exchange.catch_up("peer").await })
        };
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .unwrap();
        store_epoch_page(
            &exchange.store,
            &exchange.epoch,
            (2, head_of(&second)),
            vec![local_third.clone()],
            |chain| server.publish_epoch(chain),
        )
        .unwrap();
        resume.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), catch_up)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "a page fetched against an old head must be rejected"
        );
        let expected = vec![first, second, local_third.clone()];
        assert_eq!(*lock(&exchange.epoch), expected);
        assert_eq!(KeyStore::new(dir).epoch().unwrap(), expected);
        assert_eq!(server.epoch_head(), Some((3, head_of(&local_third))));
    }

    async fn check_scheduler(
        sender: &Arc<Peers>,
        peers: &Arc<Peers>,
        dir: &std::path::Path,
        peer_dir: &std::path::Path,
        routes: &PeerTestRoutes,
    ) {
        let PeerTestRoutes {
            busy_requests,
            partitioned,
            stalled,
            healthy_requests,
            selective_pushes,
            summary_requests,
            ..
        } = routes;
        let busy = sender.repair_peer("local").await.unwrap_err();
        assert!(matches!(
            busy.downcast_ref::<PeerError>(),
            Some(PeerError::Busy)
        ));
        let worker = sender.clone();
        let repair_task = tokio::spawn(async move { worker.repair_loop().await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while busy_requests.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("busy peer was not retried");
        partitioned.store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), stalled.notified())
            .await
            .expect("stalled peer was not contacted");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if sender.engine.durable_snapshot().await.unwrap()
                    == peers.engine.durable_snapshot().await.unwrap()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("periodic repair after partition did not converge");
        healthy_requests.store(0, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), async {
            while healthy_requests.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("healthy peer was not repaired periodically while another peer stalled");
        assert!(
            sender.repair_peak.load(Ordering::Relaxed) >= 2,
            "a stalled peer must open a progress slot"
        );
        assert_eq!(
            KeyStore::new(peer_dir).peer_state().unwrap(),
            KeyStore::new(dir).peer_state().unwrap(),
        );
        assert!(
            selective_pushes.load(Ordering::SeqCst) > 0,
            "partition repair must exercise selective exchange"
        );
        repair_task.abort();
        let _ = repair_task.await;
        let requests_before = healthy_requests.load(Ordering::SeqCst);
        let summaries_before = summary_requests.load(Ordering::SeqCst);
        sender
            .repair_peer("local")
            .await
            .expect("equal durable states should reconcile");
        assert_eq!(
            healthy_requests.load(Ordering::SeqCst) - requests_before,
            1,
            "idle repair uses one digest probe"
        );
        assert_eq!(
            summary_requests.load(Ordering::SeqCst),
            summaries_before,
            "idle repair must not send summaries"
        );
    }

    async fn check_large_upload(
        sender: &Arc<Peers>,
        peer_claim: &Claim,
        exchange: &Arc<Exchange>,
        server: &Arc<EnrollServer>,
        dir: &std::path::Path,
        routes: &PeerTestRoutes,
    ) -> Arc<Peers> {
        let PeerTestRoutes {
            target,
            pause_chunk,
            chunk_started,
            chunk_resume,
            ..
        } = routes;
        // Writes to a node's state carry that node's generation clock.
        let clock = &sender.exchange.clock;
        let mut large = sender.engine.durable_snapshot().await.unwrap();
        for i in 0..20_000 {
            let mut claim = peer_claim.clone();
            claim.exp += i;
            large
                .put(Entry::Claim(claim), "R", &Policy::default(), now(), clock)
                .unwrap();
        }
        assert!(large.to_bytes().len() > MAX_SYNC_BYTES);
        {
            let mut state = sender.exchange.state.write().await;
            sender.exchange.store.store_peer_state(&large).unwrap();
            *state = large;
        }
        pause_chunk.store(2, Ordering::SeqCst);
        let in_flight = {
            let sender = sender.clone();
            tokio::spawn(async move { sender.repair_peer("local").await })
        };
        tokio::time::timeout(Duration::from_secs(60), chunk_started.notified())
            .await
            .expect("upload did not reach a second chunk");
        let before_restart = KeyStore::new(dir).peer_state().unwrap();
        let peers = Peers::new(
            exchange.settings.clone(),
            None,
            server.clone(),
            Arc::new(UnusedDirectory),
            Arc::new(UnusedInitiator),
            KeyStore::new(dir),
        )
        .unwrap();
        assert_eq!(
            peers.engine.durable_snapshot().await.unwrap(),
            before_restart,
            "partial upload must not survive restart as a merge"
        );
        *lock(target) = Some(peers.clone());
        chunk_resume.notify_one();
        assert!(
            in_flight.await.unwrap().is_err(),
            "a restarted receiver must reject a continuation"
        );
        sender
            .repair_peer("local")
            .await
            .expect("large upload should reconcile after restart");
        assert_eq!(
            sender.engine.durable_snapshot().await.unwrap(),
            peers.engine.durable_snapshot().await.unwrap()
        );
        peers
    }

    async fn check_large_download(
        sender: &Arc<Peers>,
        peers: &Arc<Peers>,
        peer_claim: &Claim,
        dir: &std::path::Path,
        peer_dir: &std::path::Path,
        routes: &PeerTestRoutes,
    ) {
        let PeerTestRoutes {
            pause_chunk,
            chunk_started,
            chunk_resume,
            healthy_requests,
            ..
        } = routes;
        let clock = &peers.exchange.clock;
        let mut large = peers.engine.durable_snapshot().await.unwrap();
        for i in 20_000..40_000 {
            let mut claim = peer_claim.clone();
            claim.exp += i;
            large
                .put(Entry::Claim(claim), "R", &Policy::default(), now(), clock)
                .unwrap();
        }
        {
            let mut state = peers.exchange.state.write().await;
            peers.exchange.store.store_peer_state(&large).unwrap();
            *state = large;
        }
        let before_pull = sender.engine.durable_snapshot().await.unwrap();
        pause_chunk.store(1, Ordering::SeqCst);
        let in_flight = {
            let sender = sender.clone();
            tokio::spawn(async move { sender.repair_peer("local").await })
        };
        tokio::time::timeout(Duration::from_secs(60), chunk_started.notified())
            .await
            .expect("download did not reach a second chunk");
        {
            let mut state = peers.exchange.state.write().await;
            let mut claim = peer_claim.clone();
            claim.exp += 40_001;
            state
                .put(Entry::Claim(claim), "R", &Policy::default(), now(), clock)
                .unwrap();
            peers.exchange.store.store_peer_state(&state).unwrap();
        }
        assert_eq!(
            sender.engine.durable_snapshot().await.unwrap(),
            before_pull,
            "a partial download must not merge"
        );
        chunk_resume.notify_one();
        // The download is pinned to the snapshot it started on: it completes
        // even though the peer wrote meanwhile, and nothing is uploaded back
        // (the sender held nothing the peer lacked).
        in_flight
            .await
            .unwrap()
            .expect("a pinned download completes across a concurrent write");
        let pulled = sender.engine.durable_snapshot().await.unwrap();
        assert_ne!(pulled, before_pull, "the download merged");
        assert_ne!(
            pulled,
            peers.engine.durable_snapshot().await.unwrap(),
            "the concurrent write is not part of the pinned snapshot"
        );
        // The concurrent write is one entry: the next repair moves it alone.
        let requests_before = healthy_requests.load(Ordering::SeqCst);
        sender
            .repair_peer("local")
            .await
            .expect("large download should reconcile after concurrent write");
        let requests = healthy_requests.load(Ordering::SeqCst) - requests_before;
        assert!(
            requests < 20,
            "one changed entry is repaired entry by entry, not by a snapshot ({requests} requests)"
        );
        assert_eq!(
            KeyStore::new(peer_dir).peer_state().unwrap(),
            KeyStore::new(dir).peer_state().unwrap()
        );
    }

    async fn check_peer_bootstrap(
        dir: &std::path::Path,
        server: &Arc<EnrollServer>,
        exchange: &Arc<Exchange>,
    ) -> (Arc<Peers>, AnchorState, Claim) {
        let stored_key = SigningKey::generate_preferred().unwrap();
        let mut saved = AnchorState::default();
        saved
            .put(
                Entry::Key(stored_key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                now(),
                &GenerationClock::new(),
            )
            .unwrap();
        KeyStore::new(dir).store_peer_state(&saved).unwrap();
        let peers = Peers::new(
            exchange.settings.clone(),
            None,
            server.clone(),
            Arc::new(UnusedDirectory),
            Arc::new(UnusedInitiator),
            KeyStore::new(dir),
        )
        .unwrap();
        let inbound_key = SigningKey::generate_preferred().unwrap();
        let mut inbound = AnchorState::default();
        inbound
            .put(
                Entry::Key(inbound_key.public().to_jwk_json()),
                "R",
                &Policy::default(),
                now(),
                &GenerationClock::new(),
            )
            .unwrap();
        let peer_claim = Claim {
            realm: "R".into(),
            server: "peer".into(),
            anchor: None,
            key: *inbound_key.public().thumbprint(),
            iat: now(),
            exp: now() + 3600,
        };
        let own = Delegation::new(&peer_claim);
        let own_hash = PeerSync::delegation_hash(&own).unwrap();
        let chain_hash = PeerSync::chain_hash(&[]).unwrap();
        let sync_of = |body: RequestBody, context: bool| {
            let payload = payload(body);
            let token =
                PeerSync::channel_binding("peer", "local", &own_hash, &payload, &chain_hash)
                    .unwrap()
                    .to_vec();
            PeerSync {
                sender: "peer".into(),
                receiver: "local".into(),
                own_hash,
                own: context.then(|| own.clone()),
                payload,
                token,
                chain_hash,
                chain: context.then(Vec::new),
            }
            .to_bytes()
        };
        let message = |body: RequestBody| sync_of(body, true);
        check_context(&peers, &sync_of, &message, &inbound, &saved).await;

        let buckets_sync = check_summary(&peers, &message, &inbound, &saved).await;

        saved = check_upload(&peers, &message, &inbound, saved, dir, &buckets_sync).await;

        check_persistence(&peers, &message, &inbound, saved, dir, exchange, server).await;
        (peers, inbound, peer_claim)
    }

    fn bootstrap_sender(
        peer_dir: &std::path::Path,
        inbound: &AnchorState,
        peer_claim: &Claim,
        exchange: &Arc<Exchange>,
        server: &Arc<EnrollServer>,
        address: std::net::SocketAddr,
    ) -> Arc<Peers> {
        let mut peer_state = inbound.clone();
        peer_state
            .put(
                Entry::Claim(peer_claim.clone()),
                "R",
                &Policy::default(),
                now(),
                &GenerationClock::new(),
            )
            .unwrap();
        KeyStore::new(peer_dir)
            .store_peer_state(&peer_state)
            .unwrap();
        let mut settings = exchange.settings.clone();
        settings.me = "peer".into();
        settings.peers = vec!["a-stalled".into(), "local".into()];
        settings.endpoints = BTreeMap::from([
            ("a-stalled".into(), format!("http://{address}/stall")),
            ("local".into(), format!("http://{address}")),
        ]);
        for i in 0..15 {
            let peer = format!("n-padding-{i:02}");
            settings
                .endpoints
                .insert(peer.clone(), format!("http://{address}"));
            settings.peers.push(peer);
        }
        assert_eq!(repair_concurrency(settings.peers.len() + 1), 1);
        settings.interval = Duration::from_millis(100);
        Peers::new(
            settings,
            None,
            server.clone(),
            Arc::new(UnusedDirectory),
            Arc::new(UnusedInitiator),
            KeyStore::new(peer_dir),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn catch_up_and_persisted_peer_bootstrap() {
        let anchor = SigningKey::generate_preferred().unwrap();
        let first = epoch_at(epoch::GENESIS, 1, &[&anchor]);
        let second = epoch_at(head_of(&first), 2, &[&anchor]);
        let pages = Arc::new(Mutex::new(vec![first.clone(), second.clone()]));
        let requested = Arc::new(Mutex::new(Vec::new()));
        let pause = Arc::new(AtomicBool::new(false));
        let started = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let target: Arc<Mutex<Option<Arc<Peers>>>> = Arc::new(Mutex::new(None));
        let partitioned = Arc::new(AtomicBool::new(true));
        let stalled = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let healthy_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let busy_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let selective_pushes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let summary_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let pause_chunk = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let chunk_started = Arc::new(Notify::new());
        let chunk_resume = Arc::new(Notify::new());
        let routes = PeerTestRoutes {
            target: target.clone(),
            partitioned: partitioned.clone(),
            healthy_requests: healthy_requests.clone(),
            busy_requests: busy_requests.clone(),
            selective_pushes: selective_pushes.clone(),
            summary_requests: summary_requests.clone(),
            pause_chunk: pause_chunk.clone(),
            chunk_started: chunk_started.clone(),
            chunk_resume: chunk_resume.clone(),
            pages: pages.clone(),
            requested: requested.clone(),
            pause: pause.clone(),
            started: started.clone(),
            resume: resume.clone(),
            stalled: stalled.clone(),
            release: release.clone(),
        };
        let app = bootstrap_test_routes(&routes);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = std::env::temp_dir().join(format!(
            "kuipa-epoch-http-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let (server, exchange) = bootstrap_exchange(&anchor, address, &dir);
        check_epoch_catch_up(&anchor, first, second, &dir, &server, &exchange, &routes).await;
        let (peers, inbound, peer_claim) = check_peer_bootstrap(&dir, &server, &exchange).await;
        *lock(&target) = Some(peers.clone());
        let peer_dir = dir.join("peer");
        std::fs::create_dir(&peer_dir).unwrap();
        let sender = bootstrap_sender(
            &peer_dir,
            &inbound,
            &peer_claim,
            &exchange,
            &server,
            address,
        );
        check_scheduler(&sender, &peers, &dir, &peer_dir, &routes).await;
        let peers =
            check_large_upload(&sender, &peer_claim, &exchange, &server, &dir, &routes).await;
        check_large_download(&sender, &peers, &peer_claim, &dir, &peer_dir, &routes).await;
        release.notify_waiters();
        server_task.abort();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn epoch_pages_update_memory_disk_and_publication() {
        let dir = std::env::temp_dir().join(format!(
            "kuipa-epoch-pages-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let store = KeyStore::new(&dir);
        let anchor = SigningKey::generate_preferred().unwrap();
        let first = epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&anchor]);
        let second = epoch_at(head_of(&first), 2, &[&anchor]);
        let state = Mutex::new(Vec::new());
        let mut published = Vec::new();
        let genesis = (0, epoch::GENESIS);
        let missing = KeyStore::new(dir.join("missing"));
        assert!(
            store_epoch_page(&missing, &state, genesis, vec![first.clone()], |_| {
                panic!("failed writes must not publish");
            })
            .is_err()
        );
        assert!(
            lock(&state).is_empty(),
            "failed writes must not change memory"
        );
        store_epoch_page(&store, &state, genesis, vec![first.clone()], |chain| {
            published = chain;
        })
        .unwrap();
        assert!(
            store_epoch_page(&store, &state, genesis, vec![second.clone()], |_| {
                panic!("a stale page must not publish");
            })
            .is_err()
        );
        store_epoch_page(
            &store,
            &state,
            (1, head_of(&first)),
            vec![second.clone()],
            |chain| published = chain,
        )
        .unwrap();
        let stored = store.epoch().unwrap();
        let memory = lock(&state).clone();
        std::fs::remove_dir_all(&dir).unwrap();
        let expected = vec![first, second];
        assert_eq!(memory, expected, "each page must advance the shared chain");
        assert_eq!(
            stored, expected,
            "each page must extend the persisted chain"
        );
        assert_eq!(published, expected, "the complete chain must be published");
    }

    #[test]
    fn a_longer_window_that_continues_the_log_is_adopted_and_keeps_both_signatures() {
        let (a, b) = (
            SigningKey::generate_preferred().unwrap(),
            SigningKey::generate_preferred().unwrap(),
        );
        let ours = vec![epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&a, &b])];
        // the same entry, signed by b: named anchors are sorted, so
        // order says nothing
        let e1b = epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&b, &a]);
        let theirs = vec![e1b.clone(), epoch_at(head_of(&e1b), 2, &[&b, &a])];
        let (merged, outcome) = merge_chain("R", &Policy::default(), &ours, &theirs);
        assert!(
            matches!(outcome, Merge::Extended),
            "the window continues ours"
        );
        assert_eq!(merged.len(), 2, "the longer window is adopted");
        let ep = merged[0].statement().unwrap();
        assert_eq!(
            merged[0].verify(&ep, &Policy::default()).unwrap(),
            [a.public().thumbprint(), b.public().thumbprint()]
                .into_iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            "our signature survives the adoption"
        );
    }

    #[test]
    fn a_shorter_window_only_adds_signatures() {
        let (a, b) = (
            SigningKey::generate_preferred().unwrap(),
            SigningKey::generate_preferred().unwrap(),
        );
        let e1 = epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&a, &b]);
        let ours = vec![e1.clone(), epoch_at(head_of(&e1), 2, &[&a, &b])];
        let theirs = vec![epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&b, &a])];
        let (merged, outcome) = merge_chain("R", &Policy::default(), &ours, &theirs);
        assert!(matches!(outcome, Merge::Kept), "nothing past our head");
        assert_eq!(merged.len(), 2, "our longer chain stays");
        let ep = merged[0].statement().unwrap();
        assert_eq!(merged[0].verify(&ep, &Policy::default()).unwrap().len(), 2);
    }

    #[test]
    fn a_different_statement_at_a_sequence_we_hold_is_a_fork() {
        let (a, b) = (
            SigningKey::generate_preferred().unwrap(),
            SigningKey::generate_preferred().unwrap(),
        );
        let ours = vec![epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&a])];
        let e1b = epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&b]);
        let theirs = vec![e1b.clone(), epoch_at(head_of(&e1b), 2, &[&b])];
        let (merged, outcome) = merge_chain("R", &Policy::default(), &ours, &theirs);
        assert!(
            matches!(outcome, Merge::Conflict),
            "the longer divergent chain is not adopted"
        );
        assert_eq!(merged, ours, "our log stands");
    }

    #[test]
    fn a_window_that_does_not_commit_to_our_head_is_a_fork() {
        let a = SigningKey::generate_preferred().unwrap();
        let ours = vec![epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&a])];
        let e2 = epoch_at([9; 48], 2, &[&a]);
        let theirs = vec![e2.clone(), epoch_at(head_of(&e2), 3, &[&a])];
        let (merged, outcome) = merge_chain("R", &Policy::default(), &ours, &theirs);
        assert!(
            matches!(outcome, Merge::Conflict),
            "an entry naming another predecessor forks from our head"
        );
        assert_eq!(merged, ours);
    }

    #[test]
    fn a_window_past_our_end_without_a_shared_entry_leaves_a_gap() {
        let a = SigningKey::generate_preferred().unwrap();
        let ours = vec![epoch_at(kuipa_enroll::epoch::GENESIS, 1, &[&a])];
        let e5 = epoch_at([7; 48], 5, &[&a]);
        let theirs = vec![e5.clone(), epoch_at(head_of(&e5), 6, &[&a])];
        let (merged, outcome) = merge_chain("R", &Policy::default(), &ours, &theirs);
        assert!(
            matches!(outcome, Merge::Gap),
            "what lies between is fetched, not assumed"
        );
        assert_eq!(merged, ours);
    }

    #[test]
    fn the_sync_window_is_a_recent_tail_within_budget() {
        let a = SigningKey::generate_preferred().unwrap();
        let mut chain = Vec::new();
        let mut prev = kuipa_enroll::epoch::GENESIS;
        for seq in 1..=8 {
            let entry = epoch_at(prev, seq, &[&a]);
            prev = head_of(&entry);
            chain.push(entry);
        }
        let full: Vec<Vec<u8>> = chain
            .iter()
            .map(|e| kuipa_enroll::epoch::encode(e).unwrap())
            .collect();
        assert!(
            full.iter().map(Vec::len).sum::<usize>() > MAX_SYNC_EPOCH_BYTES,
            "the fixture must be long enough to cut"
        );
        let window = epoch_window(&chain).unwrap();
        assert!(
            !window.is_empty() && window.len() < chain.len(),
            "a bounded tail"
        );
        assert_eq!(
            window,
            full[full.len() - window.len()..],
            "the window is the newest suffix, in order"
        );
        let bytes: usize = window.iter().map(Vec::len).sum();
        assert!(
            bytes <= MAX_SYNC_EPOCH_BYTES + full.last().unwrap().len(),
            "the newest entry is always carried; nothing else overruns the budget"
        );
    }
}

#[cfg(test)]
#[path = "peers_benchmark.rs"]
mod benchmark;
