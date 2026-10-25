//! The anchor exchange (§4.2): agirru gossip between servers over
//! `POST /ipa/ku/peer/sync`, each request authenticated with the sending
//! server's `ipa-ku/<fqdn>` Kerberos key.
//!
//! Peers are the IPA servers found in LDAP (`cn=masters`) plus configured
//! ones.  After every change the exchange renews this server's claim when
//! due, has its anchor vouch for every claim it trusts (one signature over
//! a Merkle tree), and publishes its claim, with every trusted anchor's
//! proof, and the trusted anchors to the [`EnrollServer`].

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use agirru_crdt::GenerationClock;
use agirru_engine::{
    CborCodec, GossipConfig, GossipEngine, GossipHooks, GossipRuntime, Membership, SendOutcome,
    Storage, Transport,
};
use kuipa_enroll::EnrollServer;
use kuipa_enroll::anchors::{self, AnchorState, Entry, PeerSync, Trust};
use kuipa_enroll::delegation::{
    Claim, DEFAULT_VALIDITY, Delegation, SignedSuccession, SignedVouch, VOUCH_VALIDITY,
};
use kuipa_enroll::epoch::{self, AnchorEpoch, SignedEpoch};
use kuipa_enroll::merkle::TreeHash;
use kuipa_enroll::server::Directory;
use rustls::pki_types::CertificateDer;
use rustls_native_ossl::cert_verifier::OsslServerCertVerifier;
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
    /// Anything else.
    Failed(String),
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => f.write_str("the peer refused the sync"),
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
    client: reqwest::Client,
    /// The last failure per peer, so each is logged once.
    failures: Mutex<BTreeMap<String, String>>,
}

type Engine = GossipEngine<AnchorState, String, Runtime>;

/// The running exchange.
pub struct Peers {
    exchange: Arc<Exchange>,
    engine: Arc<Engine>,
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
    let roots: Vec<_> = settings
        .ca_certs
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let verifier = OsslServerCertVerifier::builder(&roots)?.build();
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
        let state = Arc::new(RwLock::new(store.peer_state()?));
        let chain = store.epoch()?;
        let mut members: BTreeSet<String> = settings.peers.iter().cloned().collect();
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
            attested: Mutex::new(BTreeMap::new()),
            epoch: Mutex::new(chain.clone()),
            forked: AtomicBool::new(false),
            settling: Mutex::new(None),
            changed: Notify::new(),
            failures: Mutex::new(BTreeMap::new()),
        });
        exchange.server.publish_epoch(chain);
        let config = GossipConfig {
            round_interval: exchange.settings.interval,
            ..GossipConfig::default()
        };
        let engine = Arc::new(GossipEngine::bootstrap_with_state(
            clock,
            Runtime(exchange.clone(), CborCodec),
            config,
            state,
        ));
        Ok(Arc::new(Self { exchange, engine }))
    }

    /// Run the gossip rounds and the maintenance loop forever.
    pub async fn run(self: Arc<Self>) {
        let engine = self.engine.clone();
        tokio::spawn(async move { engine.run().await });
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

        let mut state = x.state.write().await;
        let before = state.len();
        state.retain(&members, realm, &x.policy, at);
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
        if wrote || state.len() != before {
            x.store.store_peer_state(&state)?;
        }
        drop(state);
        if wrote {
            self.engine.notify_local_change();
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
        let x = &self.exchange;
        let sync = PeerSync::from_bytes(body)?;
        let cb = PeerSync::channel_binding(
            &sync.sender,
            &sync.receiver,
            &sync.own,
            &sync.envelope,
            &sync.chain,
        )?;
        let directory = x.directory.clone();
        let token = sync.token.clone();
        let principal =
            tokio::task::spawn_blocking(move || directory.accept_peer(&token, &cb)).await??;
        x.refresh_members().await;
        let own = sync.attest(
            &principal,
            &x.settings.me,
            &x.members(),
            &x.settings.realm,
            &x.policy,
            now(),
        )?;
        let fresh = lock(&x.attested).insert(sync.sender.clone(), own.clone()) != Some(own);
        if fresh {
            x.changed.notify_one();
        }
        // §4.8: merge the peer's window of the anchor epoch log:
        // shared entries keep both signature sets, a window that
        // continues our log is adopted, a window that jumps past our
        // end is fetched, and a disagreement on a sequence both have
        // pauses appending — two servers must not keep extending
        // divergent histories.
        let theirs: Vec<SignedEpoch> = sync
            .chain
            .iter()
            .filter_map(|b| epoch::decode(b).ok())
            .collect();
        let mut gap = false;
        if !theirs.is_empty() {
            let mut chain = lock(&x.epoch);
            let (merged, outcome) = merge_chain(&x.settings.realm, &x.policy, &chain, &theirs);
            if merged != *chain {
                // Store before committing in memory: an unstored log is
                // not a record, and a failed write then retries next
                // round instead of advertising from memory alone.
                if let Err(e) = x.store.store_epoch(&merged) {
                    eprintln!("kuipad: anchor exchange: cannot store the anchor log: {e}");
                } else {
                    *chain = merged;
                    x.server.publish_epoch(chain.clone());
                    x.changed.notify_one();
                }
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
                }
                Merge::Gap => gap = true,
                Merge::Kept | Merge::Extended => {}
            }
        }
        if gap && let Err(e) = x.catch_up(&sync.sender).await {
            eprintln!(
                "kuipad: anchor exchange: cannot fetch the anchor log from {}: {e}",
                sync.sender
            );
        }
        // The engine answers an envelope it cannot decode with nothing; a
        // real answer is never empty.
        let response = self
            .engine
            .handle_inbound(&sync.sender, sync.envelope)
            .await;
        if response.is_empty() {
            return Err("cannot decode the gossip envelope".into());
        }
        Ok(response)
    }
}

impl Exchange {
    /// Every member, this server included.
    fn members(&self) -> BTreeSet<String> {
        lock(&self.members).0.clone()
    }

    /// Ask the directory for the server list at most every five rounds;
    /// on failure keep the previous members.
    async fn refresh_members(&self) {
        if !self.settings.discover
            || lock(&self.members)
                .1
                .is_some_and(|t| t.elapsed() < self.settings.interval * 5)
        {
            return;
        }
        let directory = self.directory.clone();
        let servers = tokio::task::spawn_blocking(move || directory.servers()).await;
        let mut members = lock(&self.members);
        match servers {
            Ok(Ok(servers)) => {
                let mut set: BTreeSet<String> = servers
                    .into_iter()
                    .chain(self.settings.peers.iter().cloned())
                    .map(|s| s.to_ascii_lowercase())
                    .collect();
                set.insert(self.settings.me.clone());
                *members = (set, Some(Instant::now()));
            }
            Ok(Err(e)) => {
                eprintln!("kuipad: anchor exchange: cannot list servers: {e}");
                members.1 = Some(Instant::now());
            }
            Err(e) => eprintln!("kuipad: anchor exchange: {e}"),
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

    async fn sync(&self, peer: &str, envelope: Vec<u8>) -> Result<Vec<u8>, PeerError> {
        let me = self.settings.me.clone();
        let own = {
            let state = self.state.read().await;
            match &self.anchor {
                Some(a) => state.own_delegation(&me, a.public()).map_err(failed)?,
                None => state.latest_claim(&me, None).map(Delegation::new),
            }
        }
        .ok_or_else(|| failed("no own claim yet"))?;
        let chain = self.epoch_bytes();
        let cb = PeerSync::channel_binding(&me, peer, &own, &envelope, &chain).map_err(failed)?;
        let initiator = self.initiator.clone();
        let target = peer.to_owned();
        let token = tokio::task::spawn_blocking(move || initiator.token(&target, &cb))
            .await
            .map_err(failed)?
            .map_err(failed)?;
        let body = PeerSync {
            sender: me,
            receiver: peer.to_owned(),
            own,
            envelope,
            token,
            chain,
        }
        .to_bytes();
        let response = self
            .client
            .post(self.url(peer))
            .header("content-type", "application/vnd.ipa-ku.peer-sync")
            .body(body)
            .send()
            .await
            .map_err(failed)?;
        match response.status() {
            reqwest::StatusCode::OK => {
                let body = response.bytes().await.map_err(failed)?;
                if body.is_empty() {
                    return Err(failed("the peer answered with no state"));
                }
                Ok(body.to_vec())
            }
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                Err(PeerError::Rejected)
            }
            status => Err(PeerError::Failed(format!("HTTP {status}"))),
        }
    }

    /// A bounded tail window of the chain, encoded for the wire (§4.8).
    fn epoch_bytes(&self) -> Vec<Vec<u8>> {
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
            let response = self
                .client
                .get(format!("{}/anchor-log?from={}", self.base(peer), seq))
                .send()
                .await?;
            if !response.status().is_success() {
                return Err(format!("HTTP {}", response.status()).into());
            }
            let body: serde_json::Value = serde_json::from_str(&response.text().await?)?;
            let entries: Vec<SignedEpoch> = serde_json::from_value(body["entries"].clone())?;
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
            let mut chain = lock(&self.epoch).clone();
            chain.extend(entries);
            self.store.store_epoch(&chain)?;
            self.server.publish_epoch(chain);
            self.changed.notify_one();
            (seq, head) = reached;
        }
    }
}

impl Transport<String> for Exchange {
    type Error = PeerError;

    async fn send_recv(&self, peer: &String, envelope: Vec<u8>) -> Result<Vec<u8>, PeerError> {
        let result = self.sync(peer, envelope).await;
        self.note(peer, &result);
        result
    }

    fn classify_error(&self, err: &PeerError) -> SendOutcome {
        match err {
            PeerError::Rejected => SendOutcome::AuthRejected,
            PeerError::Failed(_) => SendOutcome::Failed,
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
        std::future::ready(self.store.peer_state().map_err(failed))
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

    async fn on_merged(&self, _peer: &String, _after: &AnchorState, _inbound: &AnchorState) {
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
            return (ours.to_vec(), Merge::Kept);
        };
        if epoch.realm() != realm || !signed.verify(&epoch, policy).is_ok_and(|v| !v.is_empty()) {
            return (ours.to_vec(), Merge::Kept);
        }
        if let Some((seq, head)) = expect
            && (epoch.seq() != seq || epoch.prev() != head)
        {
            return (ours.to_vec(), Merge::Kept);
        }
        let Ok(head) = epoch.head() else {
            return (ours.to_vec(), Merge::Kept);
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
fn epoch_window(chain: &[SignedEpoch]) -> Vec<Vec<u8>> {
    let mut window: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0;
    for entry in chain.iter().rev() {
        let Ok(encoded) = epoch::encode(entry) else {
            continue;
        };
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
    window
}

/// The agirru runtime: every part is the [`Exchange`].
pub struct Runtime(Arc<Exchange>, CborCodec);

impl GossipRuntime<AnchorState, String> for Runtime {
    type Transport = Exchange;
    type Membership = Exchange;
    type Storage = Exchange;
    type Hooks = Exchange;
    type Codec = CborCodec;

    fn transport(&self) -> &Exchange {
        &self.0
    }
    fn membership(&self) -> &Exchange {
        &self.0
    }
    fn storage(&self) -> &Exchange {
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
    use agirru_engine::{Codec, Envelope};

    use super::*;

    /// The state inside agirru's CBOR envelope, with entries larger than a
    /// streaming decoder's scratch buffer.
    #[test]
    fn envelopes_round_trip_through_cbor() {
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
        let envelope = Envelope {
            state: state.clone(),
            issued_at: 0,
            is_delta: false,
            sender_gen: 1,
            request_delta_since: None,
            sender_observed_clock: None,
        };
        let bytes = CborCodec.encode(&envelope).unwrap();
        let back: Envelope<AnchorState> = CborCodec.decode(&bytes).unwrap();
        assert_eq!(back.state, state);
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
        let window = epoch_window(&chain);
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
