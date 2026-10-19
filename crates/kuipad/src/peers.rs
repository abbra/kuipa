//! The anchor exchange (§4.2): agirru gossip between servers over
//! `POST /ipa/ku/peer/sync`, each request authenticated with the sending
//! server's `ipa-ku/<fqdn>` Kerberos key.
//!
//! Peers are the IPA servers found in LDAP (`cn=masters`) plus configured
//! ones.  After every change the exchange renews this server's claim when
//! due, has its anchor vouch for every claim it trusts (one signature over
//! a Merkle tree), and publishes its claim, with every trusted anchor's
//! proof, and the trusted anchors to the [`EnrollServer`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
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
        let cred = kuipa_gssapi::GssClientCred::from_keytab_initiate_named(
            &self.keytab,
            &self.principal,
            &format!("MEMORY:kuipa-peer-{}", self.principal),
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
                .verify_at(&[*a.public().thumbprint()], &Policy::default(), at)
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
            policy: Policy::default(),
            server,
            directory,
            initiator,
            store,
            state: state.clone(),
            clock: clock.clone(),
            members: Mutex::new((members, None)),
            attested: Mutex::new(BTreeMap::new()),
            epoch: Mutex::new(chain.clone()),
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
            let leaves = trust.leaves()?;
            let current_vouch = state.vouch(anchor.public().thumbprint());
            let interval = x.settings.vouch_interval.as_secs();
            if anchors::needs_vouch(current_vouch, &leaves, at, interval) {
                let iat = anchors::next_vouch_iat(current_vouch, at);
                eprintln!(
                    "kuipad: anchor exchange: vouching for {} claim(s) of {:?}",
                    leaves.len(),
                    trust.servers().collect::<Vec<_>>()
                );
                let vouch = SignedVouch::issue(anchor, realm, leaves, iat, iat + VOUCH_VALIDITY)?;
                wrote |= put(&mut state, Entry::Vouch(vouch))?;
            }
        }
        let candidate = trust.own_delegation(&state)?;
        let epoch_successions: Vec<SignedSuccession> = state.successions().cloned().collect();
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
        if advertised != current {
            x.store.store_delegation(&advertised)?;
        }
        if advertised != current || trusted != x.server.anchors() {
            eprintln!(
                "kuipad: anchor exchange: trusted anchors: {}, proofs for this server's claim: {}",
                trusted.len(),
                advertised.proof_count()
            );
            x.server.publish(advertised, trusted.clone());
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
        // §4.8: adopt the peer's anchor epoch log when it is the longer
        // valid one, and keep both signature sets on shared entries.
        let theirs: Vec<SignedEpoch> = sync
            .chain
            .iter()
            .filter_map(|b| epoch::decode(b).ok())
            .collect();
        if !theirs.is_empty() {
            let mut chain = lock(&x.epoch);
            let merged = merge_chain(&x.settings.realm, &x.policy, &chain, &theirs);
            if merged != *chain {
                *chain = merged;
                if let Err(e) = x.store.store_epoch(&chain) {
                    eprintln!("kuipad: anchor exchange: cannot store the anchor log: {e}");
                }
                x.server.publish_epoch(chain.clone());
                x.changed.notify_one();
            }
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

    fn url(&self, peer: &str) -> String {
        let base = self.settings.endpoints.get(peer).map_or_else(
            || format!("https://{peer}"),
            |b| b.trim_end_matches('/').to_owned(),
        );
        format!("{base}/ipa/ku/peer/sync")
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

    /// The chain entries, encoded for the wire (§4.8).
    fn epoch_bytes(&self) -> Vec<Vec<u8>> {
        lock(&self.epoch)
            .iter()
            .filter_map(|e| epoch::encode(e).ok())
            .collect()
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
/// only the entry's does.
fn mint_epoch(
    x: &Exchange,
    realm: &str,
    anchor: &SigningKey,
    trusted: &[Thumbprint],
    successions: &[SignedSuccession],
) -> Result<(), Error> {
    let mut chain = lock(&x.epoch);
    let current = chain.last().and_then(|e| e.statement().ok());
    let seq = current.as_ref().map_or(0, AnchorEpoch::seq);
    let entry = AnchorEpoch::new(
        realm,
        seq + 1,
        trusted.iter().copied(),
        successions.iter().cloned(),
    );
    let fresh = current
        .as_ref()
        .is_none_or(|s| s.anchors() != entry.anchors() || s.successions() != entry.successions());
    if fresh {
        eprintln!(
            "kuipad: anchor exchange: recording anchor epoch {}",
            seq + 1
        );
        chain.push(SignedEpoch::issue(anchor, &entry)?);
        x.store.store_epoch(&chain)?;
        x.server.publish_epoch(chain.clone());
    }
    Ok(())
}

/// Merge a peer's anchor epoch log with ours (§4.8): the longer valid
/// chain wins, entries both servers signed keep both signature sets, and
/// a chain that does not continue itself or fails to vouch for itself is
/// ignored.
fn merge_chain(
    realm: &str,
    policy: &Policy,
    ours: &[SignedEpoch],
    theirs: &[SignedEpoch],
) -> Vec<SignedEpoch> {
    let valid = |chain: &[SignedEpoch]| {
        let mut seq = 0;
        chain.iter().all(|e| {
            e.statement().is_ok_and(|ep| {
                ep.realm() == realm
                    && ep.seq() == seq + 1
                    && e.verify(&ep, policy).is_ok_and(|v| !v.is_empty())
                    && {
                        seq = ep.seq();
                        true
                    }
            })
        })
    };
    let mut chain = ours.to_vec();
    if valid(theirs) && theirs.len() > chain.len() {
        chain = theirs.to_vec();
        for e in &mut chain {
            for o in ours {
                let _ = e.merge(o);
            }
        }
    }
    for e in &mut chain {
        for t in theirs {
            let _ = e.merge(t);
        }
    }
    chain
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
        let vouch =
            SignedVouch::issue(&anchor, "R", [claim.leaf().unwrap()], now(), now() + 100).unwrap();
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

    fn epoch_of(signers: &[&SigningKey], seq: u64) -> kuipa_enroll::epoch::SignedEpoch {
        let named: Vec<tang_pqc::Thumbprint> =
            signers.iter().map(|k| *k.public().thumbprint()).collect();
        let entry = kuipa_enroll::epoch::AnchorEpoch::new("R", seq, named.iter().copied(), []);
        kuipa_enroll::epoch::SignedEpoch::issue(signers[0], &entry).unwrap()
    }

    #[test]
    fn the_longer_valid_chain_wins_and_keeps_both_signatures() {
        let (a, b) = (
            SigningKey::generate_preferred().unwrap(),
            SigningKey::generate_preferred().unwrap(),
        );
        let ours = vec![epoch_of(&[&a, &b], 1)];
        let mut e1b = epoch_of(&[&b, &a], 1);
        assert!(e1b.merge(&epoch_of(&[&a, &b], 1)));
        let theirs = vec![e1b, epoch_of(&[&b, &a], 2)];
        let merged = merge_chain("R", &Policy::default(), &ours, &theirs);
        assert_eq!(merged.len(), 2, "the longer chain is adopted");
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
    fn a_shorter_chain_only_adds_signatures() {
        let (a, b) = (
            SigningKey::generate_preferred().unwrap(),
            SigningKey::generate_preferred().unwrap(),
        );
        let ours = vec![epoch_of(&[&a, &b], 1), epoch_of(&[&a, &b], 2)];
        let theirs = vec![epoch_of(&[&b, &a], 1)];
        let merged = merge_chain("R", &Policy::default(), &ours, &theirs);
        assert_eq!(merged.len(), 2, "our longer chain stays");
        let ep = merged[0].statement().unwrap();
        assert_eq!(merged[0].verify(&ep, &Policy::default()).unwrap().len(), 2);
    }

    #[test]
    fn a_chain_that_does_not_start_at_one_is_ignored() {
        let a = SigningKey::generate_preferred().unwrap();
        let ours = vec![epoch_of(&[&a], 1)];
        let theirs = vec![epoch_of(&[&a], 2), epoch_of(&[&a], 3)];
        let merged = merge_chain("R", &Policy::default(), &ours, &theirs);
        assert_eq!(
            merged, ours,
            "a piece that does not start at the start proves nothing"
        );
    }
}
