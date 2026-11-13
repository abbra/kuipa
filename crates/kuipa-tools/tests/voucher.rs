//! Vouchers against a real MIT KDC (skipped when the KDC tools are not
//! installed), §9: the issuer makes a voucher key and a quota; the
//! provisioner blinds a voucher for a host, the issuer signs it without
//! seeing it, and the provisioner unblinds it; the host enrolls with it.
//! A voucher creates one host only, a bound voucher works only with its
//! ephemeral key, the quota counts every signature, and a voucher is spent on
//! the server it names whichever server takes the join.
//!
//! One test function: the servers are reached through thread endpoints.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use kuipa_enroll::delegation::Delegation;
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::realm::{Deployment, RealmInfo, ServerKeys, VerifiedRealm};
use kuipa_enroll::spend::{SpendError, SpendOp, SpendRequest, VoucherSpender};
use kuipa_enroll::voucher::{Claims, Voucher};
use kuipa_enroll::{Directory as _, EnrollServer};
use kuipa_tools::flows::{self, Auth};
use kuipa_tools::paths::Paths;
use kuipa_tools::voucher;
use kuipad::http::{App, router};
use support::directory::KdcDirectory;
use support::kdc::Realm;
use tang_pqc::{
    ExchangeKeyPair, KemAlg, Policy, SignatureAlg, SigningKey, VerifyingKey, b64, unix_seconds,
};

const REALM: &str = "VOUCHER.TEST";
const SERVER: &str = "ipa1.voucher.test";

fn now() -> u64 {
    unix_seconds(SystemTime::now())
}

fn claims(fqdn: &str, binding: Vec<u8>) -> Claims {
    Claims {
        realm: REALM.into(),
        fqdn: fqdn.into(),
        server: SERVER.into(),
        hostgroup: "webservers".into(),
        not_before: now() - 60,
        not_after: now() + 3600,
        lease: 0,
        binding,
    }
}

/// The issuer's files: its voucher key, its quota, and the public key its
/// vouchers verify under.
struct Issuer {
    dir: PathBuf,
    key: PathBuf,
    quota: PathBuf,
    public: String,
}

impl Issuer {
    /// A voucher key, and a quota of five signatures.
    fn new(dir: &Path) -> Self {
        let key = dir.join("issuer.pem");
        let quota = dir.join("quota.json");
        let public = voucher::keygen(&key, SignatureAlg::MlDsa65).unwrap();
        voucher::set_quota(&quota, 5).unwrap();
        Self {
            dir: dir.to_owned(),
            key,
            quota,
            public,
        }
    }

    /// The voucher for `claims`, blinded, signed by the issuer without
    /// seeing it, and unblinded.
    fn issue(&self, claims: &Claims, name: &str) -> Voucher {
        let state = self.dir.join(format!("{name}.state"));
        let request = voucher::request(self.public.as_bytes(), claims, &state).unwrap();
        // The issuer sees 64 bytes, nothing of the claims.
        assert_eq!(b64::decode(&request).unwrap().len(), 64);
        let response = voucher::sign(&self.key, &self.quota, &request).unwrap();
        voucher::finish(&state, &response).unwrap()
    }
}

/// The IPA server under test: its anchor, its enrollment string, and the
/// directory it writes to.
struct Ipa {
    name: String,
    dir: PathBuf,
    anchor: SigningKey,
    server: Arc<EnrollServer>,
    directory: Arc<KdcDirectory>,
    string: EnrollmentString,
}

impl Ipa {
    /// Start the server on a local port, accepting vouchers under `public`.
    fn start(realm: &Arc<Realm>, public: &str) -> Self {
        Self::start_named(realm, public, SERVER)
    }

    /// The same, as the IPA server `name`.
    fn start_named(realm: &Arc<Realm>, public: &str, name: &str) -> Self {
        let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let delegation = Delegation::issue(
            &anchor,
            REALM,
            name,
            signing.public(),
            now() - 60,
            now() + 86400,
        )
        .unwrap();
        let info = RealmInfo {
            realm: REALM.into(),
            domain: "voucher.test".into(),
            basedn: "dc=voucher,dc=test".into(),
            server: name.into(),
            servers: vec![name.into()],
            ca_certs: vec![realm.chain.ca_der.clone()],
            pkinit_anchors: vec![realm.chain.ca_der.clone()],
            anchors: vec![*anchor.public().thumbprint()],
            heads: Vec::new(),
            trusts: Vec::new(),
            kdc_proxy: None,
        };
        let keys = ServerKeys {
            signing,
            join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            trust: Vec::new(),
            vouchers: vec![VerifyingKey::from_jwk_json(public.as_bytes()).unwrap()],
            retired: Vec::new(),
        };
        let server = Arc::new(EnrollServer::new(keys, info, delegation));
        let directory = Arc::new(KdcDirectory::new(realm.clone(), &[name], &[]));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        kuipa_tools::net::set_thread_endpoint(name, &url);
        let app = Arc::new(App {
            server: server.clone(),
            directory: directory.clone(),
            peers: None,
            limiter: kuipad::limit::Limiter::default(),
            tang: None,
            keys: None,
            ledger: None,
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, router(app)).await.unwrap();
            });
        });
        let string = EnrollmentString::new(
            REALM,
            *anchor.public().thumbprint(),
            tang_pqc::unix_seconds(SystemTime::now()) + 86_400,
            None,
        );
        Self {
            name: name.to_owned(),
            dir: realm.dir.clone(),
            anchor,
            server,
            directory,
            string,
        }
    }

    /// Enroll `host` with `voucher`, sealed to `ephemeral` when bound.
    fn enroll(
        &self,
        host: &str,
        voucher: &Voucher,
        ephemeral: Option<&[u8]>,
    ) -> Result<serde_json::Value, kuipa_tools::paths::Error> {
        let root = self.dir.join(format!("root-{host}"));
        std::fs::create_dir_all(&root).unwrap();
        let auth = Auth::Voucher {
            voucher: Secret::new(voucher.encode().as_ref()),
            ephemeral: ephemeral.map(Secret::new),
        };
        flows::enroll_online(
            &Paths::new(&root),
            self.string.realm(),
            &[*self.string.anchor()],
            &[],
            &[],
            flows::Host {
                fqdn: host,
                auth: &auth,
            },
            &Deployment::servers(std::slice::from_ref(&self.name)),
        )
    }

    /// The advertisement publishes the voucher key.
    fn check_advertisement(&self, public: &str) {
        let thp = *self.anchor.public().thumbprint();
        let adv = VerifiedRealm::verify(
            &self.server.advertisement(&[thp]).unwrap(),
            REALM,
            &[thp],
            &Policy::default(),
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(
            adv.voucher_keys()
                .iter()
                .map(VerifyingKey::to_jwk_json)
                .collect::<Vec<_>>(),
            vec![public.to_owned()]
        );
    }
}

/// A bearer voucher creates its host, once, and for its own name only.
fn bearer_voucher_creates_one_host(realm: &Realm, ipa: &Ipa, issuer: &Issuer) {
    let web1 = issuer.issue(&claims("web1.voucher.test", Vec::new()), "web1");
    ipa.enroll("web1.voucher.test", &web1, None).unwrap();
    assert!(realm.has(&format!("host/web1.voucher.test@{REALM}")));
    assert_eq!(
        ipa.directory.hostgroups.lock().unwrap()["webservers"],
        ["web1.voucher.test"]
    );
    assert!(
        ipa.enroll("web1.voucher.test", &web1, None).is_err(),
        "used up"
    );
    // Not for another host.
    assert!(ipa.enroll("web9.voucher.test", &web1, None).is_err());
}

/// A bound voucher works only with its ephemeral key.
fn bound_voucher_needs_its_ephemeral_key(realm: &Realm, ipa: &Ipa, issuer: &Issuer) {
    let key_file = ipa.dir.join("web2-ephemeral.jwk");
    let binding = voucher::ephemeral(&key_file).unwrap();
    let web2 = issuer.issue(&claims("web2.voucher.test", binding), "web2");
    assert!(ipa.enroll("web2.voucher.test", &web2, None).is_err());
    assert!(!realm.has(&format!("host/web2.voucher.test@{REALM}")));
    let key = std::fs::read(&key_file).unwrap();
    ipa.enroll("web2.voucher.test", &web2, Some(&key)).unwrap();
}

/// A voucher under a key the realm does not know is refused (its signature
/// still counts against the shared quota file).
fn voucher_under_unknown_key_is_refused(ipa: &Ipa, issuer: &Issuer) {
    let stranger = ipa.dir.join("stranger.pem");
    let other = voucher::keygen(&stranger, SignatureAlg::MlDsa65).unwrap();
    let state = ipa.dir.join("web3.state");
    let request = voucher::request(
        other.as_bytes(),
        &claims("web3.voucher.test", Vec::new()),
        &state,
    )
    .unwrap();
    let response = voucher::sign(&stranger, &issuer.quota, &request).unwrap();
    let web3 = voucher::finish(&state, &response).unwrap();
    assert!(ipa.enroll("web3.voucher.test", &web3, None).is_err());
}

/// A leased voucher's host stops getting tickets when its lease ends, and
/// is removed after; a lease over the realm's longest is refused.
fn leased_voucher_creates_a_host_that_ends(realm: &Realm, ipa: &Ipa, issuer: &Issuer) {
    let runner = "runner1.voucher.test";
    let leased = Claims {
        lease: 2 * 3600,
        ..claims(runner, Vec::new())
    };
    let before = now();
    ipa.enroll(runner, &issuer.issue(&leased, "runner1"), None)
        .unwrap();
    let principal = format!("host/{runner}@{REALM}");
    let end = ipa
        .directory
        .principal_lease(&principal.parse().unwrap())
        .unwrap()
        .expect("the host is leased");
    assert!((before + 2 * 3600..=now() + 2 * 3600).contains(&end));
    // The KDC stops its tickets then.
    let getprinc = realm.kadmin(&["getprinc", &principal]);
    let expiration = getprinc
        .lines()
        .find(|l| l.starts_with("Expiration date:"))
        .unwrap();
    assert!(!expiration.contains("[never]"), "{expiration}");
    // An unleased host has no lease.
    assert_eq!(
        ipa.directory
            .principal_lease(&format!("host/web1.voucher.test@{REALM}").parse().unwrap())
            .unwrap(),
        None
    );
    // Removed once the lease passed, and only it.
    assert_eq!(ipa.directory.purge_leases(end).unwrap(), [] as [String; 0]);
    assert_eq!(ipa.directory.purge_leases(end + 1).unwrap(), [runner]);
    assert!(!realm.has(&principal));
    assert!(realm.has(&format!("host/web1.voucher.test@{REALM}")));

    let too_long = Claims {
        lease: kuipa_enroll::voucher::DEFAULT_MAX_LEASE + 1,
        ..claims("runner2.voucher.test", Vec::new())
    };
    assert!(
        ipa.enroll(
            "runner2.voucher.test",
            &issuer.issue(&too_long, "runner2"),
            None
        )
        .is_err()
    );
    assert!(!realm.has(&format!("host/runner2.voucher.test@{REALM}")));
}

/// The quota of five is used up: a sixth signature is refused.
fn quota_is_used_up(issuer: &Issuer) {
    let state = issuer.dir.join("web4.state");
    let request = voucher::request(
        issuer.public.as_bytes(),
        &claims("web4.voucher.test", Vec::new()),
        &state,
    )
    .unwrap();
    let err = voucher::sign(&issuer.key, &issuer.quota, &request).unwrap_err();
    assert!(err.to_string().contains("quota exhausted"), "{err}");
}

/// A spender that reaches the voucher's home server in this process, as
/// kuipad does over HTTPS, unless `up` is cleared.
struct HomeSpender {
    home: Arc<EnrollServer>,
    directory: Arc<KdcDirectory>,
    me: String,
    up: AtomicBool,
    /// What the redeemer asked, in order.
    ops: std::sync::Mutex<Vec<(SpendOp, String)>>,
}

impl std::fmt::Debug for HomeSpender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HomeSpender")
    }
}

impl HomeSpender {
    fn call(&self, op: SpendOp, fqdn: &str, voucher: &[u8]) -> Result<(), SpendError> {
        if !self.up.load(Ordering::SeqCst) {
            return Err(SpendError::Unavailable("connection refused".into()));
        }
        self.ops.lock().unwrap().push((op, fqdn.to_owned()));
        let request = SpendRequest {
            op,
            sender: self.me.clone(),
            receiver: SERVER.into(),
            fqdn: fqdn.into(),
            voucher: voucher.to_vec(),
            token: Vec::new(),
        };
        self.home
            .spend_for_peer(&request, &self.me, &*self.directory)
            .map_err(|r| SpendError::Refused(r.to_string().into()))
    }
}

impl VoucherSpender for HomeSpender {
    fn spend(&self, _: &str, fqdn: &str, voucher: &[u8]) -> Result<(), SpendError> {
        self.call(SpendOp::Spend, fqdn, voucher)
    }

    fn release(&self, _: &str, fqdn: &str, voucher: &[u8]) -> Result<(), SpendError> {
        self.call(SpendOp::Release, fqdn, voucher)
    }
}

/// A voucher's salt is spent on the server it names, whichever server takes
/// the join, and only there: the other server writes no record and cannot
/// accept the voucher by itself, so two servers cannot each take it before
/// their directories replicate.
fn voucher_is_spent_on_its_home_server(realm: &Arc<Realm>) {
    const OTHER: &str = "ipa2.voucher.test";
    let dir = realm.dir.join("home-server");
    std::fs::create_dir_all(&dir).unwrap();
    let issuer = Issuer::new(&dir);
    let home = Ipa::start_named(realm, &issuer.public, SERVER);
    let other = Ipa::start_named(realm, &issuer.public, OTHER);
    let spender = Arc::new(HomeSpender {
        home: home.server.clone(),
        directory: home.directory.clone(),
        me: OTHER.into(),
        up: AtomicBool::new(true),
        ops: std::sync::Mutex::new(Vec::new()),
    });
    other.server.set_voucher_spender(spender.clone());
    let records = |ipa: &Ipa| ipa.directory.spent.lock().unwrap().clone();

    // Taken by the other server: the record is on the home server's directory.
    let web5 = issuer.issue(&claims("web5.voucher.test", Vec::new()), "web5");
    other.enroll("web5.voucher.test", &web5, None).unwrap();
    assert!(realm.has(&format!("host/web5.voucher.test@{REALM}")));
    assert!(records(&other).is_empty(), "the redeemer writes no record");
    assert_eq!(
        records(&home).into_values().collect::<Vec<_>>(),
        [("web5.voucher.test".to_owned(), OTHER.to_owned())]
    );
    // Used up at either server.
    assert!(home.enroll("web5.voucher.test", &web5, None).is_err());
    assert!(other.enroll("web5.voucher.test", &web5, None).is_err());

    // The home server cannot be asked: the join fails, nothing is recorded, and
    // it works when the home server is back.
    let web6 = issuer.issue(&claims("web6.voucher.test", Vec::new()), "web6");
    spender.up.store(false, Ordering::SeqCst);
    assert!(other.enroll("web6.voucher.test", &web6, None).is_err());
    assert!(!realm.has(&format!("host/web6.voucher.test@{REALM}")));
    assert_eq!(records(&home).len(), 1);
    spender.up.store(true, Ordering::SeqCst);
    other.enroll("web6.voucher.test", &web6, None).unwrap();
    assert_eq!(records(&home).len(), 2);

    // A join that fails with no host made releases the record on the home
    // server: web1 exists already.
    let web1 = issuer.issue(&claims("web1.voucher.test", Vec::new()), "web1");
    let before = spender.ops.lock().unwrap().len();
    assert!(other.enroll("web1.voucher.test", &web1, None).is_err());
    assert_eq!(
        spender.ops.lock().unwrap()[before..],
        [
            (SpendOp::Spend, "web1.voucher.test".to_owned()),
            (SpendOp::Release, "web1.voucher.test".to_owned())
        ],
        "spent, then released: nothing was made"
    );
    assert_eq!(records(&home).len(), 2, "the record was released");

    // A voucher for a server that is not the one asked is not spent for it.
    let elsewhere = Claims {
        server: "ipa3.voucher.test".into(),
        ..claims("web7.voucher.test", Vec::new())
    };
    let web7 = issuer.issue(&elsewhere, "web7");
    assert!(other.enroll("web7.voucher.test", &web7, None).is_err());
    assert!(!realm.has(&format!("host/web7.voucher.test@{REALM}")));
    assert_eq!(records(&home).len(), 2);
}

#[test]
fn vouchers_against_a_real_kdc() {
    let Some(realm) = Realm::start(REALM, "voucher") else {
        return;
    };
    let realm = Arc::new(realm);
    let issuer = Issuer::new(&realm.dir);
    let ipa = Ipa::start(&realm, &issuer.public);
    ipa.check_advertisement(&issuer.public);
    bearer_voucher_creates_one_host(&realm, &ipa, &issuer);
    bound_voucher_needs_its_ephemeral_key(&realm, &ipa, &issuer);
    voucher_under_unknown_key_is_refused(&ipa, &issuer);
    leased_voucher_creates_a_host_that_ends(&realm, &ipa, &issuer);
    voucher_is_spent_on_its_home_server(&realm);
    quota_is_used_up(&issuer);
}
