//! Vouchers against a real MIT KDC (skipped when the KDC tools are not
//! installed), §9: the issuer makes a voucher key and a quota; the
//! provisioner blinds a voucher for a host, the issuer signs it without
//! seeing it, and the provisioner unblinds it; the host enrolls with it.
//! A voucher creates one host only, a bound voucher works only with its
//! ephemeral key, and the quota counts every signature.
//!
//! One test function: `KUIPA_ENDPOINTS` is set once, before any thread
//! exists.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use kuipa_enroll::EnrollServer;
use kuipa_enroll::delegation::Delegation;
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::realm::{Deployment, RealmInfo, ServerKeys, VerifiedRealm};
use kuipa_enroll::voucher::{Claims, Voucher};
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
        hostgroup: "webservers".into(),
        not_before: now() - 60,
        not_after: now() + 3600,
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
    /// A voucher key, and a quota of three signatures.
    fn new(dir: &Path) -> Self {
        let key = dir.join("issuer.pem");
        let quota = dir.join("quota.json");
        let public = voucher::keygen(&key, SignatureAlg::MlDsa65).unwrap();
        voucher::set_quota(&quota, 3).unwrap();
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
    dir: PathBuf,
    anchor: SigningKey,
    server: Arc<EnrollServer>,
    directory: Arc<KdcDirectory>,
    string: EnrollmentString,
}

impl Ipa {
    /// Start the server on a local port, accepting vouchers under `public`.
    fn start(realm: &Arc<Realm>, public: &str) -> Self {
        let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let delegation = Delegation::issue(
            &anchor,
            REALM,
            SERVER,
            signing.public(),
            now() - 60,
            now() + 86400,
        )
        .unwrap();
        let info = RealmInfo {
            realm: REALM.into(),
            domain: "voucher.test".into(),
            basedn: "dc=voucher,dc=test".into(),
            server: SERVER.into(),
            servers: vec![SERVER.into()],
            ca_certs: vec![realm.chain.ca_der.clone()],
            pkinit_anchors: vec![realm.chain.ca_der.clone()],
            anchors: vec![*anchor.public().thumbprint()],
            heads: Vec::new(),
            trusts: Vec::new(),
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
        let directory = Arc::new(KdcDirectory::new(realm.clone(), &[SERVER], &[]));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        // SAFETY: the only test in this binary, before any thread starts.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("KUIPA_ENDPOINTS", format!("{SERVER}={url}"));
        }
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
            &Deployment::servers(&[SERVER.into()]),
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

/// The quota of three is used up: a fourth signature is refused.
fn quota_of_three_is_used_up(issuer: &Issuer) {
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
    quota_of_three_is_used_up(&issuer);
}
