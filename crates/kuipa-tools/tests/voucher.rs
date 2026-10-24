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

#[test]
#[allow(clippy::too_many_lines)]
fn vouchers_against_a_real_kdc() {
    let Some(realm) = Realm::start(REALM, "voucher") else {
        return;
    };
    let realm = Arc::new(realm);
    let dir = realm.dir.clone();

    // ── Issuer: a voucher key and a quota of three ──
    let issuer_key = dir.join("issuer.pem");
    let quota = dir.join("quota.json");
    let public = voucher::keygen(&issuer_key, SignatureAlg::MlDsa65).unwrap();
    voucher::set_quota(&quota, 3).unwrap();

    // ── The IPA server accepts vouchers under it ──
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

    // The advertisement publishes the voucher key.
    let thp = *anchor.public().thumbprint();
    let adv = VerifiedRealm::verify(
        &server.advertisement(&[thp]).unwrap(),
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
        std::slice::from_ref(&public)
    );

    let issue = |c: &Claims, name: &str| -> Voucher {
        let state = dir.join(format!("{name}.state"));
        let request = voucher::request(public.as_bytes(), c, &state).unwrap();
        // The issuer sees 64 bytes, nothing of the claims.
        assert_eq!(b64::decode(&request).unwrap().len(), 64);
        let response = voucher::sign(&issuer_key, &quota, &request).unwrap();
        voucher::finish(&state, &response).unwrap()
    };
    let string = EnrollmentString::new(
        REALM,
        *anchor.public().thumbprint(),
        tang_pqc::unix_seconds(std::time::SystemTime::now()) + 86_400,
        None,
    );
    let enroll = |host: &str, v: &Voucher, ephemeral: Option<&[u8]>| {
        let root = dir.join(format!("root-{host}"));
        std::fs::create_dir_all(&root).unwrap();
        let auth = Auth::Voucher {
            voucher: Secret::new(v.encode().as_ref()),
            ephemeral: ephemeral.map(Secret::new),
        };
        flows::enroll_online(
            &Paths::new(&root),
            string.realm(),
            &[*string.anchor()],
            &[],
            &[],
            &auth,
            host,
            &Deployment::servers(&[SERVER.into()]),
        )
    };

    // ── A bearer voucher creates its host, once ──
    let web1 = issue(&claims("web1.voucher.test", Vec::new()), "web1");
    enroll("web1.voucher.test", &web1, None).unwrap();
    assert!(realm.has(&format!("host/web1.voucher.test@{REALM}")));
    assert_eq!(
        directory.hostgroups.lock().unwrap()["webservers"],
        ["web1.voucher.test"]
    );
    assert!(enroll("web1.voucher.test", &web1, None).is_err(), "used up");
    // Not for another host.
    assert!(enroll("web9.voucher.test", &web1, None).is_err());

    // ── A bound voucher works only with its ephemeral key ──
    let key_file = dir.join("web2-ephemeral.jwk");
    let binding = voucher::ephemeral(&key_file).unwrap();
    let web2 = issue(&claims("web2.voucher.test", binding), "web2");
    assert!(enroll("web2.voucher.test", &web2, None).is_err());
    assert!(!realm.has(&format!("host/web2.voucher.test@{REALM}")));
    let key = std::fs::read(&key_file).unwrap();
    enroll("web2.voucher.test", &web2, Some(&key)).unwrap();

    // ── A voucher under a key the realm does not know is refused (its
    //    signature still counts against the shared quota file) ──
    let stranger = dir.join("stranger.pem");
    let other = voucher::keygen(&stranger, SignatureAlg::MlDsa65).unwrap();
    let state = dir.join("web3.state");
    let request = voucher::request(
        other.as_bytes(),
        &claims("web3.voucher.test", Vec::new()),
        &state,
    )
    .unwrap();
    let response = voucher::sign(&stranger, &quota, &request).unwrap();
    let web3 = voucher::finish(&state, &response).unwrap();
    assert!(enroll("web3.voucher.test", &web3, None).is_err());

    // ── The quota of three is used up ──
    let state = dir.join("web4.state");
    let request = voucher::request(
        public.as_bytes(),
        &claims("web4.voucher.test", Vec::new()),
        &state,
    )
    .unwrap();
    let err = voucher::sign(&issuer_key, &quota, &request).unwrap_err();
    assert!(err.to_string().contains("quota exhausted"), "{err}");
}
