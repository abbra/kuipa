//! Trusted realms against two real MIT KDCs (skipped when the KDC tools are
//! not installed): realm B invites realm A, A's server establishes the
//! trust (both KDCs get the cross-realm keys from the derived secret) and
//! publishes B; a host enrolled in A then installs B's anchors, PKINIT
//! anchors and KDCs from B's advertisement, verified with the anchors A
//! vouches for, gets anonymous-PKINIT armour from B's KDC, and a user of B
//! gets a ticket for that host across the trust (§17).
//!
//! One test function: `KUIPA_ENDPOINTS` is set once, before any thread
//! exists.  Kerberos runs only in `kinit` subprocesses.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use kuipa_enroll::EnrollServer;
use kuipa_enroll::delegation::Delegation;
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::realm::{Deployment, RealmInfo, ServerKeys, TrustedRealm};
use kuipa_enroll::server::Directory;
use kuipa_enroll::trust::Invitation;
use kuipa_tools::flows::{self, Auth, Outcome};
use kuipa_tools::paths::{self, Paths};
use kuipad::http::{App, router};
use support::directory::KdcDirectory;
use support::kdc::Realm;
use tang_pqc::{ExchangeKeyPair, KemAlg, SignatureAlg, SigningKey, Thumbprint, unix_seconds};

const A: &str = "A.TEST";
const B: &str = "B.TEST";
const SERVER_A: &str = "ipa1.a.test";
const SERVER_B: &str = "ipa1.b.test";
const HOST: &str = "web1.a.test";

fn now() -> u64 {
    unix_seconds(SystemTime::now())
}

/// One server of `realm`, with its own anchor, serving the daemon's router
/// on `listener`.
fn server(
    realm: &Arc<Realm>,
    fqdn: &str,
    listener: std::net::TcpListener,
    otps: &[(&str, &[u8])],
    trusts: Vec<TrustedRealm>,
) -> (Arc<EnrollServer>, Thumbprint, Arc<KdcDirectory>) {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let delegation = Delegation::issue(
        &anchor,
        &realm.realm,
        fqdn,
        signing.public(),
        now() - 60,
        now() + 30 * 86400,
    )
    .unwrap();
    let info = RealmInfo {
        realm: realm.realm.clone(),
        domain: realm.realm.to_lowercase(),
        basedn: "dc=test".into(),
        server: fqdn.into(),
        servers: vec![fqdn.into()],
        ca_certs: vec![realm.chain.ca_der.clone()],
        pkinit_anchors: vec![realm.chain.ca_der.clone()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts,
    };
    info.validate().unwrap();
    let keys = ServerKeys {
        signing,
        join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        trust: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        vouchers: Vec::new(),
        retired: Vec::new(),
    };
    let server = Arc::new(EnrollServer::new(keys, info, delegation));
    let directory = Arc::new(KdcDirectory::new(realm.clone(), &[fqdn], &[]));
    for (host, otp) in otps {
        directory
            .otps
            .lock()
            .unwrap()
            .insert((*host).to_owned(), otp.to_vec());
    }
    let app = Arc::new(App {
        server: server.clone(),
        directory: directory.clone(),
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
    });
    let rt = tokio::runtime::Runtime::new().unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, router(app)).await.unwrap();
        });
    });
    (server, *anchor.public().thumbprint(), directory)
}

fn trust_b(servers: &[&str], anchor: Thumbprint) -> TrustedRealm {
    TrustedRealm {
        realm: B.into(),
        domain: "b.test".into(),
        servers: servers.iter().map(|s| (*s).to_owned()).collect(),
        anchors: vec![anchor],
    }
}

/// A `KRB5_CONFIG` list: the host's generated configuration for A, then
/// `snippet`, as `includedir` would merge it, with each realm's KDC
/// pointed at its socket.
fn config(realms: [&Realm; 2], paths: &Paths, snippet: &str, name: &str) -> PathBuf {
    let [realm_a, realm_b] = realms;
    let own = realm_b.dir.join(format!("{name}.a"));
    let generated = std::fs::read_to_string(paths.krb5_conf()).unwrap();
    let generated = generated.replace(&format!("{SERVER_A}:88"), realm_a.socket.to_str().unwrap());
    std::fs::write(&own, generated).unwrap();
    let file = realm_b.dir.join(name);
    let snippet = snippet.replace(&format!("{SERVER_B}:88"), realm_b.socket.to_str().unwrap());
    std::fs::write(&file, snippet).unwrap();
    PathBuf::from(format!("{}:{}", own.display(), file.display()))
}

fn exists(p: &Path) -> bool {
    p.exists()
}

#[test]
#[allow(clippy::too_many_lines)]
fn trusted_realm_against_real_kdcs() {
    let Some(realm_a) = Realm::start(A, "trust-a") else {
        return;
    };
    let Some(realm_b) = Realm::start(B, "trust-b") else {
        return;
    };
    let (realm_a, realm_b) = (Arc::new(realm_a), Arc::new(realm_b));
    let listeners = [(); 2].map(|()| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
    let urls = listeners
        .each_ref()
        .map(|l| format!("http://{}", l.local_addr().unwrap()));
    // SAFETY: the only test in this binary, before any thread starts.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var(
            "KUIPA_ENDPOINTS",
            format!(
                "{SERVER_A}={},{SERVER_B}={},ipa9.b.test=http://127.0.0.1:9",
                urls[0], urls[1]
            ),
        );
    }
    let [listener_a, listener_b] = listeners;
    let (server_b, anchor_b, dir_b) = server(&realm_b, SERVER_B, listener_b, &[], Vec::new());
    let (server_a, anchor_a, dir_a) = server(
        &realm_a,
        SERVER_A,
        listener_a,
        &[(HOST, b"Secret123")],
        Vec::new(),
    );

    // ── B invites A; A's server establishes the trust (§17.4) ──
    let invitation = Invitation::new(B, anchor_b).unwrap();
    dir_b
        .add_trust_invitation(&invitation.secret_hash().unwrap(), now() + 3600)
        .unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let endpoints = std::collections::BTreeMap::from([(SERVER_B.to_owned(), urls[1].clone())]);
    let dir_a_dyn: Arc<dyn Directory + Send + Sync> = dir_a.clone();
    let (established, recorded) = rt
        .block_on(kuipad::trust::establish(
            &server_a,
            &invitation,
            &[SERVER_B.to_owned()],
            &endpoints,
            &*dir_a_dyn,
        ))
        .unwrap();
    assert!(recorded, "A's directory records the trust and its keys");
    assert_eq!(established.partner.realm, B);
    assert_eq!(
        dir_b.trusted_realms().unwrap()[0].realm,
        A,
        "and so does B's"
    );
    assert_eq!(server_b.anchors(), [anchor_b]);
    // The invitation was single use.
    assert!(
        rt.block_on(kuipad::trust::establish(
            &server_a,
            &invitation,
            &[SERVER_B.to_owned()],
            &endpoints,
            &*dir_a_dyn,
        ))
        .is_err()
    );
    // A publishes B from its directory, refreshed from B's advertisement.
    rt.block_on(kuipad::trust::refresh(
        &server_a,
        &dir_a_dyn,
        &[],
        &endpoints,
    ));
    assert_eq!(server_a.trusts()[0].realm, B);

    // ── A host of realm A ──
    let dir = realm_a.dir.join("root-web1");
    std::fs::create_dir_all(&dir).unwrap();
    let p = Paths::new(&dir);
    let mut s = EnrollmentString::new(
        A,
        anchor_a,
        tang_pqc::unix_seconds(std::time::SystemTime::now()) + 86_400,
        Some(Secret::new(b"Secret123")),
    );
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &p,
        s.realm(),
        &[*s.anchor()],
        &[],
        &Auth::LdapOtp(otp),
        HOST,
        &Deployment::servers(&[SERVER_A.to_owned()]),
    )
    .unwrap();
    assert_eq!(p.trusted_realms().len(), 0);

    // ── Install B: verified with the anchor A vouches for ──
    let result = flows::trusted_realms(&p).unwrap();
    assert_eq!(
        result["trusted_realms"][0]["status"], "installed",
        "{result}"
    );
    assert_eq!(p.trusted_realms(), [B]);
    assert_eq!(
        paths::read_anchors_from(&p.trust_anchors(B)).unwrap(),
        [anchor_b]
    );
    assert_eq!(
        paths::read_anchors(&p).unwrap(),
        [anchor_a],
        "B's anchors never join the host's own"
    );
    let pkinit = std::fs::read(p.trust_dir(B).join("pkinit-anchors.pem")).unwrap();
    assert_eq!(
        synta_certificate::pem_to_der(&pkinit),
        std::slice::from_ref(&realm_b.chain.ca_der)
    );
    let snippet = std::fs::read_to_string(p.trust_krb5_conf(B)).unwrap();
    assert!(
        p.trust_krb5_conf(B)
            .ends_with("etc/krb5.conf.d/kuipa_trust_B_TEST")
    );
    assert!(!snippet.contains("[libdefaults]"), "{snippet}");
    assert!(
        snippet.contains(&format!("kdc = {SERVER_B}:88")),
        "{snippet}"
    );

    // ── Armour from B's KDC with B's chain, for B only ──
    let armor = realm_b.dir.join("armor.ccache");
    realm_b
        .kinit_anonymous(
            &armor,
            &config([&realm_a, &realm_b], &p, &snippet, "b.conf"),
        )
        .expect("anonymous PKINIT to B with B's installed PKINIT anchors");
    let without: String = snippet
        .lines()
        .filter(|l| !l.contains("pkinit_anchors") && !l.contains("pkinit_pool"))
        .flat_map(|l| [l, "\n"])
        .collect();
    assert!(
        realm_b
            .kinit_anonymous(
                &realm_b.dir.join("x.ccache"),
                &config([&realm_a, &realm_b], &p, &without, "b-bare.conf")
            )
            .is_err(),
        "without B's chain there is no armour"
    );
    let a_chain = snippet.replace(
        p.trust_dir(B).join("pkinit-anchors.pem").to_str().unwrap(),
        p.pkinit_anchors().to_str().unwrap(),
    );
    assert_ne!(a_chain, snippet);
    assert!(
        realm_b
            .kinit_anonymous(
                &realm_b.dir.join("y.ccache"),
                &config([&realm_a, &realm_b], &p, &a_chain, "b-a-chain.conf")
            )
            .is_err(),
        "A's PKINIT anchors do not vouch for B's KDC"
    );

    // ── A user of B gets a ticket for this A host over the trust, with
    //    the cross-realm keys the establishment created ──
    realm_b.add_user("alice@B.TEST", "Alice123");
    let login = config([&realm_a, &realm_b], &p, &snippet, "login.conf");
    let user = realm_b.dir.join("alice.ccache");
    realm_b.kinit(
        "alice@B.TEST",
        "Alice123",
        &user,
        Some(&armor),
        Some(&login),
    );
    let out = std::process::Command::new("kvno")
        .env("KRB5_CONFIG", &login)
        .env("KRB5CCNAME", format!("FILE:{}", user.display()))
        .args(["-S", "host", HOST])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "kvno over the trust: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("host/{HOST}@{A}")));

    // ── Refresh, an unreachable B (files kept), removal, leave ──
    let result = flows::trusted_realms(&p).unwrap();
    assert_eq!(result["trusted_realms"][0]["status"], "refreshed");
    server_a.publish_trusts(vec![trust_b(&["ipa9.b.test"], anchor_b)]);
    let err = flows::trusted_realms(&p).unwrap_err();
    assert!(
        err.downcast_ref::<Outcome>()
            .is_some_and(|o| matches!(o, Outcome::RetryLater(_))),
        "{err}"
    );
    assert!(exists(&p.trust_krb5_conf(B)), "last verified files kept");
    // A trust entry with A's own anchor is not a separate realm: the
    // client refuses A's advertisement and changes nothing.
    server_a.publish_trusts(vec![trust_b(&[SERVER_B], anchor_a)]);
    assert!(flows::trusted_realms(&p).is_err());
    assert_eq!(p.trusted_realms(), [B]);
    server_a.publish_trusts(vec![]);
    let result = flows::trusted_realms(&p).unwrap();
    assert_eq!(result["trusted_realms"][0]["status"], "removed");
    assert_eq!(p.trusted_realms().len(), 0);
    assert!(!exists(&p.trust_krb5_conf(B)));
    assert!(!exists(&p.trust_dir(B)));

    server_a.publish_trusts(vec![trust_b(&[SERVER_B], anchor_b)]);
    flows::trusted_realms(&p).unwrap();
    flows::leave(&p).unwrap();
    assert_eq!(p.trusted_realms().len(), 0);
    assert!(!exists(&p.trust_krb5_conf(B)));
}
