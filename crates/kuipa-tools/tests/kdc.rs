//! Integration tests against a real MIT KDC (skipped when the KDC tools are
//! not installed).  Everything runs in one test function: the Kerberos
//! library reads `KRB5_CONFIG` and `KRB5CCNAME` from the environment, which
//! is set once, before any thread exists.
//!
//! Two servers run the daemon's router and its anchor exchange, each with
//! its own anchor, authenticating their syncs with their `ipa-ku/<fqdn>`
//! keys.  The directory ([`KdcDirectory`]) accepts GSS-API tokens for real
//! and gets keys from the KDC; only the LDAP side is simulated.

mod support;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use kuipa_enroll::EnrollServer;
use kuipa_enroll::anchors::PeerSync;
use kuipa_enroll::bundle::{Mode, StageParams};
use kuipa_enroll::delegation::Delegation;
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::join::{
    AuthType, KERBEROS_BINDING_LEN, KerberosBinding, Operation, Prepared, Response,
    kerberos_prf_input,
};
use kuipa_enroll::keytab::{Enctype, Keytab};
use kuipa_enroll::realm::{Deployment, RealmInfo, ServerKeys, VerifiedRealm};
use kuipa_enroll::server::parse_stage_result;
use kuipa_enroll::vault;
use kuipa_gssapi::{
    AcceptStep, GssClientCred, GssError, GssServerCred, InitStep, NoPreauth, Preauth,
};
use kuipa_tools::flows::{self, Auth, Outcome, Target};
use kuipa_tools::net::{Endpoint, Trust};
use kuipa_tools::paths::{self, Paths};
use kuipa_tools::seal::{Seal, UserPaths};
use kuipad::http::{App, router};
use kuipad::keystore::KeyStore;
use kuipad::peers::{Initiator, KeytabInitiator, Peers, Settings};
use support::directory::KdcDirectory;
use support::kdc::Realm;
use tang_pqc::{
    ExchangeKeyPair, KemAlg, Policy, SignatureAlg, SigningKey, Thumbprint, unix_seconds,
};

const REALM: &str = "EXAMPLE.TEST";
const SERVER: &str = "ipa1.example.test";
const SERVER2: &str = "ipa2.example.test";
const ADMIN: &str = "admin@EXAMPLE.TEST";

fn set_env(vars: &[(&str, String)]) {
    for (k, v) in vars {
        // SAFETY: the only test in this binary, before any thread starts.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(k, v);
        }
    }
}

fn token(cred: &GssClientCred, cb: &[u8]) -> Vec<u8> {
    match kuipa_gssapi::init_token(cred, &format!("ipa-ku@{SERVER}"), Some(cb)).unwrap() {
        InitStep::Complete(t) | InitStep::Continue { token: t, .. } => t,
    }
}

/// A front end that answers whatever the KDC asks for from a script, and
/// records the asking: an exchange with no secret brought is driven by the
/// KDC, so this is what exercises the responder and the prompter for real.
struct Scripted {
    answer: &'static [u8],
    asked: std::cell::RefCell<Vec<String>>,
}

impl Preauth for Scripted {
    fn prompt(&self, label: &str) -> Result<Vec<u8>, GssError> {
        self.asked.borrow_mut().push(label.to_owned());
        Ok(self.answer.to_vec())
    }

    fn secret(&self, label: &str) -> Result<Vec<u8>, GssError> {
        self.prompt(label)
    }
}

fn now() -> u64 {
    unix_seconds(SystemTime::now())
}

/// Serve the daemon's router on `listener`, and run its anchor exchange.
fn spawn(listener: std::net::TcpListener, app: Arc<App<Arc<KdcDirectory>>>) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            if let Some(peers) = app.peers.clone() {
                tokio::spawn(peers.run());
            }
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, router(app)).await.unwrap();
        });
    });
}

/// Wait until `done` holds, for at most 60 s.
fn wait_for(what: &str, done: impl Fn() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn root(realm: &Realm, name: &str) -> Paths {
    let dir = realm.dir.join(format!("root-{name}"));
    std::fs::create_dir_all(&dir).unwrap();
    Paths::new(dir)
}

/// Make a kryoptic token (`KRYOPTIC_CONF` is set) with an ML-KEM-768 key,
/// PIN 1234, label `dev`; the module, or `None` without the tools.
fn token_with_ml_kem_key() -> Option<std::path::PathBuf> {
    let module = std::path::PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
    if !module.exists() || !Path::new("/usr/lib64/ossl-modules/pkcs11.so").exists() {
        return None;
    }
    // With the tools installed, a failure here is a failure, not a skip.
    let tool = |args: &[&str]| {
        let out = std::process::Command::new("pkcs11-tool")
            .arg("--module")
            .arg(&module)
            .args(args)
            .output()
            .expect("pkcs11-tool");
        assert!(out.status.success(), "pkcs11-tool {args:?}: {out:?}");
        Some(())
    };
    tool(&["--init-token", "--label", "kuipa", "--so-pin", "12345678"])?;
    tool(&[
        "--token-label",
        "kuipa",
        "--login",
        "--so-pin",
        "12345678",
        "--init-pin",
        "--pin",
        "1234",
    ])?;
    tool(&[
        "--token-label",
        "kuipa",
        "--login",
        "--pin",
        "1234",
        "--keypairgen",
        "--key-type",
        "ML-KEM-768",
        "--label",
        "dev",
        "--id",
        "01",
    ])?;
    Some(module)
}

fn kvnos(path: &Path) -> Vec<u32> {
    let mut v: Vec<u32> = Keytab::from_mit(&std::fs::read(path).unwrap())
        .unwrap()
        .entries()
        .iter()
        .map(|e| e.kvno)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// The state the scenario's sections share: the realm and its directory,
/// the two IPA servers and the anchors they vouch for, and web1's root.
struct Scenario {
    realm: Arc<Realm>,
    directory: Arc<KdcDirectory>,
    ipa: Vec<Arc<EnrollServer>>,
    own_anchors: Vec<Thumbprint>,
    urls: [String; 2],
    admin_ccache: std::path::PathBuf,
    web1: Paths,
    servers: Deployment,
    anchors: [Thumbprint; 1],
}

/// The files a keytab and a file protection left behind, for the checks
/// that follow.
#[derive(Clone)]
struct Copies {
    http: std::path::PathBuf,
    http_keys: Vec<u8>,
    service: String,
    as_keytab: Target,
    secret: std::path::PathBuf,
    as_file: Target,
    copy: std::path::PathBuf,
    stale: std::path::PathBuf,
}

/// Alice's login and her personal vault, for the sections that use them.
struct Alice {
    cc: String,
    home: UserPaths,
    bob_cc: String,
    sealed: Vec<u8>,
}

/// An enrollment string for `anchor`, with the one-time `secret` if any.
fn enrollment_string(anchor: Thumbprint, secret: Option<&[u8]>) -> EnrollmentString {
    EnrollmentString::new(
        REALM,
        anchor,
        tang_pqc::unix_seconds(std::time::SystemTime::now()) + 86_400,
        secret.map(Secret::new),
    )
}

fn check_channel_bindings(realm: &Realm) {
    // ── GSS-API channel bindings, as the daemon and the client use them ──
    let svc = realm.dir.join("kuipa.keytab");
    std::fs::write(&svc, realm.new_keys(&format!("ipa-ku/{SERVER}@{REALM}"))).unwrap();
    {
        let probe = realm.dir.join("probe.keytab");
        std::fs::write(
            &probe,
            realm.new_keys("host/probe.example.test@EXAMPLE.TEST"),
        )
        .unwrap();
        let server =
            GssServerCred::acquire(&format!("ipa-ku@{SERVER}"), svc.to_str().unwrap()).unwrap();
        let client = GssClientCred::from_client_keytab(
            probe.to_str().unwrap(),
            Some("host/probe.example.test@EXAMPLE.TEST"),
            None,
        )
        .unwrap();
        assert!(matches!(
            kuipa_gssapi::accept_token(&server, &token(&client, &[1; 32]), Some(&[1; 32])).unwrap(),
            AcceptStep::Complete { principal, .. } if principal == "host/probe.example.test@EXAMPLE.TEST"
        ));
        assert!(
            kuipa_gssapi::accept_token(&server, &token(&client, &[1; 32]), Some(&[2; 32])).is_err(),
            "a token bound to another exchange is refused"
        );

        // One Kerberos message establishes both contexts: the acceptor
        // derives the initiator's pseudo-random output (§5.1), and nothing
        // else does.
        let target = format!("ipa-ku@{SERVER}");
        let (t, mine) = kuipa_gssapi::init_bound(&client, &target, &[3; 32], b"in", 32).unwrap();
        let (who, theirs) = kuipa_gssapi::accept_bound(&server, &t, &[3; 32], b"in", 32).unwrap();
        assert_eq!(who, "host/probe.example.test@EXAMPLE.TEST");
        assert_eq!(mine, theirs);
        let (t, mine) = kuipa_gssapi::init_bound(&client, &target, &[3; 32], b"in", 32).unwrap();
        let (_, other) = kuipa_gssapi::accept_bound(&server, &t, &[3; 32], b"other", 32).unwrap();
        assert_ne!(mine, other, "the output depends on the input");
        let (_, again) = kuipa_gssapi::init_bound(&client, &target, &[3; 32], b"in", 32).unwrap();
        assert_ne!(mine, again, "every context has its own key");
        // An acceptor with another key cannot accept the token at all.
        let elsewhere = GssServerCred::acquire(&format!("ipa-ku@{SERVER2}"), svc.to_str().unwrap());
        if let Ok(elsewhere) = elsewhere {
            assert!(kuipa_gssapi::accept_bound(&elsewhere, &t, &[3; 32], b"in", 32).is_err());
        }
    }
}

/// Start one IPA server of the realm, listening on `listener` and peering
/// with `other`, reachable at `other_url`; returns it and its anchor.
fn start_ipa_server(
    realm: &Arc<Realm>,
    directory: &Arc<KdcDirectory>,
    fqdn: &str,
    other: &str,
    other_url: &str,
    listener: std::net::TcpListener,
) -> (Arc<EnrollServer>, Thumbprint) {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let delegation = Delegation::issue(
        &anchor,
        REALM,
        fqdn,
        signing.public(),
        now() - 60,
        now() + 30 * 86400,
    )
    .unwrap();
    let keys = ServerKeys {
        signing,
        join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        trust: Vec::new(),
        vouchers: Vec::new(),
        retired: Vec::new(),
    };
    let info = RealmInfo {
        realm: REALM.into(),
        domain: "example.test".into(),
        basedn: "dc=example,dc=test".into(),
        server: fqdn.into(),
        servers: [SERVER, SERVER2].map(String::from).to_vec(),
        ca_certs: vec![realm.chain.ca_der.clone()],
        pkinit_anchors: vec![realm.chain.ca_der.clone()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
    };
    let own_anchor = *anchor.public().thumbprint();
    let key_dir = realm.dir.join(format!("keys-{fqdn}"));
    std::fs::create_dir_all(&key_dir).unwrap();
    let alg = kuipa_enroll::merkle::TreeHash::for_signer(keys.signing.public().alg());
    let ledger = Arc::new(kuipad::ledger::FileLedger::open(&key_dir, REALM, fqdn, alg).unwrap());
    let server = Arc::new(EnrollServer::new(keys, info, delegation).with_ledger(ledger.clone()));
    let settings = Settings {
        me: fqdn.into(),
        realm: REALM.into(),
        peers: vec![other.into()],
        discover: false,
        endpoints: [(other.to_owned(), other_url.to_owned())].into(),
        interval: Duration::from_millis(500),
        ca_certs: vec![realm.chain.ca_der.clone()],
        vouch_interval: Duration::ZERO,
    };
    let initiator = Arc::new(KeytabInitiator::new(
        realm
            .dir
            .join(format!("kuipa-{fqdn}.keytab"))
            .display()
            .to_string(),
        format!("ipa-ku/{fqdn}@{REALM}"),
    ));
    let peers = Peers::new(
        settings,
        Some(anchor),
        server.clone(),
        directory.clone(),
        initiator,
        KeyStore::new(key_dir),
    )
    .unwrap();
    spawn(
        listener,
        Arc::new(App {
            server: server.clone(),
            directory: directory.clone(),
            peers: Some(peers),
            // Generous: a refusal in this test is the policy's, never
            // the rate limit's.
            limiter: kuipad::limit::Limiter::new(kuipad::limit::Limits {
                per_host: kuipad::limit::Rate {
                    burst: 1000.0,
                    per_minute: 1000.0,
                },
                // Every request comes from 127.0.0.1.
                per_source: kuipad::limit::Rate {
                    burst: 1000.0,
                    per_minute: 1000.0,
                },
            }),
            tang: None,
            keys: None,
            ledger: Some(ledger),
        }),
    );
    (server, own_anchor)
}

/// Start both IPA servers of the realm, each with its own anchor; returns
/// their directory, the servers and their anchors.
fn start_ipa_servers(
    realm: &Arc<Realm>,
    listeners: [std::net::TcpListener; 2],
    urls: &[String; 2],
) -> (Arc<KdcDirectory>, Vec<Arc<EnrollServer>>, Vec<Thumbprint>) {
    // ── Two IPA servers, each with its own anchor, realm info with the real CA ──
    let names = [SERVER, SERVER2];
    let directory = Arc::new(KdcDirectory::new(realm.clone(), &names, &[ADMIN]));
    for host in ["web1", "web5"] {
        directory
            .otps
            .lock()
            .unwrap()
            .insert(format!("{host}.example.test"), b"Secret123".to_vec());
    }
    let mut own_anchors = Vec::new();
    let mut ipa = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let (fqdn, other) = (names[i], names[1 - i]);
        let (server, own_anchor) =
            start_ipa_server(realm, &directory, fqdn, other, &urls[1 - i], listener);
        own_anchors.push(own_anchor);
        ipa.push(server);
    }
    (directory, ipa, own_anchors)
}

fn await_anchor_exchange(world: &Scenario) {
    let ipa = &world.ipa;
    let own_anchors = &world.own_anchors;
    // ── Anchor exchange: Kerberos-authenticated syncs, then cosignatures ──
    wait_for(
        "both servers trust both anchors and both vouch for both claims",
        || {
            ipa.iter()
                .all(|s| s.anchors().len() == 2 && s.delegation().proof_count() == 2)
        },
    );
    for (i, s) in ipa.iter().enumerate() {
        assert_eq!(s.anchors()[0], own_anchors[i], "own anchor first");
        for a in own_anchors {
            s.delegation()
                .verify_at(&[*a], &Policy::default(), now())
                .unwrap();
        }
    }

    // The anchor log converges through the same exchange; a host that
    // checks before it does sees one server behind (exit 75 territory,
    // §4.8), so wait for the two logs to be in step.
    wait_for("both servers carry the same anchor log", || {
        let first = ipa[0].epoch_head();
        first.is_some() && ipa.iter().all(|s| s.epoch_head() == first)
    });
}

fn enroll_web1_with_otp(world: &Scenario) -> Vec<u32> {
    let realm = &world.realm;
    let a = &world.web1;
    let servers = &world.servers;
    let anchors = &world.anchors;
    // ── OTP enrollment, then key rotation authenticated by the host keys ──
    // The OTP is also the host's temporary Kerberos key (FreeIPA's host-add
    // sets it): the host gets a ticket with it and rekeys itself.
    realm.add_user(&format!("host/web1.example.test@{REALM}"), "Secret123");
    let mut s = enrollment_string(anchors[0], Some(b"Secret123"));
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        a,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: "web1.example.test",
            auth: &Auth::Otp(otp),
        },
        servers,
    )
    .unwrap();
    let first = kvnos(&a.keytab());
    assert_eq!(first.len(), 1);
    let rotated = flows::rotate_keys(a, None).unwrap();
    assert_eq!(
        kvnos(&a.keytab()),
        vec![first[0], first[0] + 1],
        "new kvno plus the previous one: {rotated}"
    );
    let check = flows::check(a, None).unwrap();
    assert_eq!(check["ok"], true, "{check}");
    first
}

fn protect_keytab(world: &Scenario, first: &[u32]) {
    let a = &world.web1;
    // ── Keytab protection: rekey with escrow registration, unseal, undo ──
    flows::protect(a, &Target::Host).unwrap();
    assert!(
        std::fs::symlink_metadata(a.keytab())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(flows::unseal(a).unwrap().kvno(), Some(first[0] + 2));
    assert_eq!(flows::check(a, None).unwrap()["ok"], true);
}

fn protect_other_keytab_and_file(world: &Scenario) -> Copies {
    let realm = &world.realm;
    let directory = &world.directory;
    let a = &world.web1;
    // ── Another keytab and any file, sealed for their own principals and
    //    registered outside a rekey, with those principals' keys (§7.5) ──
    let service = format!("HTTP/web1.example.test@{REALM}");
    let http = realm.dir.join("http.keytab");
    let http_keys = realm.new_keys(&service);
    std::fs::write(&http, &http_keys).unwrap();
    let as_keytab = Target::Keytab(http.clone());
    let protected = flows::protect(a, &as_keytab).unwrap();
    assert_eq!(protected["principal"], service.as_str(), "{protected}");
    assert!(
        std::fs::symlink_metadata(&http)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&http).unwrap(), http_keys);
    assert_eq!(directory.escrow.lock().unwrap()[&service].len(), 2);
    let secret = realm.dir.join("app-secret.conf");
    std::fs::write(&secret, b"token=first\n").unwrap();
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o640)).unwrap();
    let as_file = Target::File {
        path: secret.clone(),
        keytab: None,
    };
    flows::protect(a, &as_file).unwrap();
    let host = format!("host/web1.example.test@{REALM}");
    let file_bindings = || directory.escrow_files.lock().unwrap()[&host].clone();
    assert_eq!(file_bindings().len(), 2);
    let copy = a.run_copy(&std::path::absolute(&secret).unwrap());
    assert_eq!(
        std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
        0o640
    );
    // A change written through the symlink is resealed by protecting
    // again, which retires the previous seal's bindings.
    let first_seal = std::fs::read(paths::sealed_for(&secret)).unwrap();
    std::fs::write(&secret, b"token=second\n").unwrap();
    let resealed = flows::protect(a, &as_file).unwrap();
    assert_eq!(resealed["resealed"], true);
    assert_eq!(file_bindings().len(), 2, "the old seal's bindings retired");
    let stale = realm.dir.join("stale.sealed");
    std::fs::write(&stale, &first_seal).unwrap();
    assert!(flows::unseal_file(a, &stale).is_err(), "retired seal opens");
    Copies {
        http,
        http_keys,
        service,
        as_keytab,
        secret,
        as_file,
        copy,
        stale,
    }
}

fn restore_copies_at_boot(world: &Scenario, copies: &Copies) {
    let a = &world.web1;
    let Copies {
        http,
        http_keys,
        copy,
        secret,
        ..
    } = copies.clone();
    // At boot every copy comes back through a server, as the host keytab
    // does; a host rekey replaces only the host's keytab bindings.
    flows::rotate_keys(a, None).unwrap();
    for p in [a.run_keytab(), a.run_copy(&http), copy.clone()] {
        std::fs::remove_file(p).unwrap();
    }
    let all = flows::unseal_all(a).unwrap();
    assert_eq!(all["written"].as_array().unwrap().len(), 3, "{all}");
    assert_eq!(std::fs::read(&http).unwrap(), http_keys);
    assert_eq!(std::fs::read(&secret).unwrap(), b"token=second\n");
    let check = flows::check(a, None).unwrap();
    assert_eq!(check["ok"], true, "{check}");
    assert_eq!(
        flows::status(a).unwrap()["protected"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

fn undo_copies(world: &Scenario, copies: &Copies) {
    let directory = &world.directory;
    let a = &world.web1;
    let Copies {
        http,
        http_keys,
        secret,
        as_file,
        as_keytab,
        service,
        stale,
        ..
    } = copies.clone();
    let host = format!("host/web1.example.test@{REALM}");
    let file_bindings = || directory.escrow_files.lock().unwrap()[&host].clone();
    // Undo: plain again, and the bindings retired.
    let sealed_secret = std::fs::read(paths::sealed_for(&secret)).unwrap();
    let undone = flows::unprotect(a, &as_file).unwrap();
    assert_eq!(undone["retired"], true, "{undone}");
    assert!(
        !std::fs::symlink_metadata(&secret)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&secret).unwrap(), b"token=second\n");
    assert_eq!(
        file_bindings(),
        Vec::<kuipa_enroll::escrow::BindingHash>::new()
    );
    std::fs::write(&stale, &sealed_secret).unwrap();
    assert!(flows::unseal_file(a, &stale).is_err(), "retired seal opens");
    let undone = flows::unprotect(a, &as_keytab).unwrap();
    assert_eq!(undone["retired"], true, "{undone}");
    assert_eq!(std::fs::read(&http).unwrap(), http_keys);
    assert_eq!(
        directory.escrow.lock().unwrap()[&service],
        Vec::<kuipa_enroll::escrow::BindingHash>::new()
    );
    assert!(!paths::sealed_for(&http).exists());
}

fn personal_vault(world: &Scenario) -> Alice {
    let realm = &world.realm;
    let a = &world.web1;
    // ── A user's own vault, with her ticket and a passphrase device (§7.6) ──
    // Alice is not root: she reads the host's public realm.json, anchors
    // and CA, and keeps everything of hers in her own directory.
    realm.add_user("alice@EXAMPLE.TEST", "Alice123");
    let alice_cc = realm.dir.join("alice.ccache");
    realm.kinit("alice@EXAMPLE.TEST", "Alice123", &alice_cc, None, None);
    let alice_cc = format!("FILE:{}", alice_cc.display());
    let home = UserPaths::new(realm.dir.join("alice-home"));
    let seal = Seal::new(a, &home, Some(&alice_cc));
    let policy = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        ..vault::Policy::default()
    };
    let created = seal.create("personal", policy).unwrap();
    assert_eq!(
        created["vaults"][0]["owner"], "alice@EXAMPLE.TEST",
        "{created}"
    );
    seal.add_device("personal", b"correct horse").unwrap();
    assert_eq!(
        std::fs::metadata(home.device_key())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let sealed = seal.seal("personal", b"token=alice\n").unwrap();
    assert_eq!(
        seal.open(&sealed, Some(b"correct horse")).unwrap().as_ref(),
        b"token=alice\n"
    );
    assert!(seal.open(&sealed, Some(b"wrong")).is_err());
    assert!(seal.open(&sealed, None).is_err());
    // Sealing again uses the stored descriptor and advertisements.
    let again = seal.seal("personal", b"second").unwrap();
    assert_eq!(
        seal.open(&again, Some(b"correct horse")).unwrap().as_ref(),
        b"second"
    );
    // Bob's ticket is not Alice's, even with her device and passphrase.
    realm.add_user("bob@EXAMPLE.TEST", "Bob12345");
    let bob_cc = realm.dir.join("bob.ccache");
    realm.kinit("bob@EXAMPLE.TEST", "Bob12345", &bob_cc, None, None);
    let bob_cc = format!("FILE:{}", bob_cc.display());
    let as_bob = Seal::new(a, &home, Some(&bob_cc));
    assert!(as_bob.open(&sealed, Some(b"correct horse")).is_err());
    Alice {
        cc: alice_cc,
        home,
        bob_cc,
        sealed,
    }
}

fn tlog_watch(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    let alice_cc = alice.cc.as_str();
    // ── Her vault's transparency logs (DESIGN-tlog.md §7) ──
    // The first watch sets the baseline: history listed, nothing flagged.
    let first = seal.watch("personal").unwrap();
    assert_eq!(first["ok"], true, "{first}");
    assert!(!first["baseline"].as_array().unwrap().is_empty(), "{first}");
    let actions: Vec<_> = first["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_owned())
        .collect();
    for a in ["create", "add-device", "release"] {
        assert!(actions.iter().any(|x| x == a), "{a} in {first}");
    }
    // Nothing new, nothing listed.
    let quiet = seal.watch("personal").unwrap();
    assert_eq!(quiet["ok"], true, "{quiet}");
    assert!(quiet["events"].as_array().unwrap().is_empty(), "{quiet}");
    // A device added elsewhere — her laptop, or someone holding her
    // ticket — is not in this host's descriptor: flagged.
    let laptop = UserPaths::new(realm.dir.join("alice-laptop"));
    Seal::new(a, &laptop, Some(alice_cc))
        .add_device("personal", b"battery staple")
        .unwrap();
    let flagged = seal.watch("personal").unwrap();
    assert_eq!(flagged["ok"], false, "{flagged}");
    assert_eq!(flagged["unexpected"], 1, "{flagged}");
    assert_eq!(flagged["events"][0]["action"], "add-device", "{flagged}");
    // Once she has looked (`show` stores the current descriptor), the
    // next watch is clean: the entry was reported once.
    seal.show("personal").unwrap();
    let accepted = seal.watch("personal").unwrap();
    assert_eq!(accepted["ok"], true, "{accepted}");
    // A server whose key changed category (a crypto policy change) keeps
    // a new log under a new id: reported as such, read from its start, not
    // a fork.
    let state_path = home_dir_of(realm).join("vaults/personal.tlog");
    let mut watched: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    for w in watched.as_object_mut().unwrap().values_mut() {
        w["log"] = "0".repeat(96).into();
    }
    std::fs::write(&state_path, serde_json::to_vec(&watched).unwrap()).unwrap();
    let moved = seal.watch("personal").unwrap();
    assert!(moved["forked"].as_array().unwrap().is_empty(), "{moved}");
    assert!(!moved["relogged"].as_array().unwrap().is_empty(), "{moved}");
    assert!(moved["baseline"].as_array().unwrap().is_empty(), "{moved}");
    assert!(!moved["events"].as_array().unwrap().is_empty(), "{moved}");
}

fn tlog_diverged(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    let as_bob = Seal::new(a, &alice.home, Some(&alice.bob_cc));
    let sealed = &alice.sealed;
    let state_path = home_dir_of(realm).join("vaults/personal.tlog");
    // A log that does not extend what was seen is reported as forked.
    let mut watched: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    for w in watched.as_object_mut().unwrap().values_mut() {
        w["root"] = tang_pqc::b64::encode(&[9; 32]).into();
    }
    std::fs::write(&state_path, serde_json::to_vec(&watched).unwrap()).unwrap();
    let diverged = seal.watch("personal").unwrap();
    assert_eq!(diverged["ok"], false, "{diverged}");
    assert!(
        !diverged["forked"].as_array().unwrap().is_empty(),
        "{diverged}"
    );
    // Bob cannot look up her vault: nothing checked, not clean.
    let by_bob = as_bob.watch("personal").unwrap();
    assert_eq!(by_bob["ok"], false, "{by_bob}");
    assert!(by_bob["events"].as_array().unwrap().is_empty(), "{by_bob}");
    let listed = seal.list().unwrap();
    assert_eq!(listed["vaults"].as_array().unwrap().len(), 1);
    seal.revoke("personal").unwrap();
    assert!(seal.open(sealed, Some(b"correct horse")).is_err());
}

fn daily_session(world: &Scenario, alice: &Alice) {
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    let as_bob = Seal::new(a, &alice.home, Some(&alice.bob_cc));
    // A session: one passphrase and ticket, then files open without either;
    // the servers count every release against the limit.
    let daily = vault::Policy {
        max_unlocks: Some(4),
        sessions: vault::Sessions {
            reauth: Some(3600),
            offline: None,
            epoch: None,
        },
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        ..vault::Policy::default()
    };
    seal.create("daily", daily).unwrap();
    seal.add_device("daily", b"correct horse").unwrap();
    let note = seal.seal("daily", b"daily note").unwrap();
    assert!(seal.open(&note, None).is_err(), "no session yet");
    let started = seal.unlock("daily", b"correct horse", false).unwrap();
    assert!(started["session_until"].as_u64().is_some(), "{started}");
    assert!(Seal::in_session(&note));
    // In the session neither the passphrase nor Alice's ticket is used:
    // Bob's ticket next to it changes nothing.
    assert_eq!(seal.open(&note, None).unwrap().as_ref(), b"daily note");
    assert_eq!(as_bob.open(&note, None).unwrap().as_ref(), b"daily note");
    seal.lock("daily").unwrap();
    assert!(!Seal::in_session(&note));
    assert!(seal.open(&note, None).is_err(), "locked");
    assert_eq!(
        seal.open(&note, Some(b"correct horse")).unwrap().as_ref(),
        b"daily note"
    );
    assert_eq!(seal.show("daily").unwrap()["vaults"][0]["unlocks"], 3);
    seal.open(&note, Some(b"correct horse")).unwrap();
    assert!(
        seal.open(&note, Some(b"correct horse")).is_err(),
        "the fifth unlock is over the limit"
    );
}

fn offline_session(world: &Scenario, alice: &Alice) {
    let directory = &world.directory;
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    // An offline session, once the realm allows them: files sealed with
    // --session open from the released key and the device, on this host.
    directory.limits.lock().unwrap().offline_sessions = true;
    let travel = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        sessions: vault::Sessions {
            reauth: None,
            offline: Some(3600),
            epoch: None,
        },
        ..vault::Policy::default()
    };
    seal.create("travel", travel).unwrap();
    seal.add_device("travel", b"correct horse").unwrap();
    let pass = seal.seal_session("travel", b"boarding pass").unwrap();
    assert!(
        seal.open(&pass, Some(b"correct horse")).is_err(),
        "no session yet"
    );
    let started = seal.unlock("travel", b"correct horse", true).unwrap();
    assert_eq!(started["offline"], true);
    assert!(Seal::in_session(&pass));
    assert_eq!(seal.open(&pass, None).unwrap().as_ref(), b"boarding pass");
    seal.lock("travel").unwrap();
    assert!(seal.open(&pass, None).is_err(), "locked");
}

fn registered_sealing(world: &Scenario, alice: &Alice) {
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    // Registered sealing: a reseal or a retire makes old copies unopenable.
    let kept = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        sealing: vault::Sealing::Registered,
        ..vault::Policy::default()
    };
    seal.create("kept", kept).unwrap();
    seal.add_device("kept", b"correct horse").unwrap();
    let first = seal.seal("kept", b"v1").unwrap();
    assert_eq!(
        seal.open(&first, Some(b"correct horse")).unwrap().as_ref(),
        b"v1"
    );
    let second = seal.reseal("kept", &first, Some(b"correct horse")).unwrap();
    assert!(
        seal.open(&first, Some(b"correct horse")).is_err(),
        "the old copy"
    );
    assert_eq!(
        seal.open(&second, Some(b"correct horse")).unwrap().as_ref(),
        b"v1"
    );
    seal.retire("kept", &second).unwrap();
    assert!(
        seal.open(&second, Some(b"correct horse")).is_err(),
        "retired"
    );
}

fn shared_vault(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    let bob_cc = alice.bob_cc.as_str();
    // ── A vault shared with a teammate (§7.6.12) ──
    // Bob names it alice/team, registers his own device from his own
    // directory, and opens with his device and his ticket.
    let team = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        ..vault::Policy::default()
    };
    seal.create("team", team).unwrap();
    seal.add_device("team", b"correct horse").unwrap();
    let before = seal.seal("team", b"before bob").unwrap();
    let bob_only = vault::Members {
        users: vec!["bob".into()],
        ..vault::Members::default()
    };
    let shared = seal
        .share(
            "team",
            [
                vault::Members::default(),
                bob_only.clone(),
                vault::Members::default(),
            ],
        )
        .unwrap();
    assert_eq!(
        shared["vaults"][0]["members"][0], "user:bob@EXAMPLE.TEST",
        "{shared}"
    );
    let bob_home = UserPaths::new(realm.dir.join("bob-home"));
    let bob = Seal::new(a, &bob_home, Some(bob_cc));
    assert!(bob.show("team").is_err(), "a bare name is Bob's own");
    bob.add_device("alice/team", b"bob's phrase").unwrap();
    let listed = bob.list().unwrap();
    assert_eq!(
        listed["vaults"][0]["owner"], "alice@EXAMPLE.TEST",
        "{listed}"
    );
    assert!(
        realm
            .dir
            .join("bob-home/vaults/team@alice@EXAMPLE.TEST.vault")
            .exists(),
        "kept apart from any vault of his own"
    );
    let note = bob.seal("alice/team", b"from bob").unwrap();
    assert_eq!(
        bob.open(&note, Some(b"bob's phrase")).unwrap().as_ref(),
        b"from bob"
    );
    assert_eq!(
        seal.open(&note, Some(b"correct horse")).unwrap().as_ref(),
        b"from bob"
    );
    // A file sealed before his device was registered has no share for it
    // until Alice reseals it.
    assert!(bob.open(&before, Some(b"bob's phrase")).is_err());
    let before = seal
        .reseal("team", &before, Some(b"correct horse"))
        .unwrap();
    assert_eq!(
        bob.open(&before, Some(b"bob's phrase")).unwrap().as_ref(),
        b"before bob"
    );
    // Unshared, his device goes and nothing opens for him.
    let unshared = seal
        .unshare(
            "team",
            [
                vault::Members::default(),
                bob_only,
                vault::Members::default(),
            ],
        )
        .unwrap();
    assert_eq!(
        unshared["vaults"][0]["devices"].as_array().unwrap().len(),
        1,
        "{unshared}"
    );
    assert!(bob.open(&note, Some(b"bob's phrase")).is_err());
    assert!(seal.open(&note, Some(b"correct horse")).is_ok());
}

fn break_glass(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    // ── A break-glass vault: two others approve each release
    // (DESIGN-approvals.md) ──
    realm.add_user("carol@EXAMPLE.TEST", "Carol123");
    let carol_cc = realm.dir.join("carol.ccache");
    realm.kinit("carol@EXAMPLE.TEST", "Carol123", &carol_cc, None, None);
    let carol_cc = format!("FILE:{}", carol_cc.display());
    let glass = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        approvals: Some(vault::Approvals {
            m: 2,
            from: vault::Members {
                users: vec!["bob".into(), "carol".into()],
                ..vault::Members::default()
            },
            window: None,
            uses: None,
        }),
        ..vault::Policy::default()
    };
    seal.create("glass", glass).unwrap();
    seal.add_device("glass", b"correct horse").unwrap();
    let sealed = seal.seal("glass", b"root password").unwrap();
    let pass: &[u8] = b"correct horse";
    assert!(seal.open(&sealed, Some(pass)).is_err(), "no request");
    let asked = seal.request("glass", &sealed, "INC-7: locked out").unwrap();
    let id = asked["requests"][0]["id"].as_str().unwrap().to_owned();
    // Bob and Carol approve from their own tickets; neither is a member.
    let bob_home = UserPaths::new(realm.dir.join("bob-approver"));
    let carol_home = UserPaths::new(realm.dir.join("carol-home"));
    let bob = Seal::new(a, &bob_home, Some(&alice.bob_cc));
    let carol = Seal::new(a, &carol_home, Some(&carol_cc));
    let pending = bob.pending(None).unwrap();
    assert_eq!(pending["requests"][0]["id"], id.as_str(), "{pending}");
    bob.decide("alice/glass", &id, false).unwrap();
    assert!(
        seal.open_with(&sealed, Some(pass), Some(&id)).is_err(),
        "one of two"
    );
    carol.decide("alice/glass", &id, false).unwrap();
    assert_eq!(
        seal.open_with(&sealed, Some(pass), Some(&id))
            .unwrap()
            .as_ref(),
        b"root password"
    );
    assert!(
        seal.open_with(&sealed, Some(pass), Some(&id)).is_err(),
        "used up"
    );
}

fn lost_laptop(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let a = &world.web1;
    // ── A lost laptop, back with a recovery code (DESIGN-recovery.md §2) ──
    let laptop = UserPaths::new(realm.dir.join("alice-lost-laptop"));
    let on_laptop = Seal::new(a, &laptop, Some(&alice.cc));
    let notes = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        ..vault::Policy::default()
    };
    on_laptop.create("notes", notes).unwrap();
    on_laptop.add_device("notes", b"laptop pass").unwrap();
    let note = on_laptop.seal("notes", b"pin=1234").unwrap();
    let shown = on_laptop.recovery_code(b"laptop pass").unwrap();
    let code = shown["recovery_code"].as_str().unwrap().to_owned();

    // The laptop is gone; on a new one, the code brings its key back.
    let fresh = UserPaths::new(realm.dir.join("alice-new-laptop"));
    let on_new = Seal::new(a, &fresh, Some(&alice.cc));
    let pass: &[u8] = b"new pass";
    assert!(
        on_new
            .recover_code("AAAAAAAAAAAAAAAAAAAAAAAAAA", pass)
            .is_err(),
        "another code"
    );
    on_new.recover_code(&code, pass).unwrap();
    assert_eq!(
        on_new.open(&note, Some(pass)).unwrap().as_ref(),
        b"pin=1234"
    );
    // Finishing reseals to the new laptop's own device and retires the old.
    let (done, again) = on_new
        .recover_finish(pass, std::slice::from_ref(&note), true)
        .unwrap();
    assert_eq!(done["resealed"], 1, "{done}");
    assert!(!fresh.recovered_key().exists());
    assert_eq!(
        on_new.open(&again[0], Some(pass)).unwrap().as_ref(),
        b"pin=1234"
    );
    // Whoever has the old laptop opens nothing, old file or new.
    let old_pass: &[u8] = b"laptop pass";
    assert!(on_laptop.open(&again[0], Some(old_pass)).is_err());
    assert!(on_laptop.open(&note, Some(old_pass)).is_err());
}

fn deposits(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    // ── A drop box: Bob deposits, only Alice opens (DESIGN-recovery.md §3) ──
    let drop = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        sealing: vault::Sealing::Registered,
        ..vault::Policy::default()
    };
    seal.create("drop", drop).unwrap();
    seal.add_device("drop", b"correct horse").unwrap();
    let bob_only = vault::Members {
        users: vec!["bob".into()],
        ..vault::Members::default()
    };
    seal.share(
        "drop",
        [
            vault::Members::default(),
            vault::Members::default(),
            bob_only,
        ],
    )
    .unwrap();
    let bob_home = UserPaths::new(realm.dir.join("bob-depositor"));
    let bob = Seal::new(a, &bob_home, Some(&alice.bob_cc));
    let subject = std::collections::BTreeMap::from([("name".to_owned(), "restic".to_owned())]);
    let made = bob
        .deposit(
            "alice/drop",
            b"restic password",
            vault::DepositKind::File,
            subject,
        )
        .unwrap();
    let id = made["deposits"][0]["id"].as_str().unwrap().to_owned();
    assert!(
        bob.deposit_file("alice/drop", &id).is_err(),
        "Bob only deposits"
    );
    let listed = seal.deposits("drop").unwrap();
    assert_eq!(
        listed["deposits"][0]["depositor"], "bob@EXAMPLE.TEST",
        "{listed}"
    );
    let sealed = seal.deposit_file("drop", &id).unwrap();
    assert_eq!(
        seal.open(&sealed, Some(b"correct horse")).unwrap().as_ref(),
        b"restic password"
    );
}

fn escrows(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let a = &world.web1;
    let seal = Seal::new(a, &alice.home, Some(&alice.cc));
    // Hosts deposit too, with their own keytab (DESIGN-recovery.md §5):
    // web1's LUKS recovery key, as systemd-cryptenroll prints it.
    let host = kuipa_tools::escrow::Depositor {
        paths: a,
        keytab: None,
    };
    let key = "fejrltbu-bjitujnh-dfhrrbrk-hgbtdbgg-cbbitcrk-kclhkdgb-gbbhgjvb-ldbbrleb";
    let uuid = "0b9c7f1e-6d2a-4c55-9a51-3e1f6b2d8c70";
    let printed = format!("A secret recovery key has been generated:\n    {key}\n");
    assert!(
        kuipa_tools::escrow::escrow_luks(
            &host,
            "alice/drop",
            "/dev/vda2",
            printed.as_bytes(),
            Some(uuid)
        )
        .is_err(),
        "web1 is no depositor yet"
    );
    let web1 = vault::Members {
        hosts: vec!["web1.example.test".into()],
        ..vault::Members::default()
    };
    seal.share(
        "drop",
        [vault::Members::default(), vault::Members::default(), web1],
    )
    .unwrap();
    let made = kuipa_tools::escrow::escrow_luks(
        &host,
        "alice/drop",
        "/dev/vda2",
        printed.as_bytes(),
        Some(uuid),
    )
    .unwrap();
    let luks = made["deposits"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        made["deposits"][0]["depositor"], "host/web1.example.test@EXAMPLE.TEST",
        "{made}"
    );
    kuipa_tools::escrow::escrow_file(&host, "alice/drop", "borg", b"borg passphrase").unwrap();
    // And so does any service whose keytab is on the host, as itself.
    let backup = "backup/web1.example.test@EXAMPLE.TEST";
    let keytab = realm.dir.join("backup.keytab");
    std::fs::write(&keytab, realm.new_keys(backup)).unwrap();
    let service = kuipa_tools::escrow::Depositor {
        paths: a,
        keytab: Some(&keytab),
    };
    let restic = b"restic for the backup service";
    assert!(
        kuipa_tools::escrow::escrow_file(&service, "alice/drop", "restic", restic).is_err(),
        "the service is no depositor yet"
    );
    let services = vault::Members {
        services: vec!["backup/web1.example.test".into()],
        ..vault::Members::default()
    };
    seal.share(
        "drop",
        [
            vault::Members::default(),
            vault::Members::default(),
            services,
        ],
    )
    .unwrap();
    let made = kuipa_tools::escrow::escrow_file(&service, "alice/drop", "restic", restic).unwrap();
    assert_eq!(made["deposits"][0]["depositor"], backup, "{made}");
    let listed = seal.deposits("drop").unwrap();
    assert_eq!(listed["deposits"].as_array().unwrap().len(), 4, "{listed}");
    let sealed = seal.deposit_file("drop", &luks).unwrap();
    assert_eq!(
        seal.open(&sealed, Some(b"correct horse")).unwrap().as_ref(),
        key.as_bytes()
    );
}

fn helpdesk_recovery(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let directory = &world.directory;
    let a = &world.web1;
    // ── A lost device's key, back through the helpdesk (DESIGN-recovery.md
    // §4): Carol's escrow vault takes users' device keys, and Bob approves
    // each release from it. ──
    let carol_cc = format!("FILE:{}", realm.dir.join("carol.ccache").display());
    let carol_home = UserPaths::new(realm.dir.join("carol-helpdesk"));
    let carol = Seal::new(a, &carol_home, Some(&carol_cc));
    let escrow = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        approvals: Some(vault::Approvals {
            m: 1,
            from: vault::Members {
                users: vec!["bob".into()],
                ..vault::Members::default()
            },
            window: None,
            uses: None,
        }),
        ..vault::Policy::default()
    };
    carol.create("escrow", escrow).unwrap();
    carol.add_device("escrow", b"carol pass").unwrap();
    let alice_only = vault::Members {
        users: vec!["alice".into()],
        ..vault::Members::default()
    };
    carol
        .share(
            "escrow",
            [
                vault::Members::default(),
                vault::Members::default(),
                alice_only,
            ],
        )
        .unwrap();
    *directory.recovery.lock().unwrap() = Some(vault::RecoverySettings {
        device_vault: "carol/escrow".into(),
        required: true,
    });

    // Alice's laptop registers its device: its key is deposited first.
    let old_home = UserPaths::new(realm.dir.join("alice-old-desk"));
    let old = Seal::new(a, &old_home, Some(&alice.cc));
    let pins = vault::Policy {
        factors: vault::Factors {
            device: Some(vault::Level::Any),
            ticket: true,
            passkey: false,
        },
        ..vault::Policy::default()
    };
    old.create("pins", pins).unwrap();
    old.add_device("pins", b"old pass").unwrap();
    let note = old.seal("pins", b"door=4711").unwrap();
    let deposits = carol.deposits("escrow").unwrap();
    let deposit = deposits["deposits"][0]["id"].as_str().unwrap().to_owned();

    // On a new one she registers a device and tells the helpdesk which.
    let new_home = UserPaths::new(realm.dir.join("alice-new-desk"));
    let new = Seal::new(a, &new_home, Some(&alice.cc));
    new.add_device("pins", b"new pass").unwrap();
    let shown = new.recover_helpdesk(b"new pass").unwrap();
    let device = shown["helpdesk_device"].as_str().unwrap().to_owned();
    // Carol asks for the deposit's release, Bob approves, Carol delivers.
    let sealed = carol.deposit_file("escrow", &deposit).unwrap();
    let asked = carol
        .request("escrow", &sealed, "INC-9: alice lost her desk")
        .unwrap();
    let rq = asked["requests"][0]["id"].as_str().unwrap().to_owned();
    let bob_home = UserPaths::new(realm.dir.join("bob-helpdesk"));
    Seal::new(a, &bob_home, Some(&alice.bob_cc))
        .decide("carol/escrow", &rq, false)
        .unwrap();
    let pass: &[u8] = b"carol pass";
    carol
        .deliver(
            &deposit,
            ("alice@EXAMPLE.TEST", &device),
            Some(pass),
            Some(&rq),
        )
        .unwrap();
    // Alice fetches it on the new desk and opens her old note there.
    new.recover_fetch(b"new pass").unwrap();
    assert_eq!(
        new.open(&note, Some(b"new pass")).unwrap().as_ref(),
        b"door=4711"
    );
    let (_, again) = new
        .recover_finish(b"new pass", std::slice::from_ref(&note), true)
        .unwrap();
    assert_eq!(
        new.open(&again[0], Some(b"new pass")).unwrap().as_ref(),
        b"door=4711"
    );
    *directory.recovery.lock().unwrap() = None;
}

fn token_device(world: &Scenario, alice: &Alice) {
    let realm = &world.realm;
    let a = &world.web1;
    let alice_cc = alice.cc.as_str();
    // A device on a token: an ML-KEM key that never leaves it, used through
    // pkcs11-provider; the PIN takes the passphrase's place.
    if let Some(module) = token_with_ml_kem_key() {
        let home = UserPaths::new(realm.dir.join("alice-token-home"));
        let seal = Seal::new(a, &home, Some(alice_cc));
        let policy = vault::Policy {
            factors: vault::Factors {
                device: Some(vault::Level::Any),
                ticket: true,
                passkey: false,
            },
            ..vault::Policy::default()
        };
        seal.create("token", policy).unwrap();
        let added = seal
            .add_token_device("token", &module, "pkcs11:token=kuipa;object=dev", b"1234")
            .unwrap();
        assert_eq!(
            added["vaults"][0]["devices"][0]["type"], "pkcs11",
            "{added}"
        );
        assert!(
            !home.device_key().exists(),
            "no key file: the key stays on the token"
        );
        let sealed = seal.seal("token", b"on the token").unwrap();
        assert!(Seal::needs_secret(&sealed));
        assert_eq!(
            seal.open(&sealed, Some(b"1234")).unwrap().as_ref(),
            b"on the token"
        );
    }
}

fn unprotect_host(world: &Scenario) {
    let a = &world.web1;
    flows::unprotect(a, &Target::Host).unwrap();
    assert!(!a.sealed().exists());
    flows::rotate_keys(a, None).unwrap();
}

fn admin_ticket(world: &Scenario) {
    let realm = &world.realm;
    let servers = &world.servers;
    let anchors = &world.anchors;
    let admin_ccache = &world.admin_ccache;
    // ── An administrator's existing ticket ──
    realm.kinit(ADMIN, "Admin123", admin_ccache, None, None);
    let b = root(realm, "web2");
    flows::enroll_online(
        &b,
        REALM,
        anchors,
        &[],
        &[],
        flows::Host {
            fqdn: "web2.example.test",
            auth: &Auth::Ccache,
        },
        servers,
    )
    .unwrap();
    assert_eq!(kvnos(&b.keytab()).len(), 1);
}

fn bootstrap_2fa(world: &Scenario) -> std::path::PathBuf {
    let realm = &world.realm;
    let servers = &world.servers;
    let anchors = &world.anchors;
    let admin_ccache = &world.admin_ccache;
    // ── 2FA bootstrap: the advertisement's PKINIT anchors give FAST armour ──
    let boot = realm.dir.join("bootstrap");
    flows::realm_info(REALM, anchors, &[], servers, &boot).unwrap();
    // The generated krb5.conf names KDCs by FQDN; this KDC is on a socket.
    let conf = std::fs::read_to_string(boot.join("krb5.conf"))
        .unwrap()
        .replace(&format!("{SERVER}:88"), realm.socket.to_str().unwrap());
    let conf_path = boot.join("krb5-test.conf");
    std::fs::write(&conf_path, &conf).unwrap();
    let armor = realm.dir.join("armor.ccache");
    realm
        .kinit_anonymous(&armor, &conf_path)
        .expect("anonymous PKINIT with the advertised anchors");
    // Without them it fails: the anchors really came from the advertisement.
    let bare = conf
        .lines()
        .filter(|l| !l.contains("pkinit_anchors") && !l.contains("pkinit_pool"))
        .collect::<Vec<_>>()
        .join("\n");
    let bare_path = boot.join("krb5-no-anchors.conf");
    std::fs::write(&bare_path, bare).unwrap();
    assert!(
        realm
            .kinit_anonymous(&realm.dir.join("x.ccache"), &bare_path)
            .is_err()
    );
    realm.kinit(
        ADMIN,
        "Admin123",
        admin_ccache,
        Some(&armor),
        Some(&conf_path),
    );

    // The rekey replaced web1's OTP-derived key: the OTP is spent.
    assert!(
        kuipa_gssapi::ticket(
            &conf_path,
            &format!("host/web1.example.test@{REALM}"),
            Some(b"Secret123"),
            &format!("ipa-ku/{SERVER}@{REALM}"),
            "MEMORY:spent-otp",
            &kuipa_gssapi::NoPreauth,
        )
        .is_err()
    );
    conf_path
}

fn password_enrollment(world: &Scenario) {
    let realm = &world.realm;
    let servers = &world.servers;
    let anchors = &world.anchors;
    // ── A user's password: an armoured kinit on the host, then Kerberos ──
    let g = root(realm, "web6");
    let password = |p: &[u8]| Auth::Password {
        principal: "admin".into(),
        password: Secret::new(p),
    };
    let err = flows::enroll_online(
        &g,
        REALM,
        anchors,
        &[],
        &[],
        flows::Host {
            fqdn: "web6.example.test",
            auth: &password(b"guess"),
        },
        servers,
    )
    .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::NeedsAdmin(_))),
        "{err}"
    );
    flows::enroll_online(
        &g,
        REALM,
        anchors,
        &[],
        &[],
        flows::Host {
            fqdn: "web6.example.test",
            auth: &password(b"Admin123"),
        },
        servers,
    )
    .unwrap();
    assert_eq!(kvnos(&g.keytab()).len(), 1);
}

fn collection_through_kuipa(world: &Scenario, conf_path: &Path) {
    let realm = &world.realm;
    let servers = &world.servers;
    let anchors = &world.anchors;
    // ── Collection through kuipa: nobody brought a password ──
    let collected = Scripted {
        answer: b"Admin123",
        asked: std::cell::RefCell::new(Vec::new()),
    };
    kuipa_gssapi::ticket(
        conf_path,
        ADMIN,
        None,
        &format!("ipa-ku/{SERVER}@{REALM}"),
        "MEMORY:collected",
        &collected,
    )
    .expect("the front end answers what libkrb5 asks for");
    assert!(
        !collected.asked.borrow().is_empty(),
        "kuipa was asked, instead of libkrb5 reading a terminal itself"
    );
    // A secret brought answers the exchange: nothing is asked of anyone.
    let quiet = Scripted {
        answer: b"wrong",
        asked: std::cell::RefCell::new(Vec::new()),
    };
    kuipa_gssapi::ticket(
        conf_path,
        ADMIN,
        Some(b"Admin123"),
        &format!("ipa-ku/{SERVER}@{REALM}"),
        "MEMORY:quiet",
        &quiet,
    )
    .expect("the secret brought authenticates");
    assert!(
        quiet.asked.borrow().is_empty(),
        "nothing was asked of a join that brought its secret: {:?}",
        quiet.asked.borrow()
    );
    // A factor nobody can be asked for is named as the reason, not libkrb5's
    // generic preauthentication failure.
    assert!(
        matches!(
            kuipa_gssapi::ticket(
                conf_path,
                ADMIN,
                None,
                &format!("ipa-ku/{SERVER}@{REALM}"),
                "MEMORY:unaskable",
                &NoPreauth,
            ),
            Err(GssError::Preauth { .. }),
        ),
        "an uncollectable factor must be named"
    );

    let c = root(realm, "web3");
    flows::enroll_online(
        &c,
        REALM,
        anchors,
        &[],
        &[],
        flows::Host {
            fqdn: "web3.example.test",
            auth: &Auth::Ccache,
        },
        servers,
    )
    .unwrap();
}

fn offline_enrollment(world: &Scenario) {
    let realm = &world.realm;
    let anchors = &world.anchors;
    // ── Offline: prepare, stage (admin ticket), open the bundle, first contact ──
    let d = root(realm, "web4");
    flows::prepare(&d, false, "web4.example.test").unwrap();
    let recipient =
        tang_pqc::ExchangeKey::from_jwk_json(&std::fs::read(d.recipient_public()).unwrap())
            .unwrap();
    let endpoint = Endpoint::new(SERVER, &Trust::FirstContact).unwrap();
    let adv = VerifiedRealm::verify(
        &endpoint.advertisement(anchors).unwrap(),
        REALM,
        anchors,
        &Policy::default(),
        SystemTime::now(),
    )
    .unwrap();
    let admin = GssClientCred::ambient().unwrap();
    let p = Prepared::new(
        &adv,
        Operation::Stage,
        "web4.example.test",
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (t, derived) = kuipa_gssapi::init_bound(
        &admin,
        &format!("ipa-ku@{SERVER}"),
        &cb,
        &kerberos_prf_input(&cb),
        KERBEROS_BINDING_LEN,
    )
    .unwrap();
    let params = StageParams {
        mode: Mode::MachineKey,
        recipient: Some(recipient),
        not_after: now() + 3600,
    };
    let (request, pending) = p
        .with_kerberos(KerberosBinding::new(&derived).unwrap())
        .seal(&t, &[], &params.to_bytes())
        .unwrap();
    let body = endpoint
        .post(&format!("stage/{}", request.kid()), request.to_bytes())
        .unwrap();
    let payload = pending.open(&Response::from_bytes(&body).unwrap()).unwrap();
    let (bundle, _) = parse_stage_result(payload.as_ref()).unwrap();
    flows::enroll_bundle(
        &d,
        &bundle.to_bytes(),
        Some(&enrollment_string(anchors[0], None)),
        false,
        Some("web4.example.test"),
    )
    .unwrap();
    let staged = kvnos(&d.keytab());
    let completed = flows::complete(&d).unwrap();
    assert!(!d.pending().exists(), "{completed}");
    assert_eq!(kvnos(&d.keytab()), vec![staged[0], staged[0] + 1]);
}

fn realm_wide_strings(world: &Scenario) {
    let realm = &world.realm;
    let anchors = &world.anchors;
    let own_anchors = &world.own_anchors;
    // ── Realm-wide strings: ipa1's anchor, enrollment through ipa2 alone ──
    let e = root(realm, "web5");
    let mut s5 = enrollment_string(anchors[0], Some(b"Secret123"));
    let otp = s5.take_secret().unwrap();
    let result = flows::enroll_online(
        &e,
        s5.realm(),
        &[*s5.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: "web5.example.test",
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(&[SERVER2.to_owned()]),
    )
    .unwrap();
    assert_eq!(result["issuer"], SERVER2);
    let stored = kuipa_tools::paths::read_anchors(&e).unwrap();
    assert_eq!(
        stored,
        [own_anchors[1], own_anchors[0]],
        "issuer's anchor first"
    );
}

fn refused_syncs(world: &Scenario) {
    let realm = &world.realm;
    let ipa = &world.ipa;
    let own_anchors = &world.own_anchors;
    let urls = &world.urls;
    // ── Syncs that do not authenticate their sender are refused ──
    let post = |sync: &PeerSync| {
        reqwest::blocking::Client::new()
            .post(format!("{}/ipa/ku/peer/sync", urls[1]))
            .body(sync.to_bytes())
            .send()
            .unwrap()
            .status()
    };
    let own = ipa[0].delegation().select(&[own_anchors[0]]);
    let own = Delegation::from_json(own.to_json().as_bytes()).unwrap();
    let ipa2_key = KeytabInitiator::new(
        realm
            .dir
            .join(format!("kuipa-{SERVER2}.keytab"))
            .display()
            .to_string(),
        format!("ipa-ku/{SERVER2}@{REALM}"),
    );
    let cb = PeerSync::channel_binding(SERVER, SERVER2, &own, b"", &[]).unwrap();
    let forged = PeerSync {
        sender: SERVER.into(),
        receiver: SERVER2.into(),
        own: own.clone(),
        envelope: Vec::new(),
        token: ipa2_key.token(SERVER2, &cb).unwrap(),
        chain: vec![],
    };
    assert_eq!(post(&forged), 403, "a token from another server's key");
    let garbage = PeerSync {
        token: b"not a token".to_vec(),
        ..forged.clone()
    };
    assert_eq!(post(&garbage), 403, "no valid token");
}

#[test]
fn against_a_real_kdc() {
    let Some(realm) = Realm::start(REALM, "kdc") else {
        return;
    };
    let realm = Arc::new(realm);
    let admin_ccache = realm.dir.join("admin.ccache");
    // The daemon listens on a fixed local port chosen before any thread
    // starts, so KUIPA_ENDPOINTS can map the server's FQDN to it.
    let listeners = [(); 2].map(|()| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
    let urls = listeners
        .each_ref()
        .map(|l| format!("http://{}", l.local_addr().unwrap()));
    let mut env = realm.env();
    env.push(("KRB5CCNAME", format!("FILE:{}", admin_ccache.display())));
    env.push((
        "KUIPA_ENDPOINTS",
        format!("{SERVER}={},{SERVER2}={}", urls[0], urls[1]),
    ));
    // The KDC for the armoured exchanges kuipa makes itself.
    env.push(("KUIPA_KDC", realm.socket.display().to_string()));
    // Vault sessions live in a runtime directory of their own.
    env.push((
        "KUIPA_RUNTIME_DIR",
        realm.dir.join("run-user").display().to_string(),
    ));
    // A software token (kryoptic) for a PKCS#11 device, when installed.
    let token_conf = realm.dir.join("kryoptic.conf");
    std::fs::write(
        &token_conf,
        format!(
            "[[slots]]\nslot = 42\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n",
            realm.dir.join("token.sql").display()
        ),
    )
    .unwrap();
    env.push(("KRYOPTIC_CONF", token_conf.display().to_string()));
    set_env(&env);
    realm.add_user(ADMIN, "Admin123");

    check_channel_bindings(&realm);
    let (directory, ipa, own_anchors) = start_ipa_servers(&realm, listeners, &urls);
    let world = Scenario {
        web1: root(&realm, "web1"),
        servers: Deployment::servers(&[SERVER.to_owned()]),
        anchors: [own_anchors[0]],
        realm,
        directory,
        ipa,
        own_anchors,
        urls,
        admin_ccache,
    };
    await_anchor_exchange(&world);
    let first = enroll_web1_with_otp(&world);
    protect_keytab(&world, &first);
    let copies = protect_other_keytab_and_file(&world);
    restore_copies_at_boot(&world, &copies);
    undo_copies(&world, &copies);
    let alice = personal_vault(&world);
    tlog_watch(&world, &alice);
    tlog_diverged(&world, &alice);
    daily_session(&world, &alice);
    offline_session(&world, &alice);
    registered_sealing(&world, &alice);
    shared_vault(&world, &alice);
    break_glass(&world, &alice);
    lost_laptop(&world, &alice);
    deposits(&world, &alice);
    escrows(&world, &alice);
    helpdesk_recovery(&world, &alice);
    token_device(&world, &alice);
    unprotect_host(&world);
    admin_ticket(&world);
    let conf_path = bootstrap_2fa(&world);
    password_enrollment(&world);
    collection_through_kuipa(&world, &conf_path);
    offline_enrollment(&world);
    realm_wide_strings(&world);
    refused_syncs(&world);
}

/// Alice's data directory in the test realm.
fn home_dir_of(realm: &Realm) -> std::path::PathBuf {
    realm.dir.join("alice-home")
}
