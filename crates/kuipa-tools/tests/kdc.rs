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
use tang_pqc::{ExchangeKeyPair, KemAlg, Policy, SignatureAlg, SigningKey, unix_seconds};

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

#[test]
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
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
        let client = GssClientCred::from_keytab_initiate(
            probe.to_str().unwrap(),
            "host/probe.example.test@EXAMPLE.TEST",
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
            servers: names.map(String::from).to_vec(),
            ca_certs: vec![realm.chain.ca_der.clone()],
            pkinit_anchors: vec![realm.chain.ca_der.clone()],
            anchors: vec![*anchor.public().thumbprint()],
            heads: Vec::new(),
            trusts: Vec::new(),
        };
        own_anchors.push(*anchor.public().thumbprint());
        let server = Arc::new(EnrollServer::new(keys, info, delegation));
        let key_dir = realm.dir.join(format!("keys-{fqdn}"));
        std::fs::create_dir_all(&key_dir).unwrap();
        let settings = Settings {
            me: fqdn.into(),
            realm: REALM.into(),
            peers: vec![other.into()],
            discover: false,
            endpoints: [(other.to_owned(), urls[1 - i].clone())].into(),
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
                limiter: kuipad::limit::Limiter::default(),
                tang: None,
                keys: None,
                ledger: None,
            }),
        );
        ipa.push(server);
    }

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
        for a in &own_anchors {
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
    let servers = Deployment::servers(&[SERVER.to_owned()]);
    // Clients pin ipa1's anchor only.
    let anchors = [own_anchors[0]];
    let string = |secret: Option<&[u8]>| {
        EnrollmentString::new(
            REALM,
            anchors[0],
            tang_pqc::unix_seconds(std::time::SystemTime::now()) + 86_400,
            secret.map(Secret::new),
        )
    };

    // ── OTP enrollment, then key rotation authenticated by the host keys ──
    // The OTP is also the host's temporary Kerberos key (FreeIPA's host-add
    // sets it): the host gets a ticket with it and rekeys itself.
    realm.add_user(&format!("host/web1.example.test@{REALM}"), "Secret123");
    let a = root(&realm, "web1");
    let mut s = string(Some(b"Secret123"));
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &a,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        &Auth::Otp(otp),
        "web1.example.test",
        &servers,
    )
    .unwrap();
    let first = kvnos(&a.keytab());
    assert_eq!(first.len(), 1);
    let rotated = flows::rotate_keys(&a, None).unwrap();
    assert_eq!(
        kvnos(&a.keytab()),
        vec![first[0], first[0] + 1],
        "new kvno plus the previous one: {rotated}"
    );
    let check = flows::check(&a, None).unwrap();
    assert_eq!(check["ok"], true, "{check}");

    // ── Keytab protection: rekey with escrow registration, unseal, undo ──
    flows::protect(&a, &Target::Host).unwrap();
    assert!(
        std::fs::symlink_metadata(a.keytab())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(flows::unseal(&a).unwrap().kvno(), Some(first[0] + 2));
    assert_eq!(flows::check(&a, None).unwrap()["ok"], true);

    // ── Another keytab and any file, sealed for their own principals and
    //    registered outside a rekey, with those principals' keys (§7.5) ──
    let service = format!("HTTP/web1.example.test@{REALM}");
    let http = realm.dir.join("http.keytab");
    let http_keys = realm.new_keys(&service);
    std::fs::write(&http, &http_keys).unwrap();
    let as_keytab = Target::Keytab(http.clone());
    let protected = flows::protect(&a, &as_keytab).unwrap();
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
    flows::protect(&a, &as_file).unwrap();
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
    let resealed = flows::protect(&a, &as_file).unwrap();
    assert_eq!(resealed["resealed"], true);
    assert_eq!(file_bindings().len(), 2, "the old seal's bindings retired");
    let stale = realm.dir.join("stale.sealed");
    std::fs::write(&stale, &first_seal).unwrap();
    assert!(
        flows::unseal_file(&a, &stale).is_err(),
        "retired seal opens"
    );

    // At boot every copy comes back through a server, as the host keytab
    // does; a host rekey replaces only the host's keytab bindings.
    flows::rotate_keys(&a, None).unwrap();
    for p in [a.run_keytab(), a.run_copy(&http), copy.clone()] {
        std::fs::remove_file(p).unwrap();
    }
    let all = flows::unseal_all(&a).unwrap();
    assert_eq!(all["written"].as_array().unwrap().len(), 3, "{all}");
    assert_eq!(std::fs::read(&http).unwrap(), http_keys);
    assert_eq!(std::fs::read(&secret).unwrap(), b"token=second\n");
    let check = flows::check(&a, None).unwrap();
    assert_eq!(check["ok"], true, "{check}");
    assert_eq!(
        flows::status(&a).unwrap()["protected"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Undo: plain again, and the bindings retired.
    let sealed_secret = std::fs::read(paths::sealed_for(&secret)).unwrap();
    let undone = flows::unprotect(&a, &as_file).unwrap();
    assert_eq!(undone["retired"], true, "{undone}");
    assert!(
        !std::fs::symlink_metadata(&secret)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&secret).unwrap(), b"token=second\n");
    assert_eq!(file_bindings(), Vec::<[u8; 32]>::new());
    std::fs::write(&stale, &sealed_secret).unwrap();
    assert!(
        flows::unseal_file(&a, &stale).is_err(),
        "retired seal opens"
    );
    let undone = flows::unprotect(&a, &as_keytab).unwrap();
    assert_eq!(undone["retired"], true, "{undone}");
    assert_eq!(std::fs::read(&http).unwrap(), http_keys);
    assert_eq!(
        directory.escrow.lock().unwrap()[&service],
        Vec::<[u8; 32]>::new()
    );
    assert!(!paths::sealed_for(&http).exists());

    // ── A user's own vault, with her ticket and a passphrase device (§7.6) ──
    // Alice is not root: she reads the host's public realm.json, anchors
    // and CA, and keeps everything of hers in her own directory.
    realm.add_user("alice@EXAMPLE.TEST", "Alice123");
    let alice_cc = realm.dir.join("alice.ccache");
    realm.kinit("alice@EXAMPLE.TEST", "Alice123", &alice_cc, None, None);
    let alice_cc = format!("FILE:{}", alice_cc.display());
    let home = UserPaths::new(realm.dir.join("alice-home"));
    let seal = Seal::new(&a, &home, Some(&alice_cc));
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
    let as_bob = Seal::new(&a, &home, Some(&bob_cc));
    assert!(as_bob.open(&sealed, Some(b"correct horse")).is_err());
    let listed = seal.list().unwrap();
    assert_eq!(listed["vaults"].as_array().unwrap().len(), 1);
    seal.revoke("personal").unwrap();
    assert!(seal.open(&sealed, Some(b"correct horse")).is_err());

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

    // A device on a token: an ML-KEM key that never leaves it, used through
    // pkcs11-provider; the PIN takes the passphrase's place.
    if let Some(module) = token_with_ml_kem_key() {
        let home = UserPaths::new(realm.dir.join("alice-token-home"));
        let seal = Seal::new(&a, &home, Some(&alice_cc));
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

    flows::unprotect(&a, &Target::Host).unwrap();
    assert!(!a.sealed().exists());
    flows::rotate_keys(&a, None).unwrap();

    // ── An administrator's existing ticket ──
    realm.kinit(ADMIN, "Admin123", &admin_ccache, None, None);
    let b = root(&realm, "web2");
    flows::enroll_online(
        &b,
        REALM,
        &anchors,
        &[],
        &[],
        &Auth::Ccache,
        "web2.example.test",
        &servers,
    )
    .unwrap();
    assert_eq!(kvnos(&b.keytab()).len(), 1);

    // ── 2FA bootstrap: the advertisement's PKINIT anchors give FAST armour ──
    let boot = realm.dir.join("bootstrap");
    flows::realm_info(REALM, &anchors, &[], &servers, &boot).unwrap();
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
        &admin_ccache,
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

    // ── A user's password: an armoured kinit on the host, then Kerberos ──
    let g = root(&realm, "web6");
    let password = |p: &[u8]| Auth::Password {
        principal: "admin".into(),
        password: Secret::new(p),
    };
    let err = flows::enroll_online(
        &g,
        REALM,
        &anchors,
        &[],
        &[],
        &password(b"guess"),
        "web6.example.test",
        &servers,
    )
    .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::NeedsAdmin(_))),
        "{err}"
    );
    flows::enroll_online(
        &g,
        REALM,
        &anchors,
        &[],
        &[],
        &password(b"Admin123"),
        "web6.example.test",
        &servers,
    )
    .unwrap();
    assert_eq!(kvnos(&g.keytab()).len(), 1);

    // ── Collection through kuipa: nobody brought a password ──
    let collected = Scripted {
        answer: b"Admin123",
        asked: std::cell::RefCell::new(Vec::new()),
    };
    kuipa_gssapi::ticket(
        &conf_path,
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
        &conf_path,
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
                &conf_path,
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

    let c = root(&realm, "web3");
    flows::enroll_online(
        &c,
        REALM,
        &anchors,
        &[],
        &[],
        &Auth::Ccache,
        "web3.example.test",
        &servers,
    )
    .unwrap();

    // ── Offline: prepare, stage (admin ticket), open the bundle, first contact ──
    let d = root(&realm, "web4");
    flows::prepare(&d, false, "web4.example.test").unwrap();
    let recipient =
        tang_pqc::ExchangeKey::from_jwk_json(&std::fs::read(d.recipient_public()).unwrap())
            .unwrap();
    let endpoint = Endpoint::new(SERVER, &Trust::FirstContact).unwrap();
    let adv = VerifiedRealm::verify(
        &endpoint.advertisement(&anchors).unwrap(),
        REALM,
        &anchors,
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
        Some(&string(None)),
        false,
        Some("web4.example.test"),
    )
    .unwrap();
    let staged = kvnos(&d.keytab());
    let completed = flows::complete(&d).unwrap();
    assert!(!d.pending().exists(), "{completed}");
    assert_eq!(kvnos(&d.keytab()), vec![staged[0], staged[0] + 1]);

    // ── Realm-wide strings: ipa1's anchor, enrollment through ipa2 alone ──
    let e = root(&realm, "web5");
    let mut s5 = string(Some(b"Secret123"));
    let otp = s5.take_secret().unwrap();
    let result = flows::enroll_online(
        &e,
        s5.realm(),
        &[*s5.anchor()],
        &[],
        &[],
        &Auth::LdapOtp(otp),
        "web5.example.test",
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
