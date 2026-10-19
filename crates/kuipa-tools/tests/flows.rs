//! Client flows against the daemon's HTTP router with an in-memory
//! directory: online OTP enrollment with failover and refusal, offline
//! bundles, status and leave.  (Kerberos-authenticated flows need a KDC and
//! are left to the integration environment.)

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use kuipa_enroll::EnrollServer;
use kuipa_enroll::bundle::{Bundle, Recipient};
use kuipa_enroll::delegation::Delegation;
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::keytab::{Enctype, Keytab, KeytabEntry, Principal};
use kuipa_enroll::payload::{Enrollment, RealmConfig};
use kuipa_enroll::realm::{RealmInfo, ServerKeys};
use kuipa_enroll::server::{Directory, DirectoryError, Staged};
use kuipa_tools::flows::{self, Auth, Outcome};
use kuipa_tools::paths::Paths;
use kuipad::http::{App, router};
use kuipad::limit::{Limiter, Limits, Rate};
use native_ossl::util::SecretBuf;
use tang_pqc::{ExchangeKeyPair, KemAlg, SignatureAlg, SigningKey, unix_seconds};

const REALM: &str = "EXAMPLE.TEST";
const HOST: &str = "web1.example.test";
const CA: &[u8] = b"IPA CA (DER)";

#[derive(Default)]
struct Dir {
    otps: Mutex<HashMap<String, Vec<u8>>>,
    kvno: Mutex<u32>,
}

impl Dir {
    fn keys(&self, fqdn: &str) -> Keytab {
        let mut kvno = self.kvno.lock().unwrap();
        *kvno += 1;
        Keytab::new(
            Principal::host(fqdn, REALM),
            vec![KeytabEntry {
                kvno: *kvno,
                enctype: Enctype::AES256_CTS_HMAC_SHA1_96,
                key: SecretBuf::from_slice(&[7; 32]),
                timestamp: 1,
            }],
        )
    }
}

impl Directory for Dir {
    fn join_with_otp(
        &self,
        fqdn: &str,
        otp: &[u8],
        _: &[Enctype],
    ) -> Result<Keytab, DirectoryError> {
        let mut otps = self.otps.lock().unwrap();
        if otps.get(fqdn).is_some_and(|o| o == otp) {
            otps.remove(fqdn);
            drop(otps);
            Ok(self.keys(fqdn))
        } else {
            Err("bad OTP".into())
        }
    }
    fn join_with_gss(
        &self,
        _: &str,
        _: &[u8],
        _: &[u8; 32],
        _: &[Enctype],
    ) -> Result<(Keytab, kuipa_enroll::join::KerberosBinding), DirectoryError> {
        Err("no KDC in this test".into())
    }
    fn rekey_with_gss(
        &self,
        _: &str,
        _: &[u8],
        _: &[u8; 32],
        _: &[Enctype],
    ) -> Result<(Keytab, kuipa_enroll::join::KerberosBinding), DirectoryError> {
        Err("no KDC in this test".into())
    }
    fn stage_with_gss(
        &self,
        _: &str,
        _: &[u8],
        _: &[u8; 32],
        _: &[Enctype],
        _: &Staged,
    ) -> Result<(Keytab, kuipa_enroll::join::KerberosBinding), DirectoryError> {
        Err("no KDC in this test".into())
    }
    fn register_escrow(&self, _: &Principal, _: &[[u8; 32]]) -> Result<(), DirectoryError> {
        Ok(())
    }
    fn escrow_allowed(&self, _: &Principal, _: &[u8; 32]) -> Result<bool, DirectoryError> {
        Ok(false)
    }
    fn ca_certificates(&self) -> Result<Vec<Vec<u8>>, DirectoryError> {
        Ok(vec![CA.to_vec()])
    }
    fn servers(&self) -> Result<Vec<String>, DirectoryError> {
        Ok(vec!["ipa1.example.test".into(), "ipa2.example.test".into()])
    }
}

fn now() -> u64 {
    unix_seconds(SystemTime::now())
}

thread_local! {
    static TRACE: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Writes trace output into the current thread's buffer.
struct ThreadCapture;

impl std::io::Write for ThreadCapture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        TRACE.with(|t| t.borrow_mut().extend_from_slice(b));
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `f` with its events traced at the most detailed level, as
/// `kuipa --trace` would show them; return the output too.  The
/// subscriber is process-wide (tracing caches interest per call site across
/// threads), and each thread's events go to that thread's buffer.
fn traced<T>(f: impl FnOnce() -> T) -> (T, String) {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(|| ThreadCapture)
            .init();
    });
    TRACE.with(|t| t.borrow_mut().clear());
    let out = f();
    let text = TRACE.with(|t| String::from_utf8(std::mem::take(&mut *t.borrow_mut())).unwrap());
    (out, text)
}

fn server_keys(anchor: &SigningKey, fqdn: &str) -> (ServerKeys, RealmInfo, Delegation) {
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let delegation = Delegation::issue(
        anchor,
        REALM,
        fqdn,
        signing.public(),
        now() - 60,
        now() + 86400,
    )
    .unwrap();
    (
        ServerKeys {
            signing,
            join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            trust: Vec::new(),
            vouchers: Vec::new(),
            retired: Vec::new(),
        },
        RealmInfo {
            realm: REALM.into(),
            domain: "example.test".into(),
            basedn: "dc=example,dc=test".into(),
            server: fqdn.into(),
            servers: vec!["ipa1.example.test".into(), "ipa2.example.test".into()],
            ca_certs: vec![CA.to_vec()],
            pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
            anchors: vec![*anchor.public().thumbprint()],
            trusts: Vec::new(),
        },
        delegation,
    )
}

/// Serve `router` on 127.0.0.1 in a background runtime; return its URL.
fn spawn(app: Arc<App<Dir>>) -> String {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        rt.block_on(async move { axum::serve(listener, router(app)).await.unwrap() });
    });
    url
}

/// A client root in a temporary directory, removed when dropped.
struct TempRoot {
    dir: PathBuf,
    paths: Paths,
}

impl std::ops::Deref for TempRoot {
    type Target = Paths;
    fn deref(&self) -> &Paths {
        &self.paths
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn root(name: &str) -> TempRoot {
    let dir: PathBuf =
        std::env::temp_dir().join(format!("kuipa-flows-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    TempRoot {
        paths: Paths::new(&dir),
        dir,
    }
}

fn string(anchor: &SigningKey, secret: &[u8]) -> EnrollmentString {
    EnrollmentString::new(
        REALM,
        *anchor.public().thumbprint(),
        tang_pqc::unix_seconds(std::time::SystemTime::now()) + 86_400,
        Some(Secret::new(secret)),
    )
}

#[test]
fn online_enrollment_with_failover() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, info, delegation) = server_keys(&anchor, "ipa2.example.test");
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = spawn(Arc::new(App {
        server: Arc::new(EnrollServer::new(keys, info, delegation)),
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        directory: dir,
    }));
    let paths = root("online");

    // ipa1 is down (nothing listens on port 9): fail over to ipa2.
    let dead = "http://127.0.0.1:9".to_owned();
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &paths,
            s.realm(),
            &[*s.anchor()],
            &Auth::LdapOtp(otp),
            HOST,
            &[dead.clone(), url.clone()],
        )
    });
    let result = result.unwrap();
    assert_eq!(result["issuer"], "ipa2.example.test");
    // The trace shows the failover, the request and what came back, and
    // never the OTP.
    for step in [
        "skipped, trying the next server",
        "advertisement verified: ipa2.example.test",
        "Join request for web1.example.test",
        "received keys for host/web1.example.test@EXAMPLE.TEST",
        "wrote ",
    ] {
        assert!(trace.contains(step), "{step:?} missing from:\n{trace}");
    }
    assert!(
        !trace.contains("Secret123"),
        "the OTP leaked into:\n{trace}"
    );
    assert_eq!(result["kvno"], 1);

    let kt = Keytab::from_mit(&std::fs::read(paths.keytab()).unwrap()).unwrap();
    assert_eq!(kt.principal(), &Principal::host(HOST, REALM));
    let ca = synta_certificate::pem_to_der(&std::fs::read(paths.ca()).unwrap());
    assert_eq!(ca, vec![CA.to_vec()]);

    let status = flows::status(&paths).unwrap();
    assert_eq!(status["enrolled"], true);
    assert_eq!(status["servers"][0], "ipa2.example.test", "issuer first");

    // The OTP is consumed: a second enrollment is refused (needs an admin).
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    let err = flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &Auth::LdapOtp(otp),
        HOST,
        &[url],
    )
    .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::NeedsAdmin(_))),
        "{err}"
    );

    // No reachable server at all: retry later.
    let mut s = string(&anchor, b"x");
    let otp = s.take_secret().unwrap();
    let err = flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &Auth::LdapOtp(otp),
        HOST,
        &[dead],
    )
    .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::RetryLater(_))),
        "{err}"
    );

    flows::leave(&paths).unwrap();
    assert_eq!(flows::status(&paths).unwrap()["enrolled"], false);
}

#[test]
fn guessing_is_rate_limited_per_host() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, info, delegation) = server_keys(&anchor, "ipa1.example.test");
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = spawn(Arc::new(App {
        server: Arc::new(EnrollServer::new(keys, info, delegation)),
        directory: dir,
        peers: None,
        limiter: Limiter::new(Limits {
            per_host: Rate {
                burst: 1.0,
                per_minute: 0.01,
            },
            ..Limits::default()
        }),
        tang: None,
    }));
    let guess = |otp: &[u8]| {
        let mut s = string(&anchor, otp);
        let otp = s.take_secret().unwrap();
        flows::enroll_online(
            &root("limited"),
            s.realm(),
            &[*s.anchor()],
            &Auth::LdapOtp(otp),
            HOST,
            std::slice::from_ref(&url),
        )
        .unwrap_err()
    };
    // A wrong OTP is refused...
    assert!(matches!(
        guess(b"guess1").downcast_ref::<Outcome>(),
        Some(Outcome::NeedsAdmin(_))
    ));
    // ...and the next attempt for the host is not processed at all, even
    // with the right OTP: retry later (or elsewhere).
    let err = guess(b"Secret123");
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::RetryLater(m)) if m.contains("429")),
        "{err}"
    );
}

#[test]
fn wrong_anchor_is_not_a_usable_server() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, info, delegation) = server_keys(&anchor, "ipa1.example.test");
    let url = spawn(Arc::new(App {
        server: Arc::new(EnrollServer::new(keys, info, delegation)),
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        directory: Dir::default(),
    }));
    let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let mut s = string(&other, b"Secret123");
    let otp = s.take_secret().unwrap();
    let err = flows::enroll_online(
        &root("anchor"),
        s.realm(),
        &[*s.anchor()],
        &Auth::LdapOtp(otp),
        HOST,
        &[url],
    )
    .unwrap_err();
    assert!(err.to_string().contains("anchor"), "{err}");
}

#[test]
fn rotated_anchors_are_followed_and_old_strings_expire() {
    // The server's anchor was rotated: old signed the succession to new.
    let (old, new) = (
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
    );
    let (keys, info, mut delegation) = server_keys(&new, "ipa1.example.test");
    delegation.add_successions([kuipa_enroll::delegation::SignedSuccession::issue(
        &old,
        REALM,
        new.public().thumbprint(),
        now() - 60,
        now() + 86400,
    )
    .unwrap()]);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = spawn(Arc::new(App {
        server: Arc::new(EnrollServer::new(keys, info, delegation)),
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        directory: dir,
    }));

    // A string that still names the old anchor works through the
    // succession, and the host stores the realm's current anchors.
    let paths = root("rotated");
    let mut s = string(&old, b"Secret123");
    flows::check_string(&s).unwrap();
    let otp = s.take_secret().unwrap();
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &paths,
            s.realm(),
            &[*s.anchor()],
            &Auth::LdapOtp(otp),
            HOST,
            std::slice::from_ref(&url),
        )
    });
    result.unwrap();
    assert!(trace.contains("was rotated: succeeded by"), "{trace}");
    assert_eq!(
        kuipa_tools::paths::read_anchors(&paths).unwrap(),
        vec![*new.public().thumbprint()]
    );

    // An expired string is refused before anything is sent.
    let expired = EnrollmentString::new(
        REALM,
        *old.public().thumbprint(),
        now() - 3600,
        Some(Secret::new(b"x")),
    );
    let err = flows::check_string(&expired).unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
    let err = flows::enroll_bundle(&root("expired"), b"", Some(&expired), false, None).unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
}

#[test]
fn offline_enrollment_from_a_bundle() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, _, delegation) = server_keys(&anchor, "ipa1.example.test");
    let paths = root("bundle");

    // On the host: prepare a machine key.
    let prepared = flows::prepare(&paths, false, HOST).unwrap();
    assert!(
        prepared["admin_command"]
            .as_str()
            .unwrap()
            .contains("--pq-stage")
    );
    let public =
        tang_pqc::ExchangeKey::from_jwk_json(&std::fs::read(paths.recipient_public()).unwrap())
            .unwrap();
    // Idempotent.
    assert_eq!(
        flows::prepare(&paths, false, HOST).unwrap()["thumbprint"],
        prepared["thumbprint"]
    );

    // On the server: stage (what the daemon does after stage_with_gss).
    let enrollment = Enrollment {
        config: RealmConfig {
            realm: REALM.into(),
            domain: "example.test".into(),
            basedn: "dc=example,dc=test".into(),
            issuer: "ipa1.example.test".into(),
            servers: vec!["ipa2.example.test".into()],
        },
        keytab: Dir::default().keys(HOST),
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![*anchor.public().thumbprint()],
    };
    let (bundle, _) = Bundle::create(
        &keys,
        &delegation,
        KemAlg::MlKem768,
        Recipient::MachineKey(&public),
        &enrollment,
        now(),
        now() + 3600,
    )
    .unwrap();

    // Offline on the host: only the bundle and the anchor.
    let s = EnrollmentString::new(
        REALM,
        *anchor.public().thumbprint(),
        tang_pqc::unix_seconds(std::time::SystemTime::now()) + 86_400,
        None,
    );
    let result =
        flows::enroll_bundle(&paths, &bundle.to_bytes(), Some(&s), false, Some(HOST)).unwrap();
    assert_eq!(result["enrollment"]["issuer"], "ipa1.example.test");
    assert!(
        !paths.recipient().exists(),
        "machine key deleted after opening"
    );
    assert!(paths.pending().exists());
    let status = flows::status(&paths).unwrap();
    assert!(status["pending"]["steps"].as_array().unwrap().len() > 1);

    // A bundle for another host is refused.
    assert!(
        flows::enroll_bundle(
            &paths,
            &bundle.to_bytes(),
            Some(&s),
            false,
            Some("other.example.test")
        )
        .is_err()
    );
}

/// Enrollment without a Kerberos KDC (the LDAP-checked OTP), the Kerberos
/// configuration `realm-info` writes from the advertisement, and pins
/// pre-provisioned instead of an enrollment string.  Password and Kerberos
/// OTP joins need a KDC: `tests/kdc.rs`.
#[test]
#[allow(clippy::too_many_lines)]
fn ldap_otp_enrollment_and_kerberos_bootstrap() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, info, delegation) = server_keys(&anchor, "ipa1.example.test");
    let app = Arc::new(App {
        server: Arc::new(EnrollServer::new(keys, info, delegation)),
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        directory: Dir::default(),
    });
    let url = spawn(app.clone());
    let otp = || {
        app.directory
            .otps
            .lock()
            .unwrap()
            .insert(HOST.into(), b"Secret123".to_vec());
        Auth::LdapOtp(Secret::new(b"Secret123"))
    };
    let s = EnrollmentString::new(
        REALM,
        *anchor.public().thumbprint(),
        tang_pqc::unix_seconds(std::time::SystemTime::now()) + 86_400,
        None,
    );

    // Before enrollment: the Kerberos configuration for an armoured kinit.
    let paths = root("ldap-otp");
    let dir = paths.dir.join("krb5");
    let info = flows::realm_info(
        REALM,
        &[*anchor.public().thumbprint()],
        std::slice::from_ref(&url),
        &dir,
    )
    .unwrap();
    assert_eq!(info["server"], "ipa1.example.test");
    let conf = std::fs::read_to_string(dir.join("krb5.conf")).unwrap();
    assert!(conf.contains("kdc = ipa1.example.test:88"));
    assert!(conf.contains(&format!(
        "pkinit_anchors = FILE:{}",
        dir.join("pkinit-anchors.pem").display()
    )));
    let anchors =
        synta_certificate::pem_to_der(&std::fs::read(dir.join("pkinit-anchors.pem")).unwrap());
    assert_eq!(anchors, vec![b"PKINIT anchor (DER)".to_vec()]);

    // A wrong OTP is refused; the right one enrolls.
    let err = flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &Auth::LdapOtp(Secret::new(b"guess")),
        HOST,
        std::slice::from_ref(&url),
    )
    .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<Outcome>(),
        Some(Outcome::NeedsAdmin(_))
    ));
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &paths,
            s.realm(),
            &[*s.anchor()],
            &otp(),
            HOST,
            std::slice::from_ref(&url),
        )
    });
    result.unwrap();
    assert!(trace.contains("with Otp authentication"), "{trace}");

    // Enrollment leaves a fallback krb5.conf and the PKINIT anchors behind.
    let conf = std::fs::read_to_string(paths.krb5_conf()).unwrap();
    assert!(conf.contains("default_realm = EXAMPLE.TEST"));
    assert!(
        conf.find("kdc = ipa1.example.test").unwrap()
            < conf.find("kdc = ipa2.example.test").unwrap()
    );
    assert!(paths.pkinit_anchors().exists());
    flows::leave(&paths).unwrap();
    assert!(!paths.krb5_conf().exists());

    // No enrollment string: anchors pre-provisioned in /etc/ipa/ku-anchors
    // (an image), one of them unrelated, are enough for both steps.
    let stranger = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    kuipa_tools::paths::write_anchors(
        &paths,
        &[
            *stranger.public().thumbprint(),
            *anchor.public().thumbprint(),
        ],
    )
    .unwrap();
    let pinned = kuipa_tools::paths::read_anchors(&paths).unwrap();
    flows::realm_info(REALM, &pinned, std::slice::from_ref(&url), &dir).unwrap();
    flows::enroll_online(
        &paths,
        REALM,
        &pinned,
        &otp(),
        HOST,
        std::slice::from_ref(&url),
    )
    .unwrap();
    // Only the unrelated anchor pinned: no server verifies.
    let err = flows::enroll_online(
        &root("ldap-otp-stranger"),
        REALM,
        &[*stranger.public().thumbprint()],
        &otp(),
        HOST,
        &[url],
    )
    .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::RetryLater(_))),
        "{err}"
    );
}

/// The daemon as a post-quantum Tang server (DESIGN §11.5), driven over
/// HTTP with `tang-pqc`'s client as a Clevis pin would: provision against
/// the pinned thumbprint, recover, rotate, and recover the old binding and
/// verify the new keys with the old pin through `adv/{thp}`.
#[test]
#[allow(clippy::too_many_lines)]
fn post_quantum_tang_over_http() {
    use kuipad::tang::TangKeys;
    use tang_pqc::{Binding, RecoveryResponse, SignedAdvertisement};

    let root = root("tang");
    let keys = TangKeys::new(&root.dir.join("keys"));
    let old = keys.generate().unwrap();
    let serve = |keys: &TangKeys| {
        let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let (server_keys, info, delegation) = server_keys(&anchor, "ipa1.example.test");
        spawn(Arc::new(App {
            server: Arc::new(EnrollServer::new(server_keys, info, delegation)),
            directory: Dir::default(),
            peers: None,
            limiter: Limiter::default(),
            tang: keys.server().unwrap().map(Arc::new),
        }))
    };
    let _ = rustls_native_ossl::default_provider().install_default();
    let http = reqwest::blocking::Client::new();
    let adv = |url: &str, path: &str| -> SignedAdvertisement {
        let r = http
            .get(format!("{url}/ipa/ku/tang/{path}"))
            .send()
            .unwrap();
        assert_eq!(r.status(), 200, "{path}");
        assert_eq!(r.headers()["content-type"], "application/jose+json");
        SignedAdvertisement::from_json(&r.bytes().unwrap()).unwrap()
    };
    let exchange_key = |url: &str, kid: &tang_pqc::Thumbprint| {
        let r = http
            .get(format!("{url}/ipa/ku/tang/key/{kid}"))
            .send()
            .unwrap();
        assert_eq!(r.status(), 200, "key/{kid}");
        assert_eq!(r.headers()["content-type"], "application/jwk+json");
        tang_pqc::ExchangeKey::from_jwk_json(&r.bytes().unwrap()).unwrap()
    };
    let recover = |url: &str, binding: &Binding| {
        let ek = exchange_key(url, binding.kid());
        let (request, pending) = binding.recovery_request(&ek).unwrap();
        let r = http
            .post(format!("{url}/ipa/ku/tang/rec/{}", request.kid()))
            .body(request.to_bytes())
            .send()
            .unwrap();
        assert_eq!(r.status(), 200);
        let response = RecoveryResponse::from_bytes(&r.bytes().unwrap()).unwrap();
        pending.finish(&response).unwrap()
    };

    // ── clevis encrypt, then unlock ──
    let url = serve(&keys);
    let pin = |url: &str, thp: &tang_pqc::Thumbprint| tang_pqc_clevis::Config {
        url: format!("{url}/ipa/ku/tang"),
        thp: Some(thp.to_string()),
        adv: None,
        ca: None,
    };
    let jwe = tang_pqc_clevis::encrypt(&pin(&url, &old), b"passphrase").unwrap();
    assert_eq!(
        tang_pqc_clevis::decrypt(&jwe).unwrap().as_ref(),
        b"passphrase"
    );
    let (binding, key) = adv(&url, "adv")
        .verify(&old)
        .unwrap()
        .provision(None)
        .unwrap();
    let binding = Binding::from_bytes(&binding.to_bytes()).unwrap();
    assert_eq!(recover(&url, &binding).as_ref(), key.as_ref());
    // The enrollment advertisement is separate and offers no Tang key.
    let ipa = http.get(format!("{url}/ipa/ku/adv")).send().unwrap();
    assert!(!ipa.text().unwrap().contains(&old.to_string()));

    // ── Errors as Tang has them ──
    let (request, _) = binding
        .recovery_request(&exchange_key(&url, binding.kid()))
        .unwrap();
    let wrong = |kid: &str, body: Vec<u8>| {
        http.post(format!("{url}/ipa/ku/tang/rec/{kid}"))
            .body(body)
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(
        wrong("AAAA", request.to_bytes()),
        400,
        "kid not the request's"
    );
    assert_eq!(wrong(&request.kid().to_string(), b"junk".to_vec()), 400);
    let unknown = tang_pqc::Thumbprint::from_bytes([7; 32]);
    for path in ["adv", "key"] {
        let r = http
            .get(format!("{url}/ipa/ku/tang/{path}/{unknown}"))
            .send()
            .unwrap();
        assert_eq!(r.status(), 404, "{path}/{{unknown}}");
    }

    // ── tangd-rotate-keys: the old binding still opens, the old pin still
    //    verifies the new keys through adv/{old} ──
    let new = keys.rotate().unwrap();
    let url = serve(&keys);
    // The pin: this test's restarted server has another port, and the
    // JWE header (with the URL) is authenticated, so pointing the old JWE
    // at it fails; the old binding itself still opens (above). Encrypting
    // with the old pin binds to the new keys through adv/{old}.
    let rewritten = {
        let mut parts: Vec<String> = jwe.split('.').map(str::to_owned).collect();
        let h = String::from_utf8(tang_pqc::b64::decode(&parts[0]).unwrap()).unwrap();
        let old_url = h
            .split("\"url\":\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        parts[0] =
            tang_pqc::b64::encode(h.replace(old_url, &format!("{url}/ipa/ku/tang")).as_bytes());
        parts.join(".")
    };
    assert!(tang_pqc_clevis::decrypt(&rewritten).is_err());
    let regen = tang_pqc_clevis::encrypt(&pin(&url, &old), b"passphrase").unwrap();
    assert_eq!(
        tang_pqc_clevis::decrypt(&regen).unwrap().as_ref(),
        b"passphrase"
    );
    assert_eq!(recover(&url, &binding).as_ref(), key.as_ref());
    assert!(adv(&url, "adv").verify(&old).is_err());
    let countersigned = adv(&url, &format!("adv/{old}"));
    let (rebound, rekey) = countersigned.verify(&old).unwrap().provision(None).unwrap();
    assert_eq!(rebound.to_bytes().len(), binding.to_bytes().len());
    assert!(countersigned.verify(&new).is_ok());
    assert_eq!(
        recover(&url, &Binding::from_bytes(&rebound.to_bytes()).unwrap()).as_ref(),
        rekey.as_ref()
    );

    // ── Without Tang keys there is no Tang ──
    let none = TangKeys::new(&root.dir.join("empty"));
    let url = serve(&none);
    let r = http.get(format!("{url}/ipa/ku/tang/adv")).send().unwrap();
    assert_eq!(r.status(), 404);
}
