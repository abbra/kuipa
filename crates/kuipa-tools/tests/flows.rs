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
use kuipa_enroll::delegation::{Delegation, SignedVouch};
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::epoch::{AnchorEpoch, SignedEpoch};
use kuipa_enroll::keytab::{Enctype, Keytab, KeytabEntry, Principal};
use kuipa_enroll::merkle::TreeHash;
use kuipa_enroll::payload::{Enrollment, RealmConfig};
use kuipa_enroll::realm::{Deployment, RealmInfo, ServerKeys};
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
    fn register_escrow(
        &self,
        _: &Principal,
        _: &[kuipa_enroll::escrow::BindingHash],
    ) -> Result<(), DirectoryError> {
        Ok(())
    }
    fn escrow_allowed(
        &self,
        _: &Principal,
        _: kuipa_enroll::escrow::Kind,
        _: &kuipa_enroll::escrow::BindingHash,
    ) -> Result<bool, DirectoryError> {
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

/// The tree hash of the ML-DSA-65 keys these tests sign with.
const S256: TreeHash = TreeHash::Sha256;

/// A SHA-256-sized tree hash of `byte`s.
fn test_hash(byte: u8) -> kuipa_enroll::merkle::Hash {
    kuipa_enroll::merkle::Hash::from_slice(&[byte; 32]).unwrap()
}

/// The hash of the log `keys` sign.
fn tree(keys: &ServerKeys) -> TreeHash {
    TreeHash::for_signer(keys.signing.public().alg())
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
            heads: Vec::new(),
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

/// Serve `app` as server `name` for this test's thread: the client dials
/// `name`, as it would in a real deployment, and reaches the test server.
fn serve_as(name: &str, app: Arc<App<Dir>>) -> String {
    let url = spawn(app);
    kuipa_tools::net::set_thread_endpoint(name, &url);
    name.to_owned()
}

/// The bare enroll server behind an otherwise-empty app.
fn app(server: Arc<EnrollServer>, directory: Dir) -> Arc<App<Dir>> {
    Arc::new(App {
        server,
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        keys: None,
        ledger: None,
        directory,
    })
}

/// Make server `name` unreachable for this test's thread (nothing listens
/// on port 9).
fn down(name: &str) -> String {
    kuipa_tools::net::set_thread_endpoint(name, "http://127.0.0.1:9");
    name.to_owned()
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

/// A v2 enrollment string pinning the anchor's vouch head (§4.9).
fn string_with_head(
    anchor: &SigningKey,
    head: (u64, kuipa_enroll::merkle::Hash),
    secret: &[u8],
) -> EnrollmentString {
    EnrollmentString::with_head(
        REALM,
        *anchor.public().thumbprint(),
        Some(head),
        tang_pqc::unix_seconds(std::time::SystemTime::now()) + 86_400,
        Some(Secret::new(secret)),
    )
}

#[test]
fn head_pinned_client_enrolls_without_any_signature() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, info, mut delegation) = server_keys(&anchor, "ipa1.example.test");
    // The anchor vouches for the claim; the delegation carries its proof.
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let head = vouch.head();
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(*anchor.public().thumbprint(), vouch);
    let server = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
    server.publish(delegation, vec![*anchor.public().thumbprint()], vouches);

    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = serve_as("ipa1.example.test", app(server, dir));
    let paths = root("head-pinned");

    // The client pins the head: the advertisement it fetches carries no
    // anchor key and no signature, and still verifies.
    let mut s = string_with_head(&anchor, head, b"Secret123");
    let otp = s.take_secret().unwrap();
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &paths,
            s.realm(),
            &[*s.anchor()],
            [s.head().unwrap()].as_slice(),
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &Auth::LdapOtp(otp),
            },
            &Deployment::servers(std::slice::from_ref(&url)),
        )
    });
    let result = result.unwrap();
    assert_eq!(result["issuer"], "ipa1.example.test");
    assert!(trace.contains("advertisement verified"), "{trace}");

    // The rekey wrote the pin file with the head: the next exchange can
    // also be signature-free.
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].heads, vec![head], "the head is pinned");

    // The advertisement itself, asked with the head, carries a head proof
    // only: no JWK, no signature value.
    let endpoint = kuipa_tools::net::Endpoint::new(&url, &kuipa_tools::net::Trust::FirstContact)
        .expect("endpoint");
    let adv = endpoint
        .advertisement_with_heads(&[*anchor.public().thumbprint()], &[s.head().unwrap()])
        .unwrap();
    let delegation = adv
        .unverified_member("delegation")
        .expect("delegation member")
        .expect("present");
    let body = delegation.to_string();
    assert!(body.contains("head_proofs"), "no head proof in:\n{body}");
    assert!(
        !body.contains("signatures"),
        "a signature proof was served to a head-pinned client:\n{body}"
    );
    // And it verifies against the pinned head with no signature at all.
    kuipa_enroll::realm::VerifiedRealm::verify_with_heads(
        &adv,
        REALM,
        &[*anchor.public().thumbprint()],
        &[s.head().unwrap()],
        &[],
        &tang_pqc::Policy::default(),
        std::time::SystemTime::now(),
    )
    .unwrap();
}

#[test]
fn a_stale_head_falls_back_to_the_signature_proof() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, info, mut delegation) = server_keys(&anchor, "ipa1.example.test");
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(*anchor.public().thumbprint(), vouch);
    let server = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
    server.publish(delegation, vec![*anchor.public().thumbprint()], vouches);

    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = serve_as("ipa1.example.test", app(server, dir));
    let paths = root("stale-head");

    // A head the vouch does not make (a stale pin, or another realm's):
    // the server cannot serve a head proof, and serves the signature
    // proof instead.  The client pins the anchor by thumbprint too, so
    // verification succeeds through the signature.
    let mut s = string_with_head(&anchor, (7, test_hash(9)), b"Secret123");
    let otp = s.take_secret().unwrap();
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &paths,
            s.realm(),
            &[*s.anchor()],
            &[s.head().unwrap()],
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &Auth::LdapOtp(otp),
            },
            &Deployment::servers(&[url]),
        )
    });
    let result = result.unwrap();
    assert_eq!(result["issuer"], "ipa1.example.test");
    assert!(trace.contains("advertisement verified"), "{trace}");
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
    let url = serve_as(
        "ipa2.example.test",
        app(Arc::new(EnrollServer::new(keys, info, delegation)), dir),
    );
    let paths = root("online");

    // ipa1 is down (nothing listens on port 9): fail over to ipa2.
    let dead = down("ipa1.example.test");
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &paths,
            s.realm(),
            &[*s.anchor()],
            &[],
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &Auth::LdapOtp(otp),
            },
            &Deployment::servers(&[dead.clone(), url.clone()]),
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
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(&[url]),
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
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(&[dead]),
    )
    .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::RetryLater(_))),
        "{err}"
    );

    flows::leave(&paths).unwrap();
    assert_eq!(flows::status(&paths).unwrap()["enrolled"], false);
}

/// The advertisement verifies (the anchor vouches for it), but describes
/// another deployment than the client was told to join: refused before any
/// request, without failing over, and before any secret leaves the host
/// (DESIGN §4.6).
#[test]
fn advertisement_must_describe_the_deployment() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let server = |fqdn: &str, dir: Dir| {
        let (keys, info, delegation) = server_keys(&anchor, fqdn);
        app(Arc::new(EnrollServer::new(keys, info, delegation)), dir)
    };
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let honest = server("ipa2.example.test", dir);
    // Reached as ipa1, but delegated as a server of another name.
    serve_as(
        "ipa1.example.test",
        server("rogue.example.test", Dir::default()),
    );
    serve_as("ipa2.example.test", honest.clone());
    let needs_admin = |err: &(dyn std::error::Error + Send + Sync + 'static), why: &str| {
        assert!(
            matches!(err.downcast_ref::<Outcome>(), Some(Outcome::NeedsAdmin(m)) if m.contains(why)),
            "{err}"
        );
    };
    let ldap_otp = |deployment: &Deployment| {
        let mut s = string(&anchor, b"Secret123");
        let otp = s.take_secret().unwrap();
        flows::enroll_online(
            &root("deployment"),
            s.realm(),
            &[*s.anchor()],
            &[],
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &Auth::LdapOtp(otp),
            },
            deployment,
        )
    };
    let both = Deployment::servers(&["ipa1.example.test".into(), "ipa2.example.test".into()]);

    // ipa1 answers as another server: stop, do not fail over to ipa2.
    let (result, trace) = traced(|| ldap_otp(&both));
    needs_admin(
        &*result.unwrap_err(),
        "ipa1.example.test: the advertisement is for server rogue.example.test",
    );
    assert!(!trace.contains("Join request"), "{trace}");

    // Another domain than the one the client was given.
    let elsewhere = Deployment {
        servers: vec!["ipa2.example.test".into()],
        domain: Some("example.org".into()),
    };
    needs_admin(&*ldap_otp(&elsewhere).unwrap_err(), "not example.org");

    // A password is not sent to any KDC: refused before the armoured kinit.
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &root("deployment-password"),
            REALM,
            &[*anchor.public().thumbprint()],
            &[],
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &Auth::Password {
                    principal: "admin".into(),
                    password: Secret::new(b"Secret123"),
                },
            },
            &both,
        )
    });
    needs_admin(&*result.unwrap_err(), "rogue.example.test");
    assert!(!trace.contains("armoured AS exchange"), "{trace}");

    // realm-info refuses too, and writes nothing.
    let out = root("deployment-realm-info");
    let krb5 = out.dir.join("krb5");
    let err =
        flows::realm_info(REALM, &[*anchor.public().thumbprint()], &[], &both, &krb5).unwrap_err();
    needs_admin(&*err, "rogue.example.test");
    assert!(!krb5.join("krb5.conf").exists());

    // None of that used the OTP: the honest deployment still enrolls.
    let ok = Deployment {
        servers: vec!["ipa2.example.test".into()],
        domain: Some("Example.Test".into()),
    };
    assert_eq!(ldap_otp(&ok).unwrap()["issuer"], "ipa2.example.test");
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
    let url = serve_as(
        "ipa1.example.test",
        Arc::new(App {
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
            keys: None,
            ledger: None,
        }),
    );
    let guess = |otp: &[u8]| {
        let mut s = string(&anchor, otp);
        let otp = s.take_secret().unwrap();
        flows::enroll_online(
            &root("limited"),
            s.realm(),
            &[*s.anchor()],
            &[],
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &Auth::LdapOtp(otp),
            },
            &Deployment::servers(std::slice::from_ref(&url)),
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
    let url = serve_as(
        "ipa1.example.test",
        app(
            Arc::new(EnrollServer::new(keys, info, delegation)),
            Dir::default(),
        ),
    );
    let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let mut s = string(&other, b"Secret123");
    let otp = s.take_secret().unwrap();
    let err = flows::enroll_online(
        &root("anchor"),
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(&[url]),
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
    let url = serve_as(
        "ipa1.example.test",
        app(Arc::new(EnrollServer::new(keys, info, delegation)), dir),
    );

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
            &[],
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &Auth::LdapOtp(otp),
            },
            &Deployment::servers(std::slice::from_ref(&url)),
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

/// A log that forks from the one the host pinned is reported as forked.
fn served_fork_is_refused(
    old: &SigningKey,
    new: &SigningKey,
    first: &AnchorEpoch,
    pins: [tang_pqc::Thumbprint; 2],
    succession: kuipa_enroll::delegation::SignedSuccession,
    paths: &kuipa_tools::paths::Paths,
) {
    // The same sequence with different content: the two servers minted
    // different entries; the host sees the fork.
    let (keys4, info4, mut delegation4) = server_keys(new, "ipa1.example.test");
    delegation4.add_successions([succession]);
    let forked = AnchorEpoch::new(REALM, 2, first.head().unwrap(), pins, []);
    let server4 = Arc::new(EnrollServer::new(keys4, info4, delegation4));
    server4.publish_epoch(vec![
        SignedEpoch::issue(old, first).unwrap(),
        SignedEpoch::issue(new, &forked).unwrap(),
    ]);
    serve_as("ipa1.example.test", app(server4, Dir::default()));
    let check = flows::check(paths, None).unwrap();
    assert_eq!(check["servers"][0]["ok"], false);
    assert!(
        check["servers"][0]["error"]
            .as_str()
            .unwrap()
            .contains("the two have forked"),
        "{}",
        check["servers"][0]["error"]
    );
}

#[test]
fn anchor_watermark_refuses_frozen_and_forking_logs() {
    // One pinned anchor only: §4.4's quorum needs two of them, §4.8's
    // watermark works with one.
    let (old, new, alien) = (
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
    );
    let (old_pin, new_pin, alien_pin) = (
        *old.public().thumbprint(),
        *new.public().thumbprint(),
        *alien.public().thumbprint(),
    );
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());

    // The realm on `old`, its anchor log just started.
    let (keys, info, delegation) = server_keys(&old, "ipa1.example.test");
    let server = Arc::new(EnrollServer::new(keys, info, delegation));
    let first = AnchorEpoch::new(REALM, 1, kuipa_enroll::epoch::GENESIS, [old_pin], []);
    let head1 = first.head().unwrap();
    let first_signed = SignedEpoch::issue(&old, &first).unwrap();
    server.publish_epoch(vec![first_signed.clone()]);
    serve_as("ipa1.example.test", app(server, dir));

    // The enrollment seals the log head, and the host stores it beside
    // its pin.
    let paths = root("frozen");
    let mut s = string(&old, b"Secret123");
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&"ipa1.example.test".to_string())),
    )
    .unwrap();
    assert_eq!(
        kuipa_tools::paths::read_epoch_from(&paths.anchors()).unwrap(),
        Some((1, head1)),
        "the sealed head is stored as the watermark"
    );

    // The anchor rotates properly: entry 2 names the new anchor, lists
    // the succession, and `check` follows the log and moves the
    // watermark.
    let (keys2, info2, mut delegation2) = server_keys(&new, "ipa1.example.test");
    let succession = kuipa_enroll::delegation::SignedSuccession::issue(
        &old,
        REALM,
        &new_pin,
        now() - 60,
        now() + 86400,
    )
    .unwrap();
    delegation2.add_successions([succession.clone()]);
    let second = AnchorEpoch::new(REALM, 2, head1, [new_pin], [succession.clone()]);
    let head2 = second.head().unwrap();
    let server2 = Arc::new(EnrollServer::new(keys2, info2, delegation2));
    server2.publish_epoch(vec![
        first_signed.clone(),
        SignedEpoch::issue(&new, &second).unwrap(),
    ]);
    serve_as("ipa1.example.test", app(server2, Dir::default()));
    let check = flows::check(&paths, None).unwrap();
    assert_eq!(check["servers"][0]["ok"], true, "{check}");
    assert_eq!(
        kuipa_tools::paths::read_epoch_from(&paths.anchors()).unwrap(),
        Some((2, head2)),
        "the watermark caught up with the verified log"
    );

    // A server left behind on the old anchor and the old log: with one
    // pinned anchor this is exactly what a stolen anchor looks like.
    let (keys3, info3, delegation3) = server_keys(&old, "ipa1.example.test");
    let server3 = Arc::new(EnrollServer::new(keys3, info3, delegation3));
    server3.publish_epoch(vec![first_signed]);
    serve_as("ipa1.example.test", app(server3, Dir::default()));
    let check = flows::check(&paths, None).unwrap();
    assert_eq!(check["servers"][0]["ok"], false);
    let error = check["servers"][0]["error"].as_str().unwrap();
    assert!(
        error.contains("stops at sequence 1, behind the 2"),
        "{error}"
    );
    assert_eq!(
        kuipa_tools::paths::read_epoch_from(&paths.anchors()).unwrap(),
        Some((2, head2)),
        "a refused server does not move the watermark"
    );

    served_fork_is_refused(&old, &new, &first, [new_pin, alien_pin], succession, &paths);
}
#[test]
fn a_long_anchor_log_is_read_page_by_page() {
    // A server answers the anchor log a page at most (§4.8); a log
    // longer than a page must still carry the watermark to the
    // advertised head.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (keys, info, delegation) = server_keys(&anchor, "ipa1.example.test");
    let server = Arc::new(EnrollServer::new(keys, info, delegation));
    let first = AnchorEpoch::new(REALM, 1, kuipa_enroll::epoch::GENESIS, [pin], []);
    let mut head = first.head().unwrap();
    let mut log = vec![SignedEpoch::issue(&anchor, &first).unwrap()];
    server.publish_epoch(log.clone());
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    serve_as("ipa1.example.test", app(server, dir));
    let paths = root("paging");
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&"ipa1.example.test".to_string())),
    )
    .unwrap();

    // Past one page: every entry names the same anchor, so nothing but
    // the length forces the client to keep fetching.
    let target = kuipa_enroll::epoch::MAX_EPOCH_FETCH + 2;
    while log.len() < target {
        let entry = AnchorEpoch::new(REALM, log.len() as u64 + 1, head, [pin], []);
        head = entry.head().unwrap();
        log.push(SignedEpoch::issue(&anchor, &entry).unwrap());
    }
    let (keys2, info2, delegation2) = server_keys(&anchor, "ipa1.example.test");
    let server2 = Arc::new(EnrollServer::new(keys2, info2, delegation2));
    server2.publish_epoch(log.clone());
    serve_as("ipa1.example.test", app(server2, Dir::default()));
    let check = flows::check(&paths, None).unwrap();
    assert_eq!(check["servers"][0]["ok"], true, "{check}");
    assert_eq!(
        kuipa_tools::paths::read_epoch_from(&paths.anchors()).unwrap(),
        Some((target as u64, head)),
        "the watermark followed every page of the log"
    );
}

/// The index entry of `key` in an advertisement's `anchors` index.
fn index_entry(out: &serde_json::Value, key: &str) -> serde_json::Value {
    out["anchors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key"] == key)
        .unwrap_or_else(|| panic!("no index entry for {key}: {out}"))
        .clone()
}

/// The index names every key the server named, with no log entries to
/// claim: one per thumbprint, whatever the order the details came in.
fn index_names_each_key(
    out: &serde_json::Value,
    old_pin: tang_pqc::Thumbprint,
    other_pin: tang_pqc::Thumbprint,
) {
    // The index names every key this server named, with no log entries to
    // claim: one per thumbprint, whatever the order the details came in.
    let old_pin_text = old_pin.to_string();
    let other_pin_text = other_pin.to_string();
    assert_eq!(out["pinned"], serde_json::json!([old_pin_text]));
    let roles = index_entry(out, &old_pin_text);
    assert_eq!(roles["pinned"], true);
    assert_eq!(roles["proves"], serde_json::json!(["ipa1.example.test"]));
    assert_eq!(
        roles["current_of"],
        serde_json::json!(["ipa1.example.test"])
    );
    assert_eq!(roles["log_sequences"], serde_json::json!([]), "no log yet");
    let signer = out["servers"][0]["signer"].as_str().unwrap();
    assert_eq!(
        index_entry(out, signer)["signer_of"],
        serde_json::json!(["ipa1.example.test"]),
        "the signing key signs, but is no anchor here",
    );
    let roles = index_entry(out, &other_pin_text);
    assert_eq!(roles["trust_of"], serde_json::json!(["B.TEST"]));
    assert_eq!(
        roles["current_of"],
        serde_json::json!([]),
        "a trusted realm's anchor is not this realm's"
    );
}

/// After the rotation, the index reads both anchors the other way round.
fn rotated_index_entries(
    out: &serde_json::Value,
    old_pin_text: &str,
    new_pin: tang_pqc::Thumbprint,
) {
    // Read the other way round.  Verification accepted the succession, so
    // the accepted proof is the anchor it reached (§4.2): the new anchor
    // proves the claim, the pinned one is only its predecessor.
    let old_roles = index_entry(out, old_pin_text);
    assert_eq!(old_roles["pinned"], true);
    assert_eq!(
        old_roles["proves"],
        serde_json::json!([]),
        "its own proof no longer covers this advertisement"
    );
    assert_eq!(
        old_roles["current_of"],
        serde_json::json!([]),
        "no advertisement names it as an anchor any more"
    );
    assert_eq!(
        old_roles["log_sequences"],
        serde_json::json!([1]),
        "current in the log up to the entry that rotated it"
    );
    assert_eq!(
        old_roles["replaced_by"],
        serde_json::json!([new_pin.to_string()]),
        "the old side of the succession"
    );
    let new_roles = index_entry(out, &new_pin.to_string());
    assert_eq!(
        new_roles["pinned"], false,
        "this host pins only the old one"
    );
    assert_eq!(
        new_roles["proves"],
        serde_json::json!(["ipa1.example.test"]),
        "the reached anchor is the accepted proof"
    );
    assert_eq!(
        new_roles["current_of"],
        serde_json::json!(["ipa1.example.test"])
    );
    assert_eq!(new_roles["log_sequences"], serde_json::json!([2]));
    assert_eq!(
        new_roles["replaces"],
        serde_json::json!([old_pin_text]),
        "the new side of the succession"
    );
}

/// The anchor rotates properly: the log is published through entry 2, and
/// the index reads both anchors.
fn rotation_publishes_the_log(
    old: &SigningKey,
    new: &SigningKey,
    old_pin: tang_pqc::Thumbprint,
    new_pin: tang_pqc::Thumbprint,
    deployment: &Deployment,
) {
    // The anchor rotates properly; the log is published through entry 2.
    let first = AnchorEpoch::new(REALM, 1, kuipa_enroll::epoch::GENESIS, [old_pin], []);
    let head1 = first.head().unwrap();
    let first_signed = SignedEpoch::issue(old, &first).unwrap();
    let (keys2, info2, mut delegation2) = server_keys(new, "ipa1.example.test");
    let succession = kuipa_enroll::delegation::SignedSuccession::issue(
        old,
        REALM,
        &new_pin,
        now() - 60,
        now() + 86400,
    )
    .unwrap();
    delegation2.add_successions([succession.clone()]);
    let second = AnchorEpoch::new(REALM, 2, head1, [new_pin], [succession]);
    let head2 = second.head().unwrap();
    let server2 = Arc::new(EnrollServer::new(keys2, info2, delegation2));
    server2.publish_epoch(vec![
        first_signed,
        SignedEpoch::issue(new, &second).unwrap(),
    ]);
    serve_as("ipa1.example.test", app(server2, Dir::default()));
    let out = flows::advertisements(REALM, &[old_pin], &[], deployment);
    assert_eq!(out["ok"], true, "{out}");
    let adv = &out["servers"][0];
    assert_eq!(
        adv["anchor_log_head"],
        format!("2 {}", tang_pqc::b64::encode(&head2)),
        "the head the advertisement names"
    );
    assert_eq!(
        adv["rotated_anchors"].as_array().unwrap().len(),
        1,
        "verification ran through the succession: {adv}"
    );
    let landmarks = adv["landmarks"].as_array().unwrap();
    assert_eq!(landmarks.len(), 2, "{adv}");
    let thp = |h: kuipa_enroll::epoch::EpochHead| tang_pqc::b64::encode(&h);
    assert_eq!(landmarks[0]["seq"], 1);
    assert_eq!(
        landmarks[0]["prev"],
        thp([0; 48]),
        "the first entry commits to nothing"
    );
    assert_eq!(
        landmarks[1]["prev"],
        thp(head1),
        "committed to the landmark before it"
    );
    assert_eq!(landmarks[1]["head"], thp(head2), "each landmark's head");
    assert_eq!(
        landmarks[1]["successions"][0],
        format!("{old_pin} -> {new_pin}"),
        "the rotation the entry records"
    );
    rotated_index_entries(&out, &old_pin.to_string(), new_pin);
}

#[test]
fn advertisement_lists_details_landmarks_and_an_anchor_index() {
    // A realm with no anchor log yet: the advertisement carries no head,
    // so there are no landmarks, but its details still show. Then the
    // same realm through a proper rotation: the whole landmark chain is
    // listed and verified from the one pinned anchor (§4.8), and the
    // per-key index says where each key belongs.
    let (old, new) = (
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
        SigningKey::generate(SignatureAlg::MlDsa65).unwrap(),
    );
    let (old_pin, new_pin) = (*old.public().thumbprint(), *new.public().thumbprint());
    let deployment = Deployment::servers(&["ipa1.example.test".to_string()]);
    let (keys, mut info, delegation) = server_keys(&old, "ipa1.example.test");
    // A realm this one trusts, with an anchor of its own (§17): the index
    // is where a reader finds out what such an anchor is.
    let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let other_pin = *other.public().thumbprint();
    info.trusts = vec![kuipa_enroll::realm::TrustedRealm {
        realm: "B.TEST".into(),
        domain: "b.test".into(),
        servers: vec!["ipa1.b.test".into()],
        anchors: vec![other_pin],
        heads: Vec::new(),
    }];
    info.validate().unwrap();
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    serve_as(
        "ipa1.example.test",
        app(
            Arc::new(EnrollServer::new(keys, info, delegation.clone())),
            dir,
        ),
    );
    let paths = root("advert");
    let mut s = string(&old, b"Secret123");
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &deployment,
    )
    .unwrap();
    let out = flows::advertisements(REALM, &[old_pin], &[], &deployment);
    assert_eq!(out["ok"], true, "{out}");
    assert_eq!(out["servers"][0]["realm"], REALM);
    assert_eq!(out["servers"][0]["anchor_log_head"], "", "no log, no head");
    assert!(
        out["servers"][0]["landmarks"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "{out}"
    );
    index_names_each_key(&out, old_pin, other_pin);
    rotation_publishes_the_log(&old, &new, old_pin, new_pin, &deployment);
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
        heads: vec![None],
        epoch_seq: 0,
        epoch_head: [0; 48],
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
/// Stage the OTP at the directory and name it as an LDAP-OTP authentication.
fn ldap_otp_auth(app: &App<Dir>) -> Auth {
    app.directory
        .otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    Auth::LdapOtp(Secret::new(b"Secret123"))
}

/// Without an enrollment string, the realm's anchor pre-provisioned is enough
/// for both steps, and a second unrelated anchor changes what the host requires.
fn ldap_bootstrap_checks(anchor: &SigningKey, paths: &TempRoot, url: String, app: &App<Dir>) {
    let dir = paths.dir.join("krb5");
    // No enrollment string: the realm's anchor pre-provisioned in
    // /etc/ipa/ku-anchors (an image) is enough for both steps.
    let stranger = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    kuipa_tools::paths::write_anchors(paths, &[*anchor.public().thumbprint()]).unwrap();
    let pinned = kuipa_tools::paths::read_anchors(paths).unwrap();
    flows::realm_info(
        REALM,
        &pinned,
        &[],
        &Deployment::servers(std::slice::from_ref(&url)),
        &dir,
    )
    .unwrap();
    flows::enroll_online(
        paths,
        REALM,
        &pinned,
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &ldap_otp_auth(app),
        },
        &Deployment::servers(std::slice::from_ref(&url)),
    )
    .unwrap();
    // Pinning a second, unrelated anchor changes what the host requires:
    // with two anchors known, the claim must be proven by two distinct
    // ones (§4.4), which this one-anchor realm cannot do.
    let err = flows::enroll_online(
        &root("ldap-otp-two-pins"),
        REALM,
        &[
            *stranger.public().thumbprint(),
            *anchor.public().thumbprint(),
        ],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &ldap_otp_auth(app),
        },
        &Deployment::servers(std::slice::from_ref(&url)),
    )
    .unwrap_err();
    assert!(err.to_string().contains("proven by 1 of the 2"), "{err}");
    // Only the unrelated anchor pinned: no server verifies.
    let err = flows::enroll_online(
        &root("ldap-otp-stranger"),
        REALM,
        &[*stranger.public().thumbprint()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &ldap_otp_auth(app),
        },
        &Deployment::servers(&[url]),
    )
    .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::RetryLater(_))),
        "{err}"
    );
}

#[test]
fn ldap_otp_enrollment_and_kerberos_bootstrap() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, info, delegation) = server_keys(&anchor, "ipa1.example.test");
    let app = app(
        Arc::new(EnrollServer::new(keys, info, delegation)),
        Dir::default(),
    );
    let url = serve_as("ipa1.example.test", app.clone());
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
        &[],
        &Deployment::servers(std::slice::from_ref(&url)),
        &dir,
    )
    .unwrap();
    assert_eq!(info["server"], "ipa1.example.test");
    let conf = std::fs::read_to_string(dir.join("krb5.conf")).unwrap();
    assert!(conf.contains("kdc = ipa1.example.test:88"));
    // ipa2 is advertised too, but the client was told to use ipa1 only.
    assert!(!conf.contains("ipa2"), "{conf}");
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
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(Secret::new(b"guess")),
        },
        &Deployment::servers(std::slice::from_ref(&url)),
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
            &[],
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &ldap_otp_auth(&app),
            },
            &Deployment::servers(std::slice::from_ref(&url)),
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

    ldap_bootstrap_checks(&anchor, &paths, url, &app);
}

/// A host that knows two of a realm's anchors requires the claim to be
/// proven by two distinct ones (§4.4). An imposter holding a copy of one
/// stolen anchor key is refused when two are pinned and taken for the
/// realm when one is: the second known anchor is what makes the theft
/// visible.
#[test]
fn stolen_anchor_refused_when_two_anchors_pinned() {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pins = [*anchor.public().thumbprint(), *other.public().thumbprint()];

    // ipa1: the real server. Its claim is vouched by both anchors, as
    // it is in a realm whose anchors exchanged (§4.3).
    let (keys, info, mut delegation) = server_keys(&anchor, "ipa1.example.test");
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &other,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, other.public()).unwrap());
    let ipa1_app = app(
        Arc::new(EnrollServer::new(keys, info, delegation)),
        Dir::default(),
    );
    let ipa1 = serve_as("ipa1.example.test", ipa1_app.clone());
    ipa1_app
        .directory
        .otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());

    // The thief: holds a copy of the real anchor's key, everything else
    // its own; only that one anchor vouches for it.
    let (keys, mut info, delegation) = server_keys(&anchor, "thief.example.test");
    info.servers.push("thief.example.test".into());
    let thief_app = app(
        Arc::new(EnrollServer::new(keys, info, delegation)),
        Dir::default(),
    );
    let thief = serve_as("thief.example.test", thief_app.clone());

    // Two anchors pinned: the thief is skipped before any secret leaves
    // the host, and the real server serves the join.
    let paths = root("stolen-anchor");
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &paths,
            REALM,
            &pins,
            &[],
            &[],
            flows::Host {
                fqdn: HOST,
                auth: &Auth::LdapOtp(Secret::new(b"Secret123")),
            },
            &Deployment::servers(&[thief.clone(), ipa1.clone()]),
        )
    });
    let result = result.unwrap();
    assert_eq!(result["issuer"], "ipa1.example.test");
    for step in [
        "skipped, trying the next server: its claim is proven by 1 of the 2",
        "claim also proven by pinned anchor",
        "advertisement verified: ipa1.example.test",
    ] {
        assert!(trace.contains(step), "{step:?} missing from:\n{trace}");
    }

    // The thief alone: no usable server, and the reason names why.
    let err = flows::enroll_online(
        &root("stolen-anchor-alone"),
        REALM,
        &pins,
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(Secret::new(b"Secret123")),
        },
        &Deployment::servers(std::slice::from_ref(&thief)),
    )
    .unwrap_err();
    assert!(
        matches!(err.downcast_ref::<Outcome>(), Some(Outcome::RetryLater(_))),
        "{err}"
    );
    assert!(err.to_string().contains("proven by 1 of the 2"), "{err}");

    // One anchor pinned: the thief passes for the realm and serves the
    // join — the residual §4.4 documents.
    thief_app
        .directory
        .otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let result = flows::enroll_online(
        &root("stolen-anchor-one-pin"),
        REALM,
        &pins[..1],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(Secret::new(b"Secret123")),
        },
        &Deployment::servers(&[thief]),
    )
    .unwrap();
    assert_eq!(result["issuer"], "thief.example.test");
}

/// The daemon as a post-quantum Tang server (DESIGN §11.5), driven over
/// HTTP with `tang-pqc`'s client as a Clevis pin would: provision against
/// the pinned thumbprint, recover, rotate, and recover the old binding and
/// verify the new keys with the old pin through `adv/{thp}`.
/// Serve an IPA server whose Tang keys are `keys`; returns its URL.
fn serve_tang(keys: &kuipad::tang::TangKeys) -> String {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (server_keys, info, delegation) = server_keys(&anchor, "ipa1.example.test");
    spawn(Arc::new(App {
        server: Arc::new(EnrollServer::new(server_keys, info, delegation)),
        directory: Dir::default(),
        peers: None,
        limiter: Limiter::default(),
        tang: keys.server().unwrap().map(Arc::new),
        keys: None,
        ledger: None,
    }))
}

/// The signed advertisement at `path` under Tang's `url`.
fn tang_adv(
    http: &reqwest::blocking::Client,
    url: &str,
    path: &str,
) -> tang_pqc::SignedAdvertisement {
    let r = http
        .get(format!("{url}/ipa/ku/tang/{path}"))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200, "{path}");
    assert_eq!(r.headers()["content-type"], "application/jose+json");
    tang_pqc::SignedAdvertisement::from_json(&r.bytes().unwrap()).unwrap()
}

/// The exchange key `kid` of Tang at `url`.
fn tang_exchange_key(
    http: &reqwest::blocking::Client,
    url: &str,
    kid: &tang_pqc::Thumbprint,
) -> tang_pqc::ExchangeKey {
    let r = http
        .get(format!("{url}/ipa/ku/tang/key/{kid}"))
        .send()
        .unwrap();
    assert_eq!(r.status(), 200, "key/{kid}");
    assert_eq!(r.headers()["content-type"], "application/jwk+json");
    tang_pqc::ExchangeKey::from_jwk_json(&r.bytes().unwrap()).unwrap()
}

/// Recover the key of `binding` from Tang at `url`.
fn tang_recover(
    http: &reqwest::blocking::Client,
    url: &str,
    binding: &tang_pqc::Binding,
) -> tang_pqc::Key {
    let ek = tang_exchange_key(http, url, binding.kid());
    let (request, pending) = binding.recovery_request(&ek).unwrap();
    let r = http
        .post(format!("{url}/ipa/ku/tang/rec/{}", request.kid()))
        .body(request.to_bytes())
        .send()
        .unwrap();
    assert_eq!(r.status(), 200);
    let response = tang_pqc::RecoveryResponse::from_bytes(&r.bytes().unwrap()).unwrap();
    pending.finish(&response).unwrap()
}

/// The clevis configuration pinning Tang at `url` with the key `thp`.
fn tang_pin(url: &str, thp: &tang_pqc::Thumbprint) -> tang_pqc_clevis::Config {
    tang_pqc_clevis::Config {
        url: format!("{url}/ipa/ku/tang"),
        thp: Some(thp.to_string()),
        adv: None,
        ca: None,
    }
}

#[test]
fn post_quantum_tang_over_http() {
    let root = root("tang");
    let keys = kuipad::tang::TangKeys::new(&root.dir.join("keys"));
    let old = keys.generate().unwrap();
    let _ = rustls_native_ossl::default_provider().install_default();
    let http = reqwest::blocking::Client::new();

    // ── clevis encrypt, then unlock ──
    let url = serve_tang(&keys);
    let jwe = tang_pqc_clevis::encrypt(&tang_pin(&url, &old), b"passphrase").unwrap();
    assert_eq!(
        tang_pqc_clevis::decrypt(&jwe).unwrap().as_ref(),
        b"passphrase"
    );
    let (binding, key) = tang_adv(&http, &url, "adv")
        .verify(&old)
        .unwrap()
        .provision(None)
        .unwrap();
    let binding = tang_pqc::Binding::from_bytes(&binding.to_bytes()).unwrap();
    assert_eq!(tang_recover(&http, &url, &binding).as_ref(), key.as_ref());
    // The enrollment advertisement is separate and offers no Tang key.
    let ipa = http.get(format!("{url}/ipa/ku/adv")).send().unwrap();
    assert!(!ipa.text().unwrap().contains(&old.to_string()));

    // ── Errors as Tang has them ──
    let (request, _) = binding
        .recovery_request(&tang_exchange_key(&http, &url, binding.kid()))
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
    let url = serve_tang(&keys);
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
    let regen = tang_pqc_clevis::encrypt(&tang_pin(&url, &old), b"passphrase").unwrap();
    assert_eq!(
        tang_pqc_clevis::decrypt(&regen).unwrap().as_ref(),
        b"passphrase"
    );
    assert_eq!(tang_recover(&http, &url, &binding).as_ref(), key.as_ref());
    assert!(tang_adv(&http, &url, "adv").verify(&old).is_err());
    let countersigned = tang_adv(&http, &url, &format!("adv/{old}"));
    let (rebound, rekey) = countersigned.verify(&old).unwrap().provision(None).unwrap();
    assert_eq!(rebound.to_bytes().len(), binding.to_bytes().len());
    assert!(countersigned.verify(&new).is_ok());
    assert_eq!(
        tang_recover(
            &http,
            &url,
            &tang_pqc::Binding::from_bytes(&rebound.to_bytes()).unwrap()
        )
        .as_ref(),
        rekey.as_ref()
    );

    // ── Without Tang keys there is no Tang ──
    let none = kuipad::tang::TangKeys::new(&root.dir.join("empty"));
    let url = serve_tang(&none);
    let r = http.get(format!("{url}/ipa/ku/tang/adv")).send().unwrap();
    assert_eq!(r.status(), 404);
}

/// Realm A's trust of B, with B's heads, once A's server is up.
struct TrustHeads {
    anchor: SigningKey,
    b_head: (u64, kuipa_enroll::merkle::Hash),
    b_pin: tang_pqc::Thumbprint,
    b_server: Arc<EnrollServer>,
    deployment: Deployment,
    dir: Dir,
    info: RealmInfo,
    paths: TempRoot,
    vouches: std::collections::HashMap<tang_pqc::Thumbprint, kuipa_enroll::delegation::SignedVouch>,
    keys: kuipa_enroll::realm::ServerKeys,
    delegation: kuipa_enroll::delegation::Delegation,
}

/// Realm A's trust of B, with B's heads, once A's server is up.
fn trust_heads_tail(state: TrustHeads) {
    let TrustHeads {
        anchor,
        b_head,
        b_pin,
        b_server,
        deployment,
        dir,
        info,
        paths,
        vouches,
        keys,
        delegation,
    } = state;
    // What A's kuipad refresh would publish: B as a partner, with the
    // heads B's advertisement carries for its anchors.
    let partner = kuipa_enroll::realm::TrustedRealm {
        realm: "B.TEST".into(),
        domain: "b.test".into(),
        servers: vec!["trustB1.example.test".into()],
        anchors: vec![b_pin],
        heads: b_server.heads(),
    };
    // A, advertising the trust: B's entry with its heads, as kuipad's
    // refresh would publish it.
    let mut info = info;
    info.trusts = vec![partner];
    info.validate().unwrap();
    let mut published_vouches = std::collections::HashMap::new();
    published_vouches.extend(vouches);
    let a = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
    a.publish(
        delegation,
        vec![*anchor.public().thumbprint()],
        published_vouches,
    );
    serve_as("trustA1.example.test", app(a.clone(), dir));

    // Enroll a host of A: trusted_realms works on an enrolled host's
    // state, and the enrollment pins A's head too.
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &deployment,
    )
    .unwrap();

    // Install B: the anchors file carries B's heads beside its
    // thumbprints.
    let result = flows::trusted_realms(&paths).unwrap();
    assert_eq!(
        result["trusted_realms"][0]["status"], "installed",
        "{result}"
    );
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.trust_anchors("B.TEST")).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].anchor, b_pin);
    assert_eq!(pins[0].heads, vec![b_head], "B's head is pinned");

    // B's next refresh verifies through the pinned head with no
    // signature served: ask B's advertisement with the head and check
    // the delegation carries a head proof only.
    let (result, trace) = traced(|| flows::trusted_realms(&paths));
    let result = result.unwrap();
    assert_eq!(
        result["trusted_realms"][0]["status"], "refreshed",
        "{result}"
    );
    assert_eq!(result["trusted_realms"][0]["heads"], 1, "{result}");
    assert!(
        trace.contains("claim also proven") || trace.contains("advertisement verified"),
        "{trace}"
    );
    let endpoint = kuipa_tools::net::Endpoint::new(
        &serve_as(
            "trustB1.example.test",
            app(b_server.clone(), Dir::default()),
        ),
        &kuipa_tools::net::Trust::FirstContact,
    )
    .expect("endpoint");
    let adv = endpoint
        .advertisement_with_heads(
            &[b_pin],
            &[kuipa_enroll::delegation::HeadPin {
                anchor: b_pin,
                size: b_head.0,
                root: b_head.1,
            }],
        )
        .unwrap();
    let body = adv
        .unverified_member("delegation")
        .expect("delegation member")
        .expect("present")
        .to_string();
    assert!(body.contains("head_proofs"), "no head proof in:\n{body}");
    assert!(
        !body.contains("signatures"),
        "a signature proof was served to a head-pinned client:\n{body}"
    );
    kuipa_tools::net::clear_thread_endpoints();
}

#[test]
fn trusted_realms_pins_and_uses_the_partners_heads() {
    // A realm A that trusts realm B: B's server publishes vouches, so
    // A's trusts entry — taken from B's verified advertisement, as
    // kuipad's refresh fills it — carries B's anchors with their heads
    // (DESIGN-claim-logs.md §3).  A host of A installs them, and B's
    // next refresh verifies with no signature served.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, _, mut delegation) = server_keys(&anchor, "trustA1.example.test");
    let info = trust_info_of(&anchor);
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(*anchor.public().thumbprint(), vouch);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let paths = root("trust-heads");
    let deployment = Deployment::servers(&["trustA1.example.test".to_owned()]);

    // B: its own anchor, vouching for its own claim, so its
    // advertisement carries a head.
    let b = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let b_pin = *b.public().thumbprint();
    let b_signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let mut b_delegation = Delegation::issue(
        &b,
        "B.TEST",
        "trustB1.example.test",
        b_signing.public(),
        now() - 60,
        now() + 86400,
    )
    .unwrap();
    let b_keys = ServerKeys {
        signing: b_signing,
        join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        trust: Vec::new(),
        vouchers: Vec::new(),
        retired: Vec::new(),
    };
    let b_info = RealmInfo {
        realm: "B.TEST".into(),
        domain: "b.test".into(),
        basedn: "dc=b,dc=test".into(),
        server: "trustB1.example.test".into(),
        servers: vec!["trustB1.example.test".into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![b_pin],
        heads: Vec::new(),
        trusts: Vec::new(),
    };
    let b_claim = b_delegation.claim().unwrap();
    let b_vouch = SignedVouch::issue(
        &b,
        "B.TEST",
        [b_claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let b_head = b_vouch.head();
    b_delegation.add(b_vouch.proof(&b_claim, b.public()).unwrap());
    let mut b_vouches = std::collections::HashMap::new();
    b_vouches.insert(b_pin, b_vouch);
    let b_server = Arc::new(EnrollServer::new(b_keys, b_info, b_delegation.clone()));
    b_server.publish(b_delegation, vec![b_pin], b_vouches);
    serve_as(
        "trustB1.example.test",
        app(b_server.clone(), Dir::default()),
    );

    trust_heads_tail(TrustHeads {
        anchor,
        b_head,
        b_pin,
        b_server,
        deployment,
        dir,
        info,
        paths,
        vouches,
        keys,
        delegation,
    });
}

/// A's realm info for the trust test: this one server, so the
/// advertisement lists what the deployment names.
fn trust_info_of(anchor: &SigningKey) -> RealmInfo {
    RealmInfo {
        realm: REALM.into(),
        domain: "example.test".into(),
        basedn: "dc=example,dc=test".into(),
        server: "trustA1.example.test".into(),
        servers: vec!["trustA1.example.test".into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
    }
}

/// The running mirror and what the origin served it.
struct MirrorRun {
    http: reqwest::blocking::Client,
    mirror: std::process::Child,
    data: std::path::PathBuf,
    head: (u64, kuipa_enroll::merkle::Hash),
    adv_json: serde_json::Value,
    pin: tang_pqc::Thumbprint,
    base: String,
}

/// The running mirror and what the origin served it.
fn mirror_run_tail(state: MirrorRun) {
    let MirrorRun {
        http,
        mut mirror,
        data,
        head,
        adv_json,
        pin,
        base,
    } = state;
    // A head query: uncached, the plain advertisement (the fallback);
    // after a sync, the origin's head-proof answer, cached.
    let root = tang_pqc::b64::encode(&head.1);
    let query = format!("anchor={pin}&head={pin}.{}.{root}", head.0);
    let first: serde_json::Value = serde_json::from_slice(
        &http
            .get(format!("{base}/adv?{query}"))
            .send()
            .unwrap()
            .bytes()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first, adv_json, "the fallback is the plain advertisement");
    let mut head_answer = None;
    for _ in 0..100 {
        let r: serde_json::Value = serde_json::from_slice(
            &http
                .get(format!("{base}/adv?{query}"))
                .send()
                .unwrap()
                .bytes()
                .unwrap(),
        )
        .unwrap();
        if r != adv_json {
            head_answer = Some(r);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let head_answer = head_answer.unwrap_or_else(|| {
        panic!(
            "the mirror cached no head-proof answer; its log:\n{}",
            std::fs::read_to_string(data.with_extension("log")).unwrap_or_default()
        )
    });
    // The head-proof answer is a JWS: the delegation member, decoded,
    // carries a head proof and no signature.
    let signed =
        tang_pqc::SignedAdvertisement::from_json(head_answer.to_string().as_bytes()).unwrap();
    let body = signed
        .unverified_member("delegation")
        .expect("delegation member")
        .expect("present")
        .to_string();
    assert!(body.contains("head_proofs"), "no head proof in:\n{body}");
    assert!(
        !body.contains("signatures"),
        "no signature served to a head-pinned client:\n{body}"
    );

    // A join has no route: a mirror is not a server.
    let r = http
        .post(format!("{base}/join/whatever"))
        .body("{}")
        .send()
        .unwrap();
    assert_eq!(r.status(), 404, "no authenticated route on a mirror");

    mirror.kill().unwrap();
    mirror.wait().unwrap();
    let _ = std::fs::remove_dir_all(&data);
    kuipa_tools::net::clear_thread_endpoints();
}

#[test]
fn a_mirror_serves_what_it_cached_and_no_authenticated_route() {
    // DESIGN-claim-logs.md §6: the mirror syncs the origin's public
    // endpoints and re-serves them read-only.  A head query it has
    // cached is answered with the origin's head-proof advertisement;
    // an unseen one falls back to the plain advertisement (the
    // client's stale-head fallback); a join has no route at all.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (keys, _, mut delegation) = server_keys(&anchor, "mirror1.example.test");
    let info = mirror_info_of(&anchor);
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let head = vouch.head();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, vouch);
    let server = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
    server.publish(delegation, vec![pin], vouches);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let origin = spawn(app(server, dir));

    // Run the mirror binary against the origin, on a free port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let data = std::env::temp_dir().join(format!("kuipa-mirror-test-{port}"));
    let _ = std::fs::remove_dir_all(&data);
    let mirror = std::process::Command::new(env!("CARGO_BIN_EXE_kuipa-mirror"))
        .arg("--origin")
        .arg(&origin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--data")
        .arg(&data)
        .arg("--interval")
        .arg("1")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(data.with_extension("log")).unwrap())
        .spawn()
        .expect("the mirror binary");
    let base = format!("http://127.0.0.1:{port}/ipa/ku");
    let _ = rustls_native_ossl::default_provider().install_default();
    let http = reqwest::blocking::Client::new();
    let mut adv = None;
    for _ in 0..100 {
        if let Ok(r) = http.get(format!("{base}/adv")).send()
            && r.status() == 200
        {
            adv = Some(r.bytes().unwrap().to_vec());
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let adv = adv.expect("the mirror served the advertisement");
    let adv_json: serde_json::Value = serde_json::from_slice(&adv).unwrap();

    // The claim log, with its vouch, and the anchor log with heads.
    let page: serde_json::Value = serde_json::from_slice(
        &http
            .get(format!("{base}/claim-log/{pin}"))
            .send()
            .unwrap()
            .bytes()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(page["size"], head.0, "{page}");
    assert!(page["vouch"].is_string(), "the vouch is served: {page}");
    let log: serde_json::Value = serde_json::from_slice(
        &http
            .get(format!("{base}/anchor-log"))
            .send()
            .unwrap()
            .bytes()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(log["heads"].as_array().map_or(0, Vec::len), 1, "{log}");

    mirror_run_tail(MirrorRun {
        http,
        mirror,
        data,
        head,
        adv_json,
        pin,
        base,
    });
}

/// The realm info for the mirror test's single server.
fn mirror_info_of(anchor: &SigningKey) -> RealmInfo {
    RealmInfo {
        realm: REALM.into(),
        domain: "example.test".into(),
        basedn: "dc=example,dc=test".into(),
        server: "mirror1.example.test".into(),
        servers: vec!["mirror1.example.test".into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
    }
}

/// A frozen pin's head, and the server that answers for it.
struct FrozenHead {
    anchor: SigningKey,
    head: (u64, kuipa_enroll::merkle::Hash),
    url: String,
}

/// A frozen pin's head, and the server that answers for it.
fn frozen_head_tail(state: FrozenHead) {
    let FrozenHead { anchor, head, url } = state;
    // Outside the head: the server serves a signature proof (the head
    // is stale for a renewed claim), and the frozen pin refuses it by
    // name — while an unfrozen client would accept it.
    let renewed = {
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let mut d = Delegation::issue(
            &anchor,
            REALM,
            "frozen1.example.test",
            signing.public(),
            now(),
            now() + 86400,
        )
        .unwrap();
        // A vouch whose log does not contain the old pinned prefix:
        // the claim leaf is different, so the pinned head cannot prove
        // it.
        let c = d.claim().unwrap();
        let v = SignedVouch::issue(
            &anchor,
            REALM,
            [c.leaf(S256).unwrap()],
            now(),
            now() + 86_400,
            None,
        )
        .unwrap();
        d.add(v.proof(&c, anchor.public()).unwrap());
        let mut vs = std::collections::HashMap::new();
        vs.insert(*anchor.public().thumbprint(), v);
        let server = Arc::new(EnrollServer::new(
            ServerKeys {
                signing,
                join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
                escrow: Vec::new(),
                trust: Vec::new(),
                vouchers: Vec::new(),
                retired: Vec::new(),
            },
            info_of(&anchor),
            d.clone(),
        ));
        server.publish(d, vec![*anchor.public().thumbprint()], vs);
        let dir = Dir::default();
        dir.otps
            .lock()
            .unwrap()
            .insert(HOST.into(), b"Secret123".to_vec());
        serve_as("frozen1.example.test", app(server, dir));
        url.clone()
    };
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    let err = flows::enroll_online(
        &root("frozen-outside"),
        s.realm(),
        &[*s.anchor()],
        &[kuipa_enroll::delegation::HeadPin {
            anchor: *s.anchor(),
            size: head.0,
            root: head.1,
        }],
        &[*s.anchor()],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&renewed)),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("frozen"),
        "the refusal names the freeze: {err}"
    );

    // The same server, an unfrozen client: the signature fallback
    // takes it.
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &root("frozen-pin-unfrozen"),
        s.realm(),
        &[*s.anchor()],
        &[kuipa_enroll::delegation::HeadPin {
            anchor: *s.anchor(),
            size: head.0,
            root: head.1,
        }],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&renewed)),
    )
    .unwrap();
    kuipa_tools::net::clear_thread_endpoints();
}

#[test]
fn a_frozen_pin_refuses_what_its_head_does_not_prove() {
    // DESIGN-claim-logs.md §2: a frozen pin accepts a head proof only.
    // A client whose pin is frozen enrolls while the head proves the
    // claim, and refuses — naming the freeze — once the claim is
    // outside the pinned tree, where an unfrozen client would fall
    // back to the signature.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, _, mut delegation) = server_keys(&anchor, "frozen1.example.test");
    let info = info_of(&anchor);
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let head = vouch.head();
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(*anchor.public().thumbprint(), vouch);
    let server = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
    server.publish(delegation, vec![*anchor.public().thumbprint()], vouches);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = serve_as("frozen1.example.test", app(server, dir));

    // A frozen pin: the head, and no fallback.
    let paths = root("frozen-pin");
    let pin = kuipa_tools::paths::Pin {
        anchor: *anchor.public().thumbprint(),
        exp: None,
        heads: vec![head],
        frozen: true,
        retired: Vec::new(),
    };
    kuipa_tools::paths::write_anchor_pins(
        &paths.anchors(),
        "frozen",
        std::slice::from_ref(&pin),
        None,
    )
    .unwrap();

    // The claim under the head: enrollment verifies head-wise, the
    // frozen policy satisfied.
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    let result = flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &[kuipa_enroll::delegation::HeadPin {
            anchor: *s.anchor(),
            size: head.0,
            root: head.1,
        }],
        &[*s.anchor()],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&url)),
    );
    let result = result.unwrap();
    assert_eq!(result["issuer"], "frozen1.example.test");

    frozen_head_tail(FrozenHead { anchor, head, url });
}

/// The realm info of `server_keys`, for a second server of the same
/// test realm.
fn info_of(anchor: &SigningKey) -> RealmInfo {
    RealmInfo {
        realm: REALM.into(),
        domain: "example.test".into(),
        basedn: "dc=example,dc=test".into(),
        server: "frozen1.example.test".into(),
        servers: vec!["frozen1.example.test".into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
    }
}

#[test]
fn the_claim_log_carries_the_heads_signed_vouch() {
    // DESIGN-claim-logs.md §4: the public claim-log page carries the
    // signed vouch of the head it answers, so a reader can check the
    // head was signed at all — here against the anchor key the
    // verified advertisement names — and the leaves against it.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (keys, _, mut delegation) = server_keys(&anchor, "claimlog1.example.test");
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let head = vouch.head();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, vouch);
    let server = Arc::new(EnrollServer::new(
        keys,
        claim_log_info_of(&anchor),
        delegation.clone(),
    ));
    server.publish(delegation, vec![pin], vouches);
    let url = spawn(app(server, Dir::default()));
    kuipa_tools::net::set_thread_endpoint("claimlog1.example.test", &url);

    let _ = rustls_native_ossl::default_provider().install_default();
    let http = reqwest::blocking::Client::new();
    let page: serde_json::Value = serde_json::from_slice(
        &http
            .get(format!("{url}/ipa/ku/claim-log/{pin}"))
            .send()
            .unwrap()
            .bytes()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(page["size"], head.0, "{page}");
    assert_eq!(page["leaves"].as_array().map(Vec::len), Some(1), "{page}");
    let page_vouch = kuipa_enroll::delegation::SignedVouch::from_bytes(
        &tang_pqc::b64::decode(page["vouch"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    // The signature checks against the anchor's key — the same key the
    // advertisement's signature proof carries, which the delegation's
    // own verification (against the pinned anchor) already checked.
    page_vouch
        .verify(anchor.public(), &tang_pqc::Policy::default())
        .unwrap();
    // And the page's leaves hash to the vouch's head.
    let leaves: Vec<kuipa_enroll::merkle::Hash> = page["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            let bytes = tang_pqc::b64::decode(l.as_str().unwrap()).unwrap();
            kuipa_enroll::merkle::Hash::from_slice(&bytes).unwrap()
        })
        .collect();
    assert_eq!(
        kuipa_enroll::merkle::root(&leaves).unwrap(),
        page_vouch.vouch().root
    );
    kuipa_tools::net::clear_thread_endpoints();
}

/// The realm info for the claim-log test's single server.
fn claim_log_info_of(anchor: &SigningKey) -> RealmInfo {
    RealmInfo {
        realm: REALM.into(),
        domain: "example.test".into(),
        basedn: "dc=example,dc=test".into(),
        server: "claimlog1.example.test".into(),
        servers: vec!["claimlog1.example.test".into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
    }
}

/// The leaves of `anchor`'s claim log, read page by page up to `size`,
/// and whether all `size` of them were read.
fn served_leaves(
    endpoint: &kuipa_tools::net::Endpoint,
    anchor: &tang_pqc::Thumbprint,
    size: u64,
) -> (Vec<kuipa_enroll::merkle::Hash>, bool) {
    let mut leaves = Vec::new();
    let mut from = 0;
    let complete = loop {
        match endpoint.claim_log(anchor, from) {
            Ok(page) => {
                if page.leaves.is_empty() {
                    break false;
                }
                for leaf in &page.leaves {
                    if let Ok(bytes) = tang_pqc::b64::decode(leaf)
                        && let Ok(h) = kuipa_enroll::merkle::Hash::from_slice(&bytes)
                    {
                        leaves.push(h);
                    }
                }
                from += page.leaves.len() as u64;
                if from >= size {
                    break leaves.len() as u64 == size;
                }
            }
            Err(_) => break false,
        }
    };
    (leaves, complete)
}

/// Merge the heads `offered` for the pinned anchors into the pin file's
/// windows: a head is kept only when the claim log serves the pinned history
/// under it.  Returns the merged windows and whether they restarted.
fn merge_offered(
    endpoint: &kuipa_tools::net::Endpoint,
    paths: &kuipa_tools::paths::Paths,
    offered: &[(
        tang_pqc::Thumbprint,
        Option<(u64, kuipa_enroll::merkle::Hash)>,
    )],
) -> (Vec<kuipa_tools::paths::Pin>, bool) {
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    let mut m = offered.to_vec();
    for (i, (a, new_head)) in offered.iter().enumerate() {
        let Some(p) = pins.iter().find(|p| &p.anchor == a) else {
            continue;
        };
        let Some((size, root)) = new_head else {
            continue;
        };
        let Some(&(newest, old_root)) = p.heads.last() else {
            continue;
        };
        if *size <= newest {
            continue;
        }
        let (leaves, complete) = served_leaves(endpoint, a, *size);
        let prefix = usize::try_from(newest)
            .ok()
            .and_then(|n| leaves.get(..n))
            .and_then(|l| kuipa_enroll::merkle::root(l).ok())
            .is_some_and(|r| r == old_root);
        let consistent =
            complete && prefix && kuipa_enroll::merkle::root(&leaves).is_ok_and(|r| r == *root);
        if !consistent {
            m[i].1 = None;
        }
    }
    kuipa_tools::paths::merge_windows(&pins, &m, &[])
}

/// A head whose pages do not contain the pinned history is not pinned:
/// the window keeps both of its heads.
fn forged_head_is_not_pinned(
    endpoint: &kuipa_tools::net::Endpoint,
    paths: &kuipa_tools::paths::Paths,
    pin: tang_pqc::Thumbprint,
    head1: (u64, kuipa_enroll::merkle::Hash),
    head2: (u64, kuipa_enroll::merkle::Hash),
    head3: (u64, kuipa_enroll::merkle::Hash),
) {
    // The same merge with the forged head: the pages the server now
    // serves do not contain the pinned history, so the head is not
    // pinned and the window keeps both of its heads.
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    let offered = [(pin, Some(head3))];
    let mut m = offered.to_vec();
    m[0].1 = None; // the check below refuses it
    {
        let (leaves, complete) = served_leaves(endpoint, &pin, head3.0);
        let consistent =
            complete && kuipa_enroll::merkle::root(&leaves).is_ok_and(|r| r == head3.1);
        let prefix_ok = usize::try_from(head2.0)
            .ok()
            .and_then(|n| leaves.get(..n))
            .and_then(|l| kuipa_enroll::merkle::root(l).ok())
            .is_some_and(|r| r == head2.1);
        assert!(
            !consistent || !prefix_ok,
            "the forged head skips the pinned history"
        );
    }
    let (merged, _) = kuipa_tools::paths::merge_windows(&pins, &m, &[]);
    assert_eq!(
        merged[0].heads,
        vec![head1, head2],
        "a head that skips the pinned history is not pinned"
    );
}

/// Enroll: the pin file starts with a window of one (the sealed response
/// carries the head).
fn enroll_window_of_one(anchor: &SigningKey, head1: (u64, kuipa_enroll::merkle::Hash)) -> TempRoot {
    // Enroll: the pin file starts with a window of one (the sealed
    // response carries the head).
    let paths = root("window");
    let mut s = string(anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(&["window1.example.test".to_owned()]),
    )
    .unwrap();
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    assert_eq!(pins[0].heads, vec![head1], "the window starts at head1");
    paths
}

#[test]
fn a_window_grows_only_through_a_consistent_log() {
    // DESIGN-claim-logs.md §1.3: a new head extends the window only
    // when the claim log provably contains the pinned history — the
    // pages between the sizes hash to both roots.  A server whose
    // fresh head skips the client's history serves a signature proof
    // instead, and the window keeps the pinned heads.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (keys, _, mut delegation) = server_keys(&anchor, "window1.example.test");
    let info = window_info_of(&anchor);
    let claim = delegation.claim().unwrap();
    let v1 = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let head1 = v1.head();
    delegation.add(v1.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, v1);
    let server = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
    server.publish(delegation.clone(), vec![pin], vouches);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = spawn(app(server.clone(), dir));
    kuipa_tools::net::set_thread_endpoint("window1.example.test", &url);

    let paths = enroll_window_of_one(&anchor, head1);

    // The tree grows — a second claim appended — and a rekey brings
    // the new head: the window extends, with the consistency check
    // passing over the served pages.
    let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let other_delegation = Delegation::issue(
        &other,
        REALM,
        "window2.example.test",
        other.public(),
        now() - 60,
        now() + 86400,
    )
    .unwrap();
    let other_claim = other_delegation.claim().unwrap();
    let v2 = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap(), other_claim.leaf(S256).unwrap()],
        now(),
        now() + 86_400,
        Some(&vouch_of(&server, pin)),
    )
    .unwrap();
    let head2 = v2.head();
    assert!(head2.0 > head1.0, "the log grew");
    let mut delegation2 = delegation.clone();
    delegation2.add(v2.proof(&claim, anchor.public()).unwrap());
    let mut vouches2 = std::collections::HashMap::new();
    vouches2.insert(pin, v2);
    server.publish(delegation2.clone(), vec![pin], vouches2);
    // What a rekey's write-back does, without the Kerberos rekey
    // itself (kdc.rs covers that): the new head, merged with the
    // consistency check against the served pages.
    let endpoint = kuipa_tools::net::Endpoint::new(
        "window1.example.test",
        &kuipa_tools::net::Trust::FirstContact,
    )
    .unwrap();
    let offered = [(pin, Some(head2))];
    let (merged, restarted) = merge_offered(&endpoint, &paths, &offered);
    assert!(!restarted);
    assert_eq!(
        merged[0].heads,
        vec![head1, head2],
        "the window extended through the consistent log"
    );
    kuipa_tools::paths::write_anchor_pins(&paths.anchors(), "kuipa realm anchors", &merged, None)
        .unwrap();

    // A server whose fresh head skips the history: the same size as
    // the client's newest, but a different tree (a claim dropped).
    // The consistency check refuses it, the window keeps what it had,
    // and the rekey still succeeds through the signature path.
    // Same size as the client's newest head, a different tree: the
    // leaves reordered, so the client's pinned prefix (its history)
    // does not appear at the front.
    let v3 = SignedVouch::issue(
        &anchor,
        REALM,
        [other_claim.leaf(S256).unwrap(), claim.leaf(S256).unwrap()],
        now(),
        now() + 86_400,
        None,
    )
    .unwrap();
    let head3 = v3.head();
    assert_eq!(head3.0, head2.0, "the same size, a different tree");
    assert_ne!(head3.1, head2.1);
    let mut delegation3 = delegation.clone();
    delegation3.add(v3.proof(&claim, anchor.public()).unwrap());
    let mut vouches3 = std::collections::HashMap::new();
    vouches3.insert(pin, v3);
    server.publish(delegation3.clone(), vec![pin], vouches3);
    forged_head_is_not_pinned(&endpoint, &paths, pin, head1, head2, head3);
    kuipa_tools::net::clear_thread_endpoints();
}

/// The realm info for the window test's single server.
fn window_info_of(anchor: &SigningKey) -> RealmInfo {
    RealmInfo {
        realm: REALM.into(),
        domain: "example.test".into(),
        basedn: "dc=example,dc=test".into(),
        server: "window1.example.test".into(),
        servers: vec!["window1.example.test".into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
    }
}

/// The anchor's current published vouch, for extending its log.
fn vouch_of(server: &Arc<EnrollServer>, anchor: tang_pqc::Thumbprint) -> SignedVouch {
    server.vouches().remove(&anchor).expect("a published vouch")
}

#[test]
fn audit_reports_coverage_and_split_views() {
    // DESIGN-claim-logs.md §5: the audit tool reads the public
    // endpoints and reports.  Coverage names current, stale and
    // restarted heads; a split view is two servers answering
    // different roots for the same anchor.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (keys, _, mut delegation) = server_keys(&anchor, "audit1.example.test");
    let signing = SigningKey::from_jwk(keys.signing.to_jwk().unwrap().as_ref()).unwrap();
    let info = audit_info_of(&anchor);
    let claim = delegation.claim().unwrap();
    let v1 = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let head1 = v1.head();
    delegation.add(v1.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, v1);
    let server = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
    server.publish(delegation.clone(), vec![pin], vouches);
    let url = spawn(app(server.clone(), Dir::default()));
    kuipa_tools::net::set_thread_endpoint("audit1.example.test", &url);

    // Coverage: the served head is current for itself, stale for a
    // smaller pinned one, and a split for a root the log does not
    // contain.
    let report =
        kuipa_tools::audit::coverage("audit1.example.test", &[(pin, head1.0, head1.1)]).unwrap();
    assert_eq!(report["anchors"][0]["state"], "current", "{report}");
    let report =
        kuipa_tools::audit::coverage("audit1.example.test", &[(pin, head1.0, test_hash(7))])
            .unwrap();
    assert!(
        report["anchors"][0]["state"]
            .as_str()
            .unwrap()
            .starts_with("split"),
        "{report}"
    );
    let report =
        kuipa_tools::audit::coverage("audit1.example.test", &[(pin, head1.0 + 5, head1.1)])
            .unwrap();
    assert!(
        report["anchors"][0]["state"]
            .as_str()
            .unwrap()
            .starts_with("split: the server's tree is shorter"),
        "{report}"
    );

    // A second server of the same realm, its anchor's log forked: the
    // same claim in a different order makes a different root at the
    // same size, and the split view names both sides.
    let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let other_delegation = Delegation::issue(
        &other,
        REALM,
        "audit2.example.test",
        other.public(),
        now() - 60,
        now() + 86400,
    )
    .unwrap();
    let other_claim = other_delegation.claim().unwrap();
    let v2 = SignedVouch::issue(
        &anchor,
        REALM,
        [other_claim.leaf(S256).unwrap(), claim.leaf(S256).unwrap()],
        now(),
        now() + 86_400,
        None,
    )
    .unwrap();
    let mut forked = delegation.clone();
    forked.add(v2.proof(&claim, anchor.public()).unwrap());
    let mut forked_vouches = std::collections::HashMap::new();
    forked_vouches.insert(pin, v2);
    // A second server of the same realm shares the delegated claim
    // key (§4.6): its advertisement verifies against that key, as
    // kuipad's does — with its own exchange keys.
    let server2 = Arc::new(EnrollServer::new(
        ServerKeys {
            signing,
            join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            trust: Vec::new(),
            vouchers: Vec::new(),
            retired: Vec::new(),
        },
        audit_info_of(&anchor),
        forked,
    ));
    server2.publish(delegation.clone(), vec![pin], forked_vouches);
    let url2 = spawn(app(server2, Dir::default()));
    kuipa_tools::net::set_thread_endpoint("audit2.example.test", &url2);

    let report = kuipa_tools::audit::split_view(&[
        "audit1.example.test".to_owned(),
        "audit2.example.test".to_owned(),
    ])
    .unwrap();
    assert_eq!(
        report["disagreements"].as_array().map(Vec::len),
        Some(1),
        "{report}"
    );
    assert!(
        !kuipa_tools::audit::clean(&report),
        "a split view is not clean"
    );
    kuipa_tools::net::clear_thread_endpoints();
}

/// The realm info for the audit tests' servers.
fn audit_info_of(anchor: &SigningKey) -> RealmInfo {
    RealmInfo {
        realm: REALM.into(),
        domain: "example.test".into(),
        basedn: "dc=example,dc=test".into(),
        server: "audit1.example.test".into(),
        servers: vec!["audit1.example.test".into(), "audit2.example.test".into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
    }
}

/// An enrolled host's state and CA, for a flow that works from stored
/// state (`check`) without an enrollment having run in this test.
fn enrolled(paths: &Paths, servers: &[&str]) {
    kuipa_tools::paths::write_pem(&paths.ca(), &[CA.to_vec()]).unwrap();
    kuipa_tools::paths::State {
        realm: REALM.into(),
        fqdn: HOST.into(),
        servers: servers.iter().map(|s| (*s).to_owned()).collect(),
        ..Default::default()
    }
    .store(paths)
    .unwrap();
}

/// Realm info naming `server` and these anchors, one server only.
fn info_named(server: &str, anchors: &[tang_pqc::Thumbprint]) -> RealmInfo {
    RealmInfo {
        realm: REALM.into(),
        domain: "example.test".into(),
        basedn: "dc=example,dc=test".into(),
        server: server.into(),
        servers: vec![server.into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: anchors.to_vec(),
        heads: Vec::new(),
        trusts: Vec::new(),
    }
}

/// What the `kuipa` CLI puts on the wire from a pin file: the live
/// anchors, their whole windows, and the frozen ones (§1.4, §2).
fn pins_for(
    paths: &Paths,
) -> (
    Vec<tang_pqc::Thumbprint>,
    Vec<kuipa_enroll::delegation::HeadPin>,
    Vec<tang_pqc::Thumbprint>,
) {
    let (anchors, heads, _, frozen) = kuipa_tools::paths::pinned_windows(&paths.anchors()).unwrap();
    (anchors, heads, frozen)
}

/// Pin lines, oldest-first windows and freezes as written by hand.
fn write_pins(paths: &Paths, pins: &[kuipa_tools::paths::Pin]) {
    kuipa_tools::paths::write_anchor_pins(&paths.anchors(), "test", pins, None).unwrap();
}

#[test]
fn an_expired_pin_is_no_trust_at_all() {
    // PoC poc_expired_pin: a pin whose expiry passed is not trust — not
    // its anchor, not its head, not its freeze.  Before this was fixed
    // the CLI's pin read ignored the expiry, so an unrefreshed pin kept
    // working and its head kept proving claims.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (keys, _, mut delegation) = server_keys(&anchor, "expired1.example.test");
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let head = vouch.head();
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, vouch);
    let server = Arc::new(EnrollServer::new(
        keys,
        info_named("expired1.example.test", &[pin]),
        delegation.clone(),
    ));
    server.publish(delegation, vec![pin], vouches);
    serve_as("expired1.example.test", app(server, Dir::default()));

    let paths = root("expired-pin");
    enrolled(&paths, &["expired1.example.test"]);
    write_pins(
        &paths,
        &[kuipa_tools::paths::Pin {
            anchor: pin,
            exp: Some(now() - kuipa_enroll::delegation::CLOCK_SKEW - 1),
            heads: vec![head],
            frozen: true,
            retired: Vec::new(),
        }],
    );
    assert_eq!(
        pins_for(&paths),
        (Vec::new(), Vec::new(), Vec::new()),
        "an expired pin gives nothing to verify with"
    );
    let out = flows::check(&paths, None).unwrap();
    assert_eq!(
        out["servers"][0]["ok"],
        serde_json::json!(false),
        "an expired pin must not verify the server: {out}"
    );

    // The same pin, unexpired: the anchor is trusted, its head is what
    // the advertisement is verified against, and the freeze is in force.
    write_pins(
        &paths,
        &[kuipa_tools::paths::Pin {
            anchor: pin,
            exp: Some(now() + 3600),
            heads: vec![head],
            frozen: true,
            retired: Vec::new(),
        }],
    );
    let (anchors, heads, frozen) = pins_for(&paths);
    assert_eq!(anchors, vec![pin]);
    assert_eq!(frozen, vec![pin]);
    assert_eq!(heads.len(), 1);
    let out = flows::check(&paths, None).unwrap();
    assert_eq!(out["servers"][0]["ok"], serde_json::json!(true), "{out}");

    // A corrupt pin file is an error, never "nothing pinned".
    std::fs::write(paths.anchors(), format!("{pin} +5\n")).unwrap();
    assert!(
        flows::check(&paths, None).is_err(),
        "a corrupt pin file fails closed"
    );
    kuipa_tools::net::clear_thread_endpoints();
}

/// State of a forged partner head test, once its server is up.
struct ForgedHeads {
    anchor: SigningKey,
    b_head: (u64, kuipa_enroll::merkle::Hash),
    b_pin: tang_pqc::Thumbprint,
    b_url: String,
    info: kuipa_enroll::realm::RealmInfo,
    keys: kuipa_enroll::realm::ServerKeys,
    delegation: kuipa_enroll::delegation::Delegation,
    vouches: std::collections::HashMap<tang_pqc::Thumbprint, kuipa_enroll::delegation::SignedVouch>,
}

/// State of a forged partner head test, once its server is up.
fn forged_head_tail(state: ForgedHeads) {
    let ForgedHeads {
        anchor,
        b_head,
        b_pin,
        b_url,
        mut info,
        keys,
        delegation,
        vouches,
    } = state;
    // A advertises B with a head B never signed.
    info.trusts = vec![kuipa_enroll::realm::TrustedRealm {
        realm: "B.TEST".into(),
        domain: "b.test".into(),
        servers: vec!["forgeB1.example.test".into()],
        anchors: vec![b_pin],
        heads: vec![kuipa_enroll::delegation::HeadPin {
            anchor: b_pin,
            size: 99,
            root: test_hash(7),
        }],
    }];
    info.validate().unwrap();
    let a = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
    a.publish(delegation, vec![*anchor.public().thumbprint()], vouches);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    serve_as("forgeA1.example.test", app(a, dir));

    let paths = root("forge-partner-head");
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(&["forgeA1.example.test".to_owned()]),
    )
    .unwrap();
    let result = flows::trusted_realms(&paths).unwrap();
    assert_eq!(
        result["trusted_realms"][0]["status"], "installed",
        "{result}"
    );

    // The forged head is not installed.  B's real head is what its own
    // advertisement signs — the drop was a decision, not an absence.
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.trust_anchors("B.TEST")).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].anchor, b_pin);
    assert!(
        pins[0]
            .heads
            .iter()
            .all(|(size, root)| *size != 99 && *root != test_hash(7)),
        "a forged head was pinned: {:?}",
        pins[0].heads
    );
    assert!(
        pins[0].heads.is_empty(),
        "nothing signed these heads: {:?}",
        pins[0].heads
    );
    let endpoint = kuipa_tools::net::Endpoint::new(&b_url, &kuipa_tools::net::Trust::FirstContact)
        .expect("endpoint");
    let adv = endpoint
        .advertisement(std::slice::from_ref(&b_pin))
        .unwrap();
    let decoded = kuipa_enroll::delegation::Delegation::from_value(
        adv.unverified_member("delegation")
            .expect("delegation member")
            .expect("present"),
    )
    .unwrap();
    let proved = decoded.verified_heads(&tang_pqc::Policy::default(), now());
    assert_eq!(proved.len(), 1, "{proved:?}");
    assert_eq!((proved[0].size, proved[0].root), b_head);
    kuipa_tools::net::clear_thread_endpoints();
}

#[test]
fn a_forged_partner_head_is_not_pinned() {
    // PoC poc_head_trust: A's trust entry names a head for B's anchor
    // that no signature backs.  An advertised head is the advertising
    // server's assertion (DESIGN-claim-logs.md §4); a head nothing signed
    // must not become this host's trust for B.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, _, mut delegation) = server_keys(&anchor, "forgeA1.example.test");
    let info = info_named("forgeA1.example.test", &[*anchor.public().thumbprint()]);
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(*anchor.public().thumbprint(), vouch);

    // B: its anchor signing a real head.
    let b = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let b_pin = *b.public().thumbprint();
    let b_signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let mut b_delegation = Delegation::issue(
        &b,
        "B.TEST",
        "forgeB1.example.test",
        b_signing.public(),
        now() - 60,
        now() + 86_400,
    )
    .unwrap();
    let b_claim = b_delegation.claim().unwrap();
    let b_vouch = SignedVouch::issue(
        &b,
        "B.TEST",
        [b_claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let b_head = b_vouch.head();
    b_delegation.add(b_vouch.proof(&b_claim, b.public()).unwrap());
    let b_info = RealmInfo {
        realm: "B.TEST".into(),
        domain: "b.test".into(),
        basedn: "dc=b,dc=test".into(),
        server: "forgeB1.example.test".into(),
        servers: vec!["forgeB1.example.test".into()],
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![b_pin],
        heads: Vec::new(),
        trusts: Vec::new(),
    };
    let b_server = Arc::new(EnrollServer::new(
        ServerKeys {
            signing: b_signing,
            join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            trust: Vec::new(),
            vouchers: Vec::new(),
            retired: Vec::new(),
        },
        b_info,
        b_delegation.clone(),
    ));
    let mut b_vouches = std::collections::HashMap::new();
    b_vouches.insert(b_pin, b_vouch);
    b_server.publish(b_delegation, vec![b_pin], b_vouches);
    let b_url = serve_as(
        "forgeB1.example.test",
        app(b_server.clone(), Dir::default()),
    );

    forged_head_tail(ForgedHeads {
        anchor,
        b_head,
        b_pin,
        b_url,
        info,
        keys,
        delegation,
        vouches,
    });
}

/// The mixed pins of a frozen anchor F and an anchor N, once the server is up.
struct MixedFrozen {
    f: SigningKey,
    fp: tang_pqc::Thumbprint,
    np: tang_pqc::Thumbprint,
    n_head: (u64, kuipa_enroll::merkle::Hash),
    f_head: (u64, kuipa_enroll::merkle::Hash),
    paths: TempRoot,
    url: String,
}

/// The mixed pins of a frozen anchor F and an anchor N, once the server is up.
fn mixed_frozen_tail(state: MixedFrozen) {
    let MixedFrozen {
        f,
        fp,
        np,
        n_head,
        f_head,
        paths,
        url,
    } = state;
    // The very same pins, with F unfrozen: the signature fallback is back
    // and the realm is usable — the refusal was the freeze, not F's head.
    write_pins(
        &paths,
        &[
            kuipa_tools::paths::Pin {
                anchor: fp,
                exp: None,
                heads: vec![f_head],
                frozen: false,
                retired: Vec::new(),
            },
            kuipa_tools::paths::Pin {
                anchor: np,
                exp: None,
                heads: vec![n_head],
                frozen: false,
                retired: Vec::new(),
            },
        ],
    );
    let (anchors, heads, frozen) = pins_for(&paths);
    let mut s = string(&f, b"Secret123");
    let otp = s.take_secret().unwrap();
    let result = flows::enroll_online(
        &paths,
        s.realm(),
        &anchors,
        &heads,
        &frozen,
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&url)),
    )
    .unwrap();
    assert_eq!(result["issuer"], "mixed1.example.test", "{result}");
    kuipa_tools::net::clear_thread_endpoints();
}

#[test]
fn a_frozen_pin_needs_a_proof_by_its_own_head() {
    // DESIGN-claim-logs.md §2, the mixed case: F is frozen and its head
    // does not cover the claim, N is unfrozen and its head does.  The
    // other anchor's proof is not an answer for F, so the host refuses
    // and names the freeze.  Before this was fixed one anchor's head
    // proof satisfied every frozen pin.
    let f = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let n = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let fp = *f.public().thumbprint();
    let np = *n.public().thumbprint();
    let (keys, _, delegation) = server_keys(&f, "mixed1.example.test");
    let claim = delegation.claim().unwrap();
    // F vouches for a log that does not contain this claim at all.
    let other =
        kuipa_enroll::merkle::leaf_hash(TreeHash::Sha256, b"another claim entirely").unwrap();
    let f_vouch = SignedVouch::issue(&f, REALM, [other], now() - 60, now() + 86_400, None).unwrap();
    let f_head = f_vouch.head();
    // N vouches for the claim the server advertises.
    let n_vouch = SignedVouch::issue(
        &n,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let n_head = n_vouch.head();
    let mut published = delegation.clone();
    published.add(n_vouch.proof(&claim, n.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(fp, f_vouch);
    vouches.insert(np, n_vouch);
    let server = Arc::new(EnrollServer::new(
        keys,
        info_named("mixed1.example.test", &[fp, np]),
        published.clone(),
    ));
    server.publish(published, vec![fp, np], vouches);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = serve_as("mixed1.example.test", app(server, dir));

    let paths = root("frozen-mixed");
    write_pins(
        &paths,
        &[
            kuipa_tools::paths::Pin {
                anchor: fp,
                exp: None,
                heads: vec![f_head],
                frozen: true,
                retired: Vec::new(),
            },
            kuipa_tools::paths::Pin {
                anchor: np,
                exp: None,
                heads: vec![n_head],
                frozen: false,
                retired: Vec::new(),
            },
        ],
    );
    let (anchors, heads, frozen) = pins_for(&paths);
    let mut s = string(&f, b"Secret123");
    let otp = s.take_secret().unwrap();
    let err = flows::enroll_online(
        &paths,
        s.realm(),
        &anchors,
        &heads,
        &frozen,
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&url)),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("frozen"), "{msg}");
    assert!(
        msg.contains(&fp.to_string()),
        "the refusal must name F: {msg}"
    );

    mixed_frozen_tail(MixedFrozen {
        f,
        fp,
        np,
        n_head,
        f_head,
        paths,
        url,
    });
}

/// Two frozen pins of distinct anchors, once the server is up.
struct TwoFrozen {
    f: SigningKey,
    fp: tang_pqc::Thumbprint,
    np: tang_pqc::Thumbprint,
    n_head: (u64, kuipa_enroll::merkle::Hash),
    f_head: (u64, kuipa_enroll::merkle::Hash),
    url: String,
}

/// Two frozen pins of distinct anchors, once the server is up.
fn two_frozen_tail(state: TwoFrozen) {
    let TwoFrozen {
        f,
        fp,
        np,
        n_head,
        f_head,
        url,
    } = state;
    // Both frozen pins cover the claim: the enrollment is head-wise and
    // each anchor counts toward §4.4's quorum through its own head.
    let paths = root("frozen-two");
    write_pins(
        &paths,
        &[
            kuipa_tools::paths::Pin {
                anchor: fp,
                exp: None,
                heads: vec![f_head],
                frozen: true,
                retired: Vec::new(),
            },
            kuipa_tools::paths::Pin {
                anchor: np,
                exp: None,
                heads: vec![n_head],
                frozen: true,
                retired: Vec::new(),
            },
        ],
    );
    let (anchors, heads, frozen) = pins_for(&paths);
    assert_eq!(frozen.len(), 2);
    let mut s = string(&f, b"Secret123");
    let otp = s.take_secret().unwrap();
    let result = flows::enroll_online(
        &paths,
        s.realm(),
        &anchors,
        &heads,
        &frozen,
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&url)),
    )
    .unwrap();
    assert_eq!(result["issuer"], "twofrozen1.example.test", "{result}");

    // The other half: F's pinned head no longer covers the claim, so only
    // one proof can be served — and a proof by N is not an answer for F.
    write_pins(
        &paths,
        &[
            kuipa_tools::paths::Pin {
                anchor: fp,
                exp: None,
                heads: vec![(7, test_hash(9))],
                frozen: true,
                retired: Vec::new(),
            },
            kuipa_tools::paths::Pin {
                anchor: np,
                exp: None,
                heads: vec![n_head],
                frozen: true,
                retired: Vec::new(),
            },
        ],
    );
    let (anchors, heads, frozen) = pins_for(&paths);
    let mut s = string(&f, b"Secret123");
    let otp = s.take_secret().unwrap();
    let err = flows::enroll_online(
        &root("frozen-two-outside"),
        s.realm(),
        &anchors,
        &heads,
        &frozen,
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(std::slice::from_ref(&url)),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("frozen"), "{msg}");
    assert!(
        msg.contains(&fp.to_string()),
        "the refusal must name F: {msg}"
    );
    kuipa_tools::net::clear_thread_endpoints();
}

#[test]
fn two_frozen_pins_must_both_prove_the_claim() {
    // DESIGN-claim-logs.md §2: with two frozen pins of distinct anchors,
    // each anchor's own head must prove the claim.  The server that
    // answers both is usable; one that answers only the other is refused
    // by name.
    let f = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let n = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let fp = *f.public().thumbprint();
    let np = *n.public().thumbprint();
    let (keys, _, delegation) = server_keys(&f, "twofrozen1.example.test");
    let claim = delegation.claim().unwrap();
    let f_vouch = SignedVouch::issue(
        &f,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let n_vouch = SignedVouch::issue(
        &n,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let f_head = f_vouch.head();
    let n_head = n_vouch.head();
    let mut published = delegation.clone();
    published.add(f_vouch.proof(&claim, f.public()).unwrap());
    published.add(n_vouch.proof(&claim, n.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(fp, f_vouch);
    vouches.insert(np, n_vouch);
    let server = Arc::new(EnrollServer::new(
        keys,
        info_named("twofrozen1.example.test", &[fp, np]),
        published.clone(),
    ));
    server.publish(published, vec![fp, np], vouches);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = serve_as("twofrozen1.example.test", app(server, dir));

    two_frozen_tail(TwoFrozen {
        f,
        fp,
        np,
        n_head,
        f_head,
        url,
    });
}

#[test]
fn a_whole_window_travels_so_the_newest_head_proves() {
    // DESIGN-claim-logs.md §1.4: the server tries each pinned head in
    // turn, so a claim under the newest head of a window is proven even
    // though nothing under the oldest proves it.  Sending only one head
    // per anchor used to refuse this honest server.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (keys, _, delegation) = server_keys(&anchor, "window1.example.test");
    let claim = delegation.claim().unwrap();
    // The claim is the second leaf: the pinned window's oldest head, over
    // the first leaf alone, cannot prove it.
    let older =
        kuipa_enroll::merkle::leaf_hash(TreeHash::Sha256, b"an earlier enrollment").unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [older, claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let newest = vouch.head();
    let oldest = (1, kuipa_enroll::merkle::root(&[older]).unwrap());
    let mut published = delegation.clone();
    published.add(vouch.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, vouch);
    let server = Arc::new(EnrollServer::new(
        keys,
        info_named("window1.example.test", &[pin]),
        published.clone(),
    ));
    server.publish(published, vec![pin], vouches);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = serve_as("window1.example.test", app(server, dir));

    let paths = root("full-window");
    write_pins(
        &paths,
        &[kuipa_tools::paths::Pin {
            anchor: pin,
            exp: None,
            heads: vec![oldest, newest],
            frozen: true,
            retired: Vec::new(),
        }],
    );
    let (anchors, heads, frozen) = pins_for(&paths);
    assert_eq!(heads.len(), 2, "the whole window travels (§1.4)");
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    let (result, trace) = traced(|| {
        flows::enroll_online(
            &paths,
            s.realm(),
            &anchors,
            &heads,
            &frozen,
            flows::Host {
                fqdn: HOST,
                auth: &Auth::LdapOtp(otp),
            },
            &Deployment::servers(std::slice::from_ref(&url)),
        )
    });
    let result = result.expect("the newest head of the window proves the claim");
    assert_eq!(result["issuer"], "window1.example.test", "{result}");
    assert!(trace.contains("advertisement verified"), "{trace}");

    // The answer was head-wise: asked with the window, the server serves
    // a proof and no signature.
    let endpoint = kuipa_tools::net::Endpoint::new(&url, &kuipa_tools::net::Trust::FirstContact)
        .expect("endpoint");
    let body = endpoint
        .advertisement_with_heads(&[pin], &heads)
        .unwrap()
        .unverified_member("delegation")
        .expect("delegation member")
        .expect("present")
        .to_string();
    assert!(body.contains("head_proofs"), "no head proof in:\n{body}");
    assert!(
        !body.contains("signatures"),
        "a signature was served to a head-pinned client:\n{body}"
    );
    // What the operator froze stays as written: the exchange rewrites
    // nothing of a frozen window (§2).
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    assert_eq!(pins[0].heads, vec![oldest, newest]);
    kuipa_tools::net::clear_thread_endpoints();
}

/// Open a staged bundle offline into `paths`: what `install` merges into
/// the pin file, with the payload naming `heads` beside its anchor.
fn bundle_enroll(
    paths: &Paths,
    anchor: &SigningKey,
    keys: &ServerKeys,
    delegation: &Delegation,
    heads: Vec<Option<(u64, kuipa_enroll::merkle::Hash)>>,
    issuer: &str,
) -> Result<serde_json::Value, kuipa_tools::paths::Error> {
    let _ = flows::prepare(paths, false, HOST);
    let public =
        tang_pqc::ExchangeKey::from_jwk_json(&std::fs::read(paths.recipient_public()).unwrap())
            .unwrap();
    let enrollment = Enrollment {
        config: RealmConfig {
            realm: REALM.into(),
            domain: "example.test".into(),
            basedn: "dc=example,dc=test".into(),
            issuer: issuer.into(),
            servers: vec![issuer.into()],
        },
        keytab: Dir::default().keys(HOST),
        ca_certs: vec![CA.to_vec()],
        pkinit_anchors: vec![b"PKINIT anchor (DER)".to_vec()],
        anchors: vec![*anchor.public().thumbprint()],
        heads,
        epoch_seq: 0,
        epoch_head: [0; 48],
    };
    let (bundle, _) = Bundle::create(
        keys,
        delegation,
        KemAlg::MlKem768,
        Recipient::MachineKey(&public),
        &enrollment,
        now(),
        now() + 3600,
    )
    .unwrap();
    let s = EnrollmentString::new(REALM, *anchor.public().thumbprint(), now() + 86_400, None);
    flows::enroll_bundle(paths, &bundle.to_bytes(), Some(&s), false, Some(HOST))
}

#[test]
fn a_payload_head_nothing_signed_is_not_pinned() {
    // DESIGN-claim-logs.md §4: an enrollment names heads beside its
    // anchors, but a head becomes trust only when an anchor signed it.
    // Here the issuer signs one head; a payload naming another must not
    // pin it, and the head it does sign must be pinned.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    // The bundle is staged by one server key; the daemon that answers the
    // backing fetch has its own, each consistent with its own delegation.
    let (bundle_keys, _, bundle_delegation) = server_keys(&anchor, "back1.example.test");
    let (keys, _, mut delegation) = server_keys(&anchor, "back1.example.test");
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let head = vouch.head();
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, vouch);
    let server = Arc::new(EnrollServer::new(
        keys,
        info_named("back1.example.test", &[pin]),
        delegation.clone(),
    ));
    server.publish(delegation.clone(), vec![pin], vouches);
    serve_as("back1.example.test", app(server, Dir::default()));

    // A head nothing signed: the anchor is pinned, its window stays empty.
    let paths = root("payload-unbacked");
    bundle_enroll(
        &paths,
        &anchor,
        &bundle_keys,
        &bundle_delegation,
        vec![Some((9, test_hash(9)))],
        "back1.example.test",
    )
    .unwrap();
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].anchor, pin);
    assert!(
        pins[0].heads.is_empty(),
        "an unbacked head was pinned: {:?}",
        pins[0].heads
    );

    // The head the issuer does sign: pinned.
    let paths = root("payload-backed");
    bundle_enroll(
        &paths,
        &anchor,
        &bundle_keys,
        &bundle_delegation,
        vec![Some(head)],
        "back1.example.test",
    )
    .unwrap();
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    assert_eq!(pins[0].heads, vec![head], "the signed head is pinned");
    kuipa_tools::net::clear_thread_endpoints();
}

#[test]
fn a_head_beyond_the_fetch_cap_is_not_pinned() {
    // DESIGN-claim-logs.md §1.3, bounded: growing a window means reading
    // the claim log between the pinned head and the new one, and a host
    // reads at most `flows::MAX_HEAD_FETCH_PAGES` (64) pages of
    // `MAX_CLAIM_LOG_PAGE` leaves.  A head past that budget is not
    // checked and not pinned — otherwise one answer could make a host
    // walk an unbounded log to grow its trust.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (bundle_keys, _, bundle_delegation) = server_keys(&anchor, "cap1.example.test");
    let (keys, _, mut delegation) = server_keys(&anchor, "cap1.example.test");
    let claim = delegation.claim().unwrap();
    let vouch = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    delegation.add(vouch.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, vouch);
    let server = Arc::new(EnrollServer::new(
        keys,
        info_named("cap1.example.test", &[pin]),
        delegation.clone(),
    ));
    server.publish(delegation.clone(), vec![pin], vouches);
    serve_as("cap1.example.test", app(server, Dir::default()));

    // A window of one leaf, and a payload head past the budget.
    let leaf = kuipa_enroll::merkle::leaf_hash(TreeHash::Sha256, b"the pinned leaf").unwrap();
    let pinned = (1, kuipa_enroll::merkle::root(&[leaf]).unwrap());
    let paths = root("fetch-cap");
    write_pins(
        &paths,
        &[kuipa_tools::paths::Pin {
            anchor: pin,
            exp: None,
            heads: vec![pinned],
            frozen: false,
            retired: Vec::new(),
        }],
    );
    let budget = 64 * kuipa_enroll::server::MAX_CLAIM_LOG_PAGE;
    // The budget is checked against the *claimed* size, before a page is
    // read or a hash computed, so the refused head needs no tree behind
    // it: what is being tested is that a claimed size past the budget is
    // never chased.
    let far = (
        budget as u64 + 1,
        kuipa_enroll::merkle::root(&[leaf]).unwrap(),
    );
    let (result, trace) = traced(|| {
        bundle_enroll(
            &paths,
            &anchor,
            &bundle_keys,
            &bundle_delegation,
            vec![Some(far)],
            "cap1.example.test",
        )
    });
    result.unwrap();
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    assert_eq!(
        pins[0].heads,
        vec![pinned],
        "a head beyond the fetch budget was pinned"
    );
    assert!(
        trace.contains(&format!("its head names {} leaves", budget + 1)),
        "{trace}"
    );
    kuipa_tools::net::clear_thread_endpoints();
}

#[test]
fn the_tlog_routes_serve_heads_leaves_and_proofs() {
    // DESIGN-tlog.md §5: a server's log is public — its signed head, its
    // leaves, and inclusion and consistency proofs at any size a client
    // holds a head for — and only under the log's own id.
    use kuipa_enroll::server::Ledger;
    use kuipa_enroll::tlog::{Kind, Leaf, SignedHead};

    let dir = std::env::temp_dir().join(format!("kuipa-flows-tlog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let (keys, info, delegation) = server_keys(&anchor, "tlog1.example.test");
    let signer = keys.signing.public().clone();
    let ledger = Arc::new(
        kuipad::ledger::FileLedger::open(&dir, REALM, "tlog1.example.test", tree(&keys)).unwrap(),
    );
    let server = Arc::new(EnrollServer::new(keys, info, delegation).with_ledger(ledger.clone()));
    let url = spawn(Arc::new(App {
        server,
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        keys: None,
        ledger: Some(ledger.clone()),
        directory: Dir::default(),
    }));
    let _ = rustls_native_ossl::default_provider().install_default();
    let http = reqwest::blocking::Client::new();
    let base = format!("{url}/ipa/ku/tlog/{}", ledger.id());
    let get = |path: &str| http.get(format!("{base}/{path}")).send().unwrap();
    let json = |path: &str| -> serde_json::Value {
        serde_json::from_slice(&get(path).bytes().unwrap()).unwrap()
    };
    let hashes = |v: &serde_json::Value| -> Vec<kuipa_enroll::merkle::Hash> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|h| {
                tang_pqc::b64::decode(h.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect()
    };

    // Nothing logged yet: no head to serve.
    assert_eq!(get("head").status(), 404);
    for i in 0..2u8 {
        ledger.append(Kind::VAULT_DEVICE, b"vault", &[i]).unwrap();
    }
    let old = SignedHead::from_bytes(&get("head").bytes().unwrap()).unwrap();
    old.verify(&signer, &tang_pqc::Policy::default()).unwrap();
    for i in 0..3u8 {
        ledger.append(Kind::ESCROW_RELEASE, b"vault", &[i]).unwrap();
    }
    let new = SignedHead::from_bytes(&get("head").bytes().unwrap()).unwrap();
    assert_eq!((old.head.size, new.head.size), (2, 5));

    let leaves: Vec<Leaf> = json("leaves?from=0")["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| Leaf::from_bytes(&tang_pqc::b64::decode(l.as_str().unwrap()).unwrap()).unwrap())
        .collect();
    assert_eq!(leaves.len(), 5);
    assert_eq!(json("leaves?from=4")["leaves"].as_array().unwrap().len(), 1);
    let path = hashes(&json("proof?index=1&size=2")["path"]);
    assert!(old.head.includes(&leaves[1], 1, &path).unwrap());
    let path = hashes(&json("proof?index=4&size=5")["path"]);
    assert!(new.head.includes(&leaves[4], 4, &path).unwrap());
    let proof = hashes(&json("consistency?from=2&size=5")["proof"]);
    assert!(new.head.extends(&old.head, &proof).unwrap());

    // Bad or missing numbers, sizes beyond the log, another log's id.
    assert_eq!(get("proof?index=1").status(), 400);
    assert_eq!(get("proof?index=7&size=5").status(), 404);
    assert_eq!(get("consistency?from=2&size=9").status(), 404);
    let other = kuipa_enroll::tlog::LogId::of(REALM, "elsewhere", TreeHash::Sha256).unwrap();
    let status = http
        .get(format!("{url}/ipa/ku/tlog/{other}/head"))
        .send()
        .unwrap()
        .status();
    assert_eq!(status, 404);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A server named `fqdn` with its own transparency log in `dir`, served
/// for this test's thread.
fn tlog_server(
    anchor: &SigningKey,
    fqdn: &str,
    dir: &std::path::Path,
    witnesses: &[&SigningKey],
) -> Arc<kuipad::ledger::FileLedger> {
    let (keys, info, delegation) = server_keys(anchor, fqdn);
    let ledger = Arc::new(
        kuipad::ledger::FileLedger::open(dir, REALM, fqdn, tree(&keys))
            .unwrap()
            .with_witnesses(witnesses.iter().map(|w| w.public().clone()).collect()),
    );
    let server = Arc::new(EnrollServer::new(keys, info, delegation).with_ledger(ledger.clone()));
    let url = spawn(Arc::new(App {
        server,
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        keys: None,
        ledger: Some(ledger.clone()),
        directory: Dir::default(),
    }));
    kuipa_tools::net::set_thread_endpoint(fqdn, &url);
    ledger
}

#[test]
fn audit_replays_a_servers_transparency_log() {
    // DESIGN-tlog.md §5: kuipa-audit tlog checks a server's head against
    // the key its verified advertisement names, replays every leaf, and
    // with a state file requires the next run's log to extend this one.
    use kuipa_enroll::server::Ledger;
    use kuipa_enroll::tlog::Kind;

    let base = std::env::temp_dir().join(format!("kuipa-flows-audit-tlog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let state = base.join("audited.json");
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = [*anchor.public().thumbprint()];
    let fqdn = "tlogaudit1.example.test";
    let audit = || kuipa_tools::audit::tlog(fqdn, &pin, &[], Some(&state)).unwrap();

    let ledger = tlog_server(&anchor, fqdn, &base.join("one"), &[]);
    assert_eq!(audit()["state"], "empty");
    for i in 0..3u8 {
        ledger.append(Kind::VAULT_DEVICE, b"v", &[i]).unwrap();
    }
    ledger.append(Kind::KEYS_FETCH, b"host", b"x").unwrap();
    let first = audit();
    assert_eq!(first["state"], "verified", "{first}");
    assert_eq!(first["size"], 4, "{first}");
    assert_eq!(first["kinds"]["vault-device"], 3, "{first}");
    assert_eq!(first["kinds"]["keys-fetch"], 1, "{first}");

    // The log grew: still verified, and it extends what was recorded.
    ledger.append(Kind::ESCROW_RELEASE, b"v", b"y").unwrap();
    let grown = audit();
    assert_eq!(grown["state"], "verified", "{grown}");
    assert_eq!(grown["previous"]["size"], 4, "{grown}");

    // Another anchor does not verify the advertisement: no report.
    let stranger = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    assert!(kuipa_tools::audit::tlog(fqdn, &[*stranger.public().thumbprint()], &[], None).is_err());

    // The same server answering from a different log — its history
    // rewritten — is forked against the recorded head.
    let rewritten = tlog_server(&anchor, fqdn, &base.join("two"), &[]);
    for i in 0..6u8 {
        rewritten.append(Kind::VAULT_POLICY, b"v", &[i]).unwrap();
    }
    let forked = audit();
    assert!(
        forked["state"].as_str().unwrap().starts_with("forked"),
        "{forked}"
    );
    // Without the state file, the rewritten log is consistent in itself.
    let alone = kuipa_tools::audit::tlog(fqdn, &pin, &[], None).unwrap();
    assert_eq!(alone["state"], "verified", "{alone}");
    kuipa_tools::net::clear_thread_endpoints();
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_witness_cosigns_only_heads_that_extend() {
    // DESIGN-tlog.md §4: kuipa-witness cosigns a head the log's advertised
    // key signed and that extends the last it cosigned; the server serves
    // trusted cosignatures; a rewritten log is reported forked, never
    // cosigned.
    use kuipa_enroll::server::Ledger;
    use kuipa_enroll::tlog::Kind;

    let base = std::env::temp_dir().join(format!("kuipa-flows-witness-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = [*anchor.public().thumbprint()];
    let fqdn = "witnessed1.example.test";
    let servers = [fqdn.to_owned()];
    let witness = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
    let stranger = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
    let state = base.join("witness.json");
    let pass = |key: &SigningKey, state: &std::path::Path| {
        let v = kuipa_tools::witness::pass(key, &servers, &pin, state).unwrap();
        v["servers"][0]["state"].as_str().unwrap().to_owned()
    };
    let cosigners = || {
        kuipa_tools::audit::tlog(fqdn, &pin, &[witness.public().clone()], None).unwrap()
            ["witnesses"]
            .as_array()
            .unwrap()
            .len()
    };

    let ledger = tlog_server(&anchor, fqdn, &base.join("one"), &[&witness]);
    assert_eq!(pass(&witness, &state), "empty");
    for i in 0..3u8 {
        ledger.append(Kind::VAULT_DEVICE, b"v", &[i]).unwrap();
    }
    assert_eq!(pass(&witness, &state), "cosigned");
    assert_eq!(cosigners(), 1);
    assert_eq!(pass(&witness, &state), "unchanged");
    // The log grew: re-signed, cosigned again through a consistency proof.
    ledger.append(Kind::ESCROW_RELEASE, b"v", b"x").unwrap();
    assert_eq!(cosigners(), 0);
    assert_eq!(pass(&witness, &state), "cosigned");
    assert_eq!(cosigners(), 1);
    // A witness the server does not trust is refused.
    let by_stranger = pass(&stranger, &base.join("stranger.json"));
    assert!(by_stranger.starts_with("skipped"), "{by_stranger}");

    // The server's history rewritten: the witness refuses, and keeps
    // refusing.
    let rewritten = tlog_server(&anchor, fqdn, &base.join("two"), &[&witness]);
    for i in 0..6u8 {
        rewritten.append(Kind::VAULT_POLICY, b"v", &[i]).unwrap();
    }
    assert_eq!(pass(&witness, &state), "forked");
    assert_eq!(pass(&witness, &state), "forked");
    assert_eq!(cosigners(), 0);
    kuipa_tools::net::clear_thread_endpoints();
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn a_host_pins_what_its_anchors_logs_retired() {
    // DESIGN-tlog.md §8: an anchor that drops a claim appends a tombstone
    // instead of restarting its log.  A host pinning the head learns the
    // retired claim from the page's vouch, whose entries make the pinned
    // root, and records it next to the pin.
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let pin = *anchor.public().thumbprint();
    let (keys, _, issued) = server_keys(&anchor, "window1.example.test");
    let claim = issued.claim().unwrap();
    // Only the proof by the vouch that retired a claim: `issue` carries
    // one of its own.
    let mut delegation = Delegation::new(&claim);
    let gone = Delegation::issue(
        &anchor,
        REALM,
        "gone.example.test",
        SigningKey::generate(SignatureAlg::MlDsa65)
            .unwrap()
            .public(),
        now() - 60,
        now() + 86_400,
    )
    .unwrap()
    .claim()
    .unwrap();
    let v1 = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap(), gone.leaf(S256).unwrap()],
        now() - 60,
        now() + 86_400,
        None,
    )
    .unwrap();
    let v2 = SignedVouch::issue(
        &anchor,
        REALM,
        [claim.leaf(S256).unwrap()],
        now() - 30,
        now() + 86_400,
        Some(&v1),
    )
    .unwrap();
    assert_eq!(v2.retired(), &[gone.leaf(S256).unwrap()]);
    delegation.add(v2.proof(&claim, anchor.public()).unwrap());
    let mut vouches = std::collections::HashMap::new();
    vouches.insert(pin, v2.clone());
    let server = Arc::new(EnrollServer::new(
        keys,
        window_info_of(&anchor),
        delegation.clone(),
    ));
    server.publish(delegation, vec![pin], vouches);
    let dir = Dir::default();
    dir.otps
        .lock()
        .unwrap()
        .insert(HOST.into(), b"Secret123".to_vec());
    let url = spawn(app(server, dir));
    kuipa_tools::net::set_thread_endpoint("window1.example.test", &url);

    let paths = root("retired");
    let mut s = string(&anchor, b"Secret123");
    let otp = s.take_secret().unwrap();
    flows::enroll_online(
        &paths,
        s.realm(),
        &[*s.anchor()],
        &[],
        &[],
        flows::Host {
            fqdn: HOST,
            auth: &Auth::LdapOtp(otp),
        },
        &Deployment::servers(&["window1.example.test".to_owned()]),
    )
    .unwrap();
    let pins = kuipa_tools::paths::read_anchor_pins(&paths.anchors()).unwrap();
    assert_eq!(pins[0].heads, vec![v2.head()], "{pins:?}");
    assert_eq!(pins[0].retired, vec![gone.leaf(S256).unwrap()], "{pins:?}");
    kuipa_tools::net::clear_thread_endpoints();
}
