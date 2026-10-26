//! An interactive kuipa realm: a real MIT KDC (with PKINIT), two IPA
//! servers running the daemon's HTTP router and anchor exchange over a
//! KDC-backed directory, each with its own anchor, pre-made OTP enrollment
//! strings (pinning ipa1's anchor) and an administrator.  A second realm,
//! `B.TEST`, with its own KDC, CA, server and user, is advertised as trusted
//! (§17).  Three more servers ipa1's anchor delegates advertise CA chains of
//! their own — a PEM blob, a KDC certificate as a PKINIT anchor, a Merkle
//! Tree CA — for host `app1` to enroll through ([`chains`]).  Started by
//! `contrib/ci/local-ci.sh interactive`, which drops you into a shell inside
//! it.
//!
//! ```text
//! kuipa-playground run --env-file F [--hosts N]
//!     start the realm; write shell settings to F; serve until SIGINT/SIGTERM
//! kuipa-playground stage --host FQDN (--recipient JWK | --secret) --out FILE
//!     what `ipa host-add --pq-stage` would do, with the admin ticket in
//!     KRB5CCNAME; prints the enrollment string to use with the bundle
//! kuipa-playground passkey [--user PRINCIPAL [--alg ALG]] [--pin PIN | --no-pin]
//!                          [--user-verification on|off]
//!     what `ipa user-add-passkey --register` and `ipa passkeyconfig-mod`
//!     would do, with the software security key $KUIPA_SOFT_FIDO2
//! ```
//!
//! Hardware-bound devices use software stand-ins: a kryoptic PKCS#11 token
//! (`pq_token`) and the software security key `kuipa` is built with for
//! the playground (`soft-fido2`, `pq_passkey`).

#[path = "../tests/support/mod.rs"]
mod support;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use kuipa_enroll::EnrollServer;
use kuipa_enroll::bundle::{Mode, StageParams};
use kuipa_enroll::delegation::Delegation;
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::join::{
    AuthType, KERBEROS_BINDING_LEN, KerberosBinding, Operation, Prepared, Response,
    kerberos_prf_input,
};
use kuipa_enroll::keytab::Enctype;
use kuipa_enroll::realm::{RealmInfo, ServerKeys, VerifiedRealm};
use kuipa_enroll::server::Directory;
use kuipa_enroll::server::parse_stage_result;
use kuipa_enroll::trust::Invitation;
use kuipa_gssapi::GssClientCred;
use kuipa_tools::net::{Endpoint, Trust};
use kuipad::http::{App, router};
use kuipad::keystore::KeyStore;
use kuipad::peers::{KeytabInitiator, Peers, Settings};
use support::directory::KdcDirectory;
use support::kdc::Realm;
use tang_pqc::{ExchangeKeyPair, Policy, SignatureAlg, SigningKey, Thumbprint, b64, unix_seconds};

const REALM: &str = "EXAMPLE.TEST";
const DOMAIN: &str = "example.test";
const SERVERS: [&str; 2] = ["ipa1.example.test", "ipa2.example.test"];
const ADMIN: &str = "admin@EXAMPLE.TEST";
const ADMIN_PASSWORD: &str = "Secret123";
/// The realm's other users, for shared vaults, approvals and deposits
/// (`pq_as`); their password is the administrator's.
const USERS: [&str; 2] = ["bob@EXAMPLE.TEST", "carol@EXAMPLE.TEST"];
const TRUSTED_REALM: &str = "B.TEST";
const TRUSTED_DOMAIN: &str = "b.test";
const TRUSTED_SERVER: &str = "ipa1.b.test";
const TRUSTED_USER: &str = "alice@B.TEST";
/// Servers outside the realm's exchange that advertise CA chains of their
/// own, for the "CA chains" session section ([`chains`]).
const CHAIN_SERVERS: [&str; 3] = [
    "ipa-pem.example.test",
    "ipa-kdccert.example.test",
    "ipa-mtc.example.test",
];

/// The software PKCS#11 token's module (kryoptic).
const TOKEN_MODULE: &str = "/usr/lib64/pkcs11/libkryoptic_pkcs11.so";

type Error = Box<dyn std::error::Error + Send + Sync>;

fn now() -> u64 {
    unix_seconds(SystemTime::now())
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn random_otp() -> Result<String, Error> {
    let mut b = [0u8; 12];
    native_ossl::rand::Rand::fill(&mut b)?;
    Ok(b64::encode(&b))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn run(args: &[String]) -> Result<(), Error> {
    let env_file = PathBuf::from(option(args, "--env-file").ok_or("--env-file is required")?);
    let hosts: usize = option(args, "--hosts").map_or(Ok(5), |h| h.parse())?;

    let realm =
        Arc::new(Realm::start(REALM, "playground").ok_or("the MIT KDC tools are not installed")?);
    // The servers' anchor exchange gets tickets in this process, so the
    // Kerberos library must find this realm's KDC.
    for (k, v) in realm.env() {
        // SAFETY: no other thread exists yet (the runtime starts below).
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(k, v);
        }
    }
    realm.add_user(ADMIN, ADMIN_PASSWORD);
    for user in USERS {
        realm.add_user(user, ADMIN_PASSWORD);
    }
    let dir = realm.dir.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let trusted = Arc::new(
        Realm::start(TRUSTED_REALM, "playground-b").ok_or("the MIT KDC tools are not installed")?,
    );
    trusted.add_user(TRUSTED_USER, ADMIN_PASSWORD);
    let (trusted_anchor, trusted_directory, trusted_url) = start_trusted(&trusted, &rt)?;

    let directory = Arc::new(KdcDirectory::new(realm.clone(), &SERVERS, &[ADMIN]));
    let chain_directory = Arc::new(KdcDirectory::new(realm.clone(), &CHAIN_SERVERS, &[ADMIN]));
    publish_masters(&dir, &directory)?;
    watch_recovery(&dir, &directory);
    watch_passkeys(&dir, &directory);
    configure_policy(&directory);
    seed_secrets(&directory);
    let Started {
        anchor,
        mut endpoints,
        servers,
    } = start_servers(&realm, &directory, &chain_directory, &rt)?;
    endpoints.push(format!("{TRUSTED_SERVER}={trusted_url}"));

    // B.TEST invites EXAMPLE.TEST, and ipa1 establishes the trust: both
    // KDCs get the cross-realm keys from the derived secret, and every
    // EXAMPLE.TEST server publishes B.TEST from the directory (§17.4).
    let invitation = Invitation::new(TRUSTED_REALM, trusted_anchor)?;
    trusted_directory.add_trust_invitation(&invitation.secret_hash()?, now() + 3600)?;
    let shared: Arc<dyn Directory + Send + Sync> = directory.clone();
    let trusted_endpoints =
        std::collections::BTreeMap::from([(TRUSTED_SERVER.to_owned(), trusted_url)]);
    rt.block_on(kuipad::trust::establish(
        &servers[0],
        &invitation,
        &[TRUSTED_SERVER.to_owned()],
        &trusted_endpoints,
        &*shared,
    ))?;
    for server in &servers {
        rt.block_on(kuipad::trust::refresh(
            server,
            &shared,
            &[],
            &trusted_endpoints,
        ));
    }
    println!("trust established: {REALM} trusts {TRUSTED_REALM} and the other way round");
    // Enrollment strings pin ipa1's anchor; every server carries its
    // signature after the exchange.
    std::fs::write(dir.join("anchor"), anchor.to_string())?;

    write_enrollment_strings(&dir, &realm, &directory, &chain_directory, anchor, hosts)?;
    // DNS for both realms, as FreeIPA publishes it: `kuipa enroll` finds
    // the servers without `--server`.
    let srv = |servers: &[&str]| -> Vec<support::dns::Record> {
        servers
            .iter()
            .map(|s| (0, 100, 389, (*s).to_owned()))
            .collect()
    };
    let dns = support::dns::serve(
        [
            (format!("_ldap._tcp.{DOMAIN}"), srv(&SERVERS)),
            (
                format!("_ldap._tcp.{TRUSTED_DOMAIN}"),
                srv(&[TRUSTED_SERVER]),
            ),
        ]
        .into(),
        false,
    );
    let env = shell_settings(&realm, &trusted, &anchor, &endpoints.join(","), dns)?;
    std::fs::write(&env_file, env)?;
    println!("playground realm {REALM} ready in {}", dir.display());

    wait_for_shutdown(&rt)?;
    drop(rt);
    drop(directory);
    drop(realm);
    drop(trusted);
    Ok(())
}

/// Write the initial `cn=masters` state, and watch for changes from
/// `kuipa-playground masters` (the promotion story of §18): a thread
/// applies them to the directory and acknowledges them.
/// `kuipa-playground recovery` (DESIGN-recovery.md §4): a thread applies
/// `recovery.json`, the realm's device-key recovery settings, to the
/// directory, and acknowledges each change in `recovery.ack`.
fn watch_recovery(dir: &Path, directory: &Arc<KdcDirectory>) {
    let watch = directory.clone();
    let path = dir.join("recovery.json");
    let ack = dir.join("recovery.ack");
    std::thread::spawn(move || {
        let mut last = String::new();
        loop {
            if let Ok(text) = std::fs::read_to_string(&path)
                && text != last
                && let Ok(settings) = serde_json::from_str(&text)
            {
                *watch.recovery.lock().unwrap() = settings;
                if std::fs::write(&ack, &text).is_ok() {
                    last = text;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
}

/// `kuipa-playground recovery --vault OWNER/NAME [--required]`: name the
/// realm's device escrow vault, as an administrator would on
/// `cn=recovery,cn=kuipa,cn=etc`.
fn recovery(args: &[String]) -> Result<(), Error> {
    let pg =
        PathBuf::from(std::env::var("KUIPA_PLAYGROUND").map_err(|_| "run inside the playground")?);
    let vault = option(args, "--vault")
        .ok_or("usage: kuipa-playground recovery --vault OWNER/NAME [--required]")?;
    let settings = kuipa_enroll::vault::RecoverySettings {
        device_vault: vault,
        required: args.iter().any(|a| a == "--required"),
    };
    let text = serde_json::to_string_pretty(&Some(&settings))?;
    std::fs::write(pg.join("recovery.json"), &text)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::fs::read_to_string(pg.join("recovery.ack")).is_ok_and(|a| a == text) {
            println!(
                "device keys are deposited in {}{}",
                settings.device_vault,
                if settings.required { " (required)" } else { "" }
            );
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err("the playground did not acknowledge; is it running?".into())
}

/// The users' IPA passkeys and the realm's passkey configuration, as
/// `kuipa-playground passkey` writes them to `passkeys.json`.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PlaygroundPasskeys {
    /// `ipaPassKey` values by principal.
    users: std::collections::BTreeMap<String, Vec<String>>,
    /// `ipaRequireUserVerification`.
    user_verification: bool,
}

/// `kuipa-playground passkey`: a thread applies `passkeys.json` to the
/// directory, and acknowledges each change in `passkeys.ack`.
fn watch_passkeys(dir: &Path, directory: &Arc<KdcDirectory>) {
    let watch = directory.clone();
    let path = dir.join("passkeys.json");
    let ack = dir.join("passkeys.ack");
    std::thread::spawn(move || {
        let mut last = String::new();
        loop {
            if let Ok(text) = std::fs::read_to_string(&path)
                && text != last
                && let Ok(state) = serde_json::from_str::<PlaygroundPasskeys>(&text)
            {
                *watch.passkeys.lock().unwrap() = state.users.into_iter().collect();
                *watch.passkey_uv.lock().unwrap() = state.user_verification;
                if std::fs::write(&ack, &text).is_ok() {
                    last = text;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
}

/// `kuipa-playground passkey [--user PRINCIPAL [--alg ALG]] [--pin PIN |
/// --no-pin] [--user-verification on|off]`: on the software security key
/// `$KUIPA_SOFT_FIDO2`, set or remove the PIN, and make a credential for
/// the realm's domain registered as one of `PRINCIPAL`'s IPA passkeys
/// (`ipa user-add-passkey --register`, ALG `mldsa65` by default); set
/// whether the realm requires user verification (`ipa passkeyconfig-mod
/// --require-user-verification`, on by default).
fn passkey(args: &[String]) -> Result<(), Error> {
    use kuipa_tools::passkey::soft::SoftFido2;
    let pg =
        PathBuf::from(std::env::var("KUIPA_PLAYGROUND").map_err(|_| "run inside the playground")?);
    let path = pg.join("passkeys.json");
    let mut state: PlaygroundPasskeys = match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)?,
        Err(_) => PlaygroundPasskeys {
            user_verification: true,
            ..PlaygroundPasskeys::default()
        },
    };
    let key = || -> Result<SoftFido2, Error> {
        let file = std::env::var_os("KUIPA_SOFT_FIDO2").ok_or(
            "no software security key: $KUIPA_SOFT_FIDO2 (pq_admin_kinit or pq_as set it)",
        )?;
        SoftFido2::open(Path::new(&file))
    };
    if let Some(pin) = option(args, "--pin") {
        key()?.set_pin(Some(&pin))?;
        println!("the security key's PIN is set");
    }
    if args.iter().any(|a| a == "--no-pin") {
        key()?.set_pin(None)?;
        println!("the security key has no PIN");
    }
    if let Some(uv) = option(args, "--user-verification") {
        state.user_verification = uv == "on";
        println!(
            "passkey logins {} user verification (ipa passkeyconfig)",
            if state.user_verification {
                "require"
            } else {
                "do not require"
            }
        );
    }
    if let Some(user) = option(args, "--user") {
        let user = if user.contains('@') {
            user
        } else {
            format!("{user}@{REALM}")
        };
        let name = option(args, "--alg").unwrap_or_else(|| "mldsa65".to_owned());
        let alg = kuipa_enroll::passkey::Algorithm::from_name(&name).ok_or_else(|| {
            format!(
                "unknown algorithm {name}: es256, es384, eddsa, rs256, mldsa44, mldsa65 or mldsa87"
            )
        })?;
        let value = key()?.add_ipa_passkey(DOMAIN, alg)?;
        state.users.entry(user.clone()).or_default().push(value);
        println!("a new {name} passkey on the security key is registered to {user} (ipaPassKey)");
    }
    let text = serde_json::to_string_pretty(&state)?;
    std::fs::write(&path, &text)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::fs::read_to_string(pg.join("passkeys.ack")).is_ok_and(|a| a == text) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err("the playground did not acknowledge; is it running?".into())
}

fn publish_masters(dir: &Path, directory: &Arc<KdcDirectory>) -> Result<(), Error> {
    let initial = serde_json::to_string_pretty(&serde_json::json!({
        "masters": SERVERS,
        "ca": [SERVERS[0]],
    }))?;
    std::fs::write(dir.join("masters.json"), &initial)?;
    let watch = directory.clone();
    let path = dir.join("masters.json");
    let ack = dir.join("masters.ack");
    std::thread::spawn(move || {
        let mut last = String::new();
        loop {
            let applied = std::fs::read_to_string(&path)
                .ok()
                .filter(|text| *text != last)
                .and_then(|text| {
                    serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .map(|state| (text, state))
                })
                .and_then(|(text, state)| {
                    let names = |key: &str| -> Vec<String> {
                        state[key]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|v| v.as_str().map(str::to_owned))
                            .collect()
                    };
                    *watch.masters.lock().unwrap() = names("masters");
                    *watch.ca_masters.lock().unwrap() = names("ca");
                    std::fs::write(&ack, &text).is_ok().then_some(text)
                });
            if let Some(text) = applied {
                last = text;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
    Ok(())
}

/// The playground realm's policy: offline vault sessions, and the release
/// group's signing, with the administrator in it.
fn configure_policy(directory: &KdcDirectory) {
    // The playground realm's limits: every vault needs a device, only
    // the travellers group, the administrator's, may have offline
    // sessions, and the CI administrators, carol, may make vaults that
    // open with a ticket alone, for runners (DESIGN.md §7.6.2,
    // DESIGN-ci.md §2).
    {
        let mut limits = directory.limits.lock().unwrap();
        limits.factors = vec![kuipa_enroll::vault::Factors {
            device: Some(kuipa_enroll::vault::Level::Any),
            ..kuipa_enroll::vault::Factors::default()
        }];
        limits.offline_sessions = false;
        limits.groups = vec![
            kuipa_enroll::vault::GroupLimits {
                group: "travellers".into(),
                priority: 10,
                set: kuipa_enroll::vault::LimitOverrides {
                    offline_sessions: Some(true),
                    ..kuipa_enroll::vault::LimitOverrides::default()
                },
            },
            kuipa_enroll::vault::GroupLimits {
                group: "ci-admins".into(),
                priority: 20,
                set: kuipa_enroll::vault::LimitOverrides {
                    without_device: Some(true),
                    factors: Some(vec![kuipa_enroll::vault::Factors {
                        ticket: true,
                        ..kuipa_enroll::vault::Factors::default()
                    }]),
                    ..kuipa_enroll::vault::LimitOverrides::default()
                },
            },
        ];
    }
    // And let the release group sign blobs (DESIGN-sign.md); the
    // administrator is in it.
    directory.sign_policy.lock().unwrap().purposes.insert(
        "blob".into(),
        kuipa_enroll::sign::Signers {
            groups: vec!["release".into()],
            ..kuipa_enroll::sign::Signers::default()
        },
    );
    directory.sign_policy.lock().unwrap().purposes.insert(
        "git-commit".into(),
        kuipa_enroll::sign::Signers {
            groups: vec!["release".into()],
            ..kuipa_enroll::sign::Signers::default()
        },
    );
    let mut groups = directory.groups.lock().unwrap();
    groups.insert(ADMIN.into(), vec!["release".into(), "travellers".into()]);
    groups.insert(USERS[1].into(), vec!["ci-admins".into()]);
}

/// The secrets the directory serves: ipa1 is the CA and renewal master,
/// holding the material a promoting replica would fetch.
fn seed_secrets(directory: &KdcDirectory) {
    // The secrets transport (§18): ipa1 is the CA and renewal master, as
    // in a fresh IPA deployment, and holds the material a promoting
    // replica would fetch (the DM password hash, the RA agent key, a
    // CA subsystem key and a wrapped LWCA key).  The playground's
    // directory stands in for the handler executables.
    directory
        .ca_masters
        .lock()
        .unwrap()
        .push(SERVERS[0].to_owned());
    {
        let mut secrets = directory.key_secrets.lock().unwrap();
        secrets.insert(
            (kuipa_enroll::keys::Namespace::Dm.id(), "DMHash".into()),
            b"{\"dmhash\":\"{SSHA512}playground-dm-hash\"}".to_vec(),
        );
        secrets.insert(
            (kuipa_enroll::keys::Namespace::Ra.id(), "ipaCert".into()),
            br#"{"export password":"playground","pkcs12 data":"cmVwbGF5Z3JvdW5kLXJhLWFnZW50"}"#
                .to_vec(),
        );
        // The four CA subsystem keys a CA clone fetches, one at a time
        // (`CustodiaInstance.get_ca_keys`).
        for nickname in [
            "caSigningCert cert-pki-ca",
            "ocspSigningCert cert-pki-ca",
            "auditSigningCert cert-pki-ca",
            "subsystemCert cert-pki-ca",
        ] {
            secrets.insert(
                (kuipa_enroll::keys::Namespace::Ca.id(), nickname.into()),
                br#"{"export password":"playground","pkcs12 data":"cGxheWdyb3VuZC1jYS1zaWduaW5n"}"#
                    .to_vec(),
            );
        }
        secrets.insert(
            (
                kuipa_enroll::keys::Namespace::CaWrapped.id(),
                "lwca-signing".into(),
            ),
            br#"{"wrapped_key":"cGxheWdyb3VuZC1sd2Nh","certificate":"-----BEGIN CERTIFICATE-----"}"#
                .to_vec(),
        );
    }
}

/// The OTP enrollment strings for `hosts` hosts, and the realm's plain one,
/// as `ipa host-add --random` would print them.
fn write_enrollment_strings(
    dir: &Path,
    realm: &Realm,
    directory: &KdcDirectory,
    chain_directory: &KdcDirectory,
    anchor: Thumbprint,
    hosts: usize,
) -> Result<(), Error> {
    // OTP enrollment strings, as `ipa host-add --random` would print them;
    // as host-add does, the OTP is also the host's temporary Kerberos key.
    let enroll_dir = dir.join("enroll");
    std::fs::create_dir_all(&enroll_dir)?;
    let mut otps = directory.otps.lock().unwrap();
    for n in 1..=hosts {
        let fqdn = format!("web{n}.{DOMAIN}");
        let otp = random_otp()?;
        let string = EnrollmentString::new(
            REALM,
            anchor,
            now() + 86_400,
            Some(Secret::new(otp.as_bytes())),
        );
        std::fs::write(enroll_dir.join(format!("web{n}")), string.encode().as_ref())?;
        realm.add_user(&format!("host/{fqdn}@{REALM}"), &otp);
        otps.insert(fqdn, otp.into_bytes());
    }
    drop(otps);
    // app1 enrolls through the chain servers (start_chain_servers), which
    // answer from their own directory.
    let mut otps = chain_directory.otps.lock().unwrap();
    let otp = random_otp()?;
    let string = EnrollmentString::new(
        REALM,
        anchor,
        now() + 86_400,
        Some(Secret::new(otp.as_bytes())),
    );
    std::fs::write(enroll_dir.join("app1"), string.encode().as_ref())?;
    realm.add_user(&format!("host/app1.{DOMAIN}@{REALM}"), &otp);
    otps.insert(format!("app1.{DOMAIN}"), otp.into_bytes());
    drop(otps);
    // Without a secret: for the password and ticket paths, and bundles.
    let plain = EnrollmentString::new(REALM, anchor, now() + 86_400, None);
    std::fs::write(enroll_dir.join("realm"), plain.encode().as_ref())?;
    Ok(())
}

/// Block until the process is interrupted or terminated.
fn wait_for_shutdown(rt: &tokio::runtime::Runtime) -> Result<(), Error> {
    rt.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = term.recv() => Ok(()),
        }
    })?;
    Ok(())
}

/// Start the trusted realm's server, with its own anchor, on `rt`.
/// Returns its anchor, its directory and its URL.
fn start_trusted(
    realm: &Arc<Realm>,
    rt: &tokio::runtime::Runtime,
) -> Result<(Thumbprint, Arc<KdcDirectory>, String), Error> {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65)?;
    let signing = SigningKey::generate(SignatureAlg::MlDsa65)?;
    let delegation = Delegation::issue(
        &anchor,
        TRUSTED_REALM,
        TRUSTED_SERVER,
        signing.public(),
        now() - 60,
        now() + 90 * 86400,
    )?;
    let keys = ServerKeys {
        signing,
        join: vec![ExchangeKeyPair::generate_preferred()?],
        escrow: vec![ExchangeKeyPair::generate_preferred()?],
        trust: vec![ExchangeKeyPair::generate_preferred()?],
        vouchers: Vec::new(),
        retired: Vec::new(),
    };
    let info = RealmInfo {
        realm: TRUSTED_REALM.into(),
        domain: TRUSTED_DOMAIN.into(),
        basedn: "dc=b,dc=test".into(),
        server: TRUSTED_SERVER.into(),
        servers: vec![TRUSTED_SERVER.into()],
        ca_certs: vec![realm.chain.ca_der.clone()],
        pkinit_anchors: vec![realm.chain.ca_der.clone()],
        anchors: vec![*anchor.public().thumbprint()],
        heads: Vec::new(),
        trusts: Vec::new(),
        kdc_proxy: None,
    };
    let directory = Arc::new(KdcDirectory::new(realm.clone(), &[TRUSTED_SERVER], &[]));
    let app = Arc::new(App {
        server: Arc::new(EnrollServer::new(keys, info, delegation)),
        directory: directory.clone(),
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        keys: None,
        ledger: None,
    });
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
    let url = format!("http://{}", listener.local_addr()?);
    rt.spawn(async move { axum::serve(listener, router(app)).await });
    Ok((*anchor.public().thumbprint(), directory, url))
}

/// The servers' rate limiter.  Every request of the scripted session comes
/// from 127.0.0.1, much faster than a person types: only the per-address
/// allowance is raised.
fn session_limiter() -> kuipad::limit::Limiter {
    kuipad::limit::Limiter::new(kuipad::limit::Limits {
        per_source: kuipad::limit::Rate {
            burst: 600.0,
            per_minute: 600.0,
        },
        ..kuipad::limit::Limits::default()
    })
}

/// Start every server on `rt`, each with its own anchor, and wait for the
/// anchor exchange.
/// A listener for each of [`SERVERS`], their URLs, and their
/// `KUIPA_ENDPOINTS` entries.
struct Listening {
    listeners: Vec<tokio::net::TcpListener>,
    urls: Vec<String>,
    endpoints: Vec<String>,
}

fn listen(rt: &tokio::runtime::Runtime) -> Result<Listening, Error> {
    let mut listeners = Vec::new();
    let mut urls = Vec::new();
    for _ in SERVERS {
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
        urls.push(format!("http://{}", listener.local_addr()?));
        listeners.push(listener);
    }
    let endpoints = SERVERS
        .iter()
        .zip(&urls)
        .map(|(s, u)| format!("{s}={u}"))
        .collect();
    Ok(Listening {
        listeners,
        urls,
        endpoints,
    })
}

fn start_servers(
    realm: &Arc<Realm>,
    directory: &Arc<KdcDirectory>,
    chain_directory: &Arc<KdcDirectory>,
    rt: &tokio::runtime::Runtime,
) -> Result<Started, Error> {
    let dir = &realm.dir;
    let Listening {
        listeners,
        urls,
        mut endpoints,
    } = listen(rt)?;

    let (voucher_key, witness) = (start_issuer(dir)?, start_witness(dir)?);

    // Each server has its own anchor and exchanges it with the other.
    let mut anchors = Vec::new();
    let mut servers = Vec::new();
    for (i, (server, listener)) in SERVERS.iter().zip(listeners).enumerate() {
        let anchor = SigningKey::generate(SignatureAlg::MlDsa65)?;
        let signing = SigningKey::generate(SignatureAlg::MlDsa65)?;
        let delegation = Delegation::issue(
            &anchor,
            REALM,
            server,
            signing.public(),
            now() - 60,
            now() + 90 * 86400,
        )?;
        let keys = ServerKeys {
            signing,
            join: vec![ExchangeKeyPair::generate_preferred()?],
            escrow: vec![ExchangeKeyPair::generate_preferred()?],
            trust: Vec::new(),
            vouchers: vec![voucher_key.clone()],
            retired: Vec::new(),
        };
        let info = RealmInfo {
            realm: REALM.into(),
            domain: DOMAIN.into(),
            basedn: "dc=example,dc=test".into(),
            server: (*server).into(),
            servers: SERVERS.iter().map(|s| (*s).to_owned()).collect(),
            ca_certs: vec![realm.chain.ca_der.clone()],
            pkinit_anchors: vec![realm.chain.ca_der.clone()],
            anchors: vec![*anchor.public().thumbprint()],
            heads: Vec::new(),
            trusts: Vec::new(),
            kdc_proxy: None,
        };
        anchors.push(*anchor.public().thumbprint());
        let key_dir = dir.join(format!("keys-{server}"));
        let ledger = start_ledger(&key_dir, server, &keys.signing, &witness)?;
        let enroll =
            Arc::new(EnrollServer::new(keys, info, delegation).with_ledger(ledger.clone()));
        let others: Vec<usize> = (0..SERVERS.len()).filter(|j| *j != i).collect();
        let settings = Settings {
            me: (*server).into(),
            realm: REALM.into(),
            peers: others.iter().map(|j| SERVERS[*j].to_owned()).collect(),
            discover: false,
            endpoints: others
                .iter()
                .map(|j| (SERVERS[*j].to_owned(), urls[*j].clone()))
                .collect(),
            interval: Duration::from_secs(2),
            ca_certs: vec![realm.chain.ca_der.clone()],
            vouch_interval: Duration::ZERO,
        };
        if i == 0 {
            endpoints.extend(start_chain_servers(&anchor, realm, chain_directory, rt)?);
        }
        let tang = start_tang(dir, server, &key_dir, &urls[i])?;
        let initiator = Arc::new(KeytabInitiator::new(
            dir.join(format!("kuipa-{server}.keytab"))
                .display()
                .to_string(),
            format!("ipa-ku/{server}@{REALM}"),
        ));
        let peers = Peers::new(
            settings,
            Some(anchor),
            enroll.clone(),
            directory.clone(),
            initiator,
            KeyStore::new(key_dir),
        )?;
        let app = Arc::new(App {
            server: enroll.clone(),
            directory: directory.clone(),
            peers: Some(peers.clone()),
            limiter: session_limiter(),
            tang,
            keys: None,
            ledger: Some(ledger),
        });
        rt.spawn(peers.run());
        rt.spawn(async move { axum::serve(listener, router(app)).await });
        servers.push(enroll);
    }
    wait_for_exchange(&servers)?;
    Ok(Started {
        anchor: anchors[0],
        endpoints,
        servers,
    })
}

/// A server [`start_chain_servers`] runs, and the chain it advertises.
struct Chain {
    server: &'static str,
    ca_certs: Vec<Vec<u8>>,
    pkinit_anchors: Vec<Vec<u8>>,
}

/// The CA chains [`start_chain_servers`] advertise, from the realm's CA
/// (DER) and KDC certificate.
fn chains(ca: &[u8], kdc: &[u8]) -> [Chain; 3] {
    let mtc_ca =
        synta_certificate::pem_to_der(include_bytes!("../tests/data/mtc-demo-ca.pem")).remove(0);
    [
        // The CA certificate pasted as PEM where DER belongs: no certificate.
        Chain {
            server: CHAIN_SERVERS[0],
            ca_certs: vec![
                ca.to_vec(),
                synta_certificate::der_to_pem("CERTIFICATE", ca),
            ],
            pkinit_anchors: vec![ca.to_vec()],
        },
        // The KDC's own certificate as a PKINIT anchor: an end entity.
        Chain {
            server: CHAIN_SERVERS[1],
            ca_certs: vec![ca.to_vec()],
            pkinit_anchors: vec![ca.to_vec(), kdc.to_vec()],
        },
        // A sound chain that includes a Merkle Tree CA (the IETF demo's,
        // unsigned): a CA by its critical Merkle Tree CA extension.
        Chain {
            server: CHAIN_SERVERS[2],
            ca_certs: vec![ca.to_vec(), mtc_ca],
            pkinit_anchors: vec![ca.to_vec()],
        },
    ]
}

/// Servers that `anchor` (ipa1's) delegates, outside the anchor exchange,
/// each advertising a CA chain of its own ([`chains`]): what the "CA chains"
/// session section enrolls `app1` through.  A client verifies them as it
/// would any server of the realm, so what it refuses there is the chain,
/// not the server.  They answer from `directory`, their own over the realm's
/// KDC (their principals and acceptor keys; `app1`'s OTP), so the realm's
/// own servers and their list stay as they are.  Returns their
/// `KUIPA_ENDPOINTS` entries.
fn start_chain_servers(
    anchor: &SigningKey,
    realm: &Arc<Realm>,
    directory: &Arc<KdcDirectory>,
    rt: &tokio::runtime::Runtime,
) -> Result<Vec<String>, Error> {
    let mut endpoints = Vec::new();
    for Chain {
        server,
        ca_certs,
        pkinit_anchors,
    } in chains(&realm.chain.ca_der, &realm.chain.kdc_der)
    {
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
        endpoints.push(format!("{server}=http://{}", listener.local_addr()?));
        let signing = SigningKey::generate(SignatureAlg::MlDsa65)?;
        let delegation = Delegation::issue(
            anchor,
            REALM,
            server,
            signing.public(),
            now() - 60,
            now() + 90 * 86400,
        )?;
        let keys = ServerKeys {
            signing,
            join: vec![ExchangeKeyPair::generate_preferred()?],
            escrow: vec![ExchangeKeyPair::generate_preferred()?],
            trust: Vec::new(),
            vouchers: Vec::new(),
            retired: Vec::new(),
        };
        let info = RealmInfo {
            realm: REALM.into(),
            domain: DOMAIN.into(),
            basedn: "dc=example,dc=test".into(),
            server: server.into(),
            servers: vec![server.into()],
            ca_certs,
            pkinit_anchors,
            anchors: vec![*anchor.public().thumbprint()],
            heads: Vec::new(),
            trusts: Vec::new(),
            kdc_proxy: None,
        };
        let enroll = Arc::new(EnrollServer::new(keys, info, delegation.clone()));
        enroll.publish(
            delegation,
            vec![*anchor.public().thumbprint()],
            std::collections::HashMap::new(),
        );
        let app = Arc::new(App {
            server: enroll,
            directory: directory.clone(),
            peers: None,
            limiter: kuipad::limit::Limiter::default(),
            tang: None,
            keys: None,
            ledger: None,
        });
        rt.spawn(async move { axum::serve(listener, router(app)).await });
    }
    Ok(endpoints)
}

/// A transparency-log witness (DESIGN-tlog.md §4) in
/// `$KUIPA_PLAYGROUND/witness`: its private key (`witness.jwk`, for
/// `kuipa-witness`) and public key (`witness.pub.jwk`, for audits);
/// returns the key every server trusts.
fn start_witness(dir: &Path) -> Result<tang_pqc::VerifyingKey, Error> {
    let witness = dir.join("witness");
    std::fs::create_dir_all(&witness)?;
    let key = SigningKey::generate(SignatureAlg::MlDsa44)?;
    kuipa_tools::paths::write_file(&witness.join("witness.jwk"), key.to_jwk()?.as_ref(), 0o600)?;
    std::fs::write(witness.join("witness.pub.jwk"), key.public().to_jwk_json())?;
    Ok(key.public().clone())
}

/// `server`'s transparency log, as kuipad keeps it, trusting `witness`;
/// opening it creates the key directory.
fn start_ledger(
    key_dir: &Path,
    server: &str,
    signing: &tang_pqc::SigningKey,
    witness: &tang_pqc::VerifyingKey,
) -> Result<Arc<kuipad::ledger::FileLedger>, Error> {
    let alg = kuipa_enroll::merkle::TreeHash::for_signer(signing.public().alg());
    // Every event is published at once, so the session's watches see
    // what its steps just did; a real server publishes a head an hour
    // (`tlog_head_interval`).
    Ok(Arc::new(
        kuipad::ledger::FileLedger::open(key_dir, REALM, server, alg)?
            .with_head_interval(std::time::Duration::ZERO)
            .with_witnesses(vec![witness.clone()]),
    ))
}

/// A voucher issuer (§9) in `$KUIPA_PLAYGROUND/voucher`, with a quota of
/// 100; returns the key every server accepts.
fn start_issuer(dir: &Path) -> Result<tang_pqc::VerifyingKey, Error> {
    let vouchers = dir.join("voucher");
    std::fs::create_dir_all(&vouchers)?;
    let issuer = kuipa_tools::voucher::keygen(&vouchers.join("issuer.pem"), SignatureAlg::MlDsa65)?;
    std::fs::write(vouchers.join("issuer.jwk"), &issuer)?;
    kuipa_tools::voucher::set_quota(&vouchers.join("quota.json"), 100)?;
    Ok(tang_pqc::VerifyingKey::from_jwk_json(issuer.as_bytes())?)
}

/// Tang keys for `server` (DESIGN §11.5); its URL and pinned thumbprint go
/// to `$KUIPA_PLAYGROUND/tang/`.
fn start_tang(
    dir: &Path,
    server: &str,
    key_dir: &Path,
    url: &str,
) -> Result<Option<Arc<kuipad::tang::Tang>>, Error> {
    let keys = kuipad::tang::TangKeys::new(key_dir);
    let thp = keys.generate()?;
    let tang_dir = dir.join("tang");
    std::fs::create_dir_all(&tang_dir)?;
    std::fs::write(tang_dir.join(format!("{server}.thp")), format!("{thp}\n"))?;
    std::fs::write(
        tang_dir.join(format!("{server}.url")),
        format!("{url}/ipa/ku/tang\n"),
    )?;
    Ok(keys.server()?.map(Arc::new))
}

/// Wait until every server trusts every server's anchor.
fn wait_for_exchange(servers: &[Arc<EnrollServer>]) -> Result<(), Error> {
    let start = Instant::now();
    while !servers.iter().all(|s| s.anchors().len() == SERVERS.len()) {
        if start.elapsed() > Duration::from_secs(60) {
            return Err("the servers did not exchange their anchors".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    println!(
        "anchor exchange done: every server trusts {} anchors",
        SERVERS.len()
    );
    Ok(())
}

/// What [`start_servers`] started.
struct Started {
    /// ipa1's anchor.
    anchor: Thumbprint,
    /// The `KUIPA_ENDPOINTS` entries.
    endpoints: Vec<String>,
    servers: Vec<Arc<EnrollServer>>,
}

/// The playground shell's settings: the realm's environment, the server
/// endpoints, and helper functions.
fn shell_settings(
    realm: &Realm,
    trusted: &Realm,
    anchor: &Thumbprint,
    endpoints: &str,
    dns: std::net::SocketAddr,
) -> Result<String, Error> {
    let dir = &realm.dir;
    let mut env = String::new();
    for (k, v) in realm.env() {
        writeln!(env, "export {k}={}", shell_quote(&v))?;
    }
    let server_args = SERVERS
        .iter()
        .map(|s| format!("--server {s}"))
        .collect::<Vec<_>>()
        .join(" ");
    write!(
        env,
        r#"export KRB5CCNAME={ccache}
export KUIPA_PLAYGROUND={dir}
export KUIPA_ENDPOINTS={endpoints}
# The playground's DNS: SRV records for both realms' servers.
export KUIPA_DNS={dns}
export KUIPA_PG_ENDPOINTS="$KUIPA_ENDPOINTS"
export PQ_SERVERS={servers}
export PQ_ANCHOR={anchor}
export PQ_KDC_SOCKET={socket}
# The KDC for the armoured exchanges of password and OTP joins.
export KUIPA_KDC={socket}
export PQ_TRUSTED_REALM={trusted_realm}
export PQ_TRUSTED_KDC_SOCKET={trusted_socket}
# The realm's enrollment string without a secret: realm-info, ticket and
# password joins and bundles find it without anything typed.
export KUIPA_ENROLLMENT_FILE="$KUIPA_PLAYGROUND/enroll/realm"
# A software PKCS#11 token (kryoptic) for hardware-bound device keys:
# pq_token makes ML-KEM keys on it.
export KRYOPTIC_CONF="$KUIPA_PLAYGROUND/token/kryoptic.conf"
export PQ_TOKEN_MODULE={token_module}
"#,
        ccache = shell_quote(&format!("FILE:{}", dir.join("admin.ccache").display())),
        dir = shell_quote(&dir.display().to_string()),
        endpoints = shell_quote(endpoints),
        servers = shell_quote(&server_args),
        anchor = shell_quote(&anchor.to_string()),
        socket = shell_quote(&realm.socket.display().to_string()),
        trusted_realm = TRUSTED_REALM,
        trusted_socket = shell_quote(&trusted.socket.display().to_string()),
        dns = dns,
        token_module = shell_quote(TOKEN_MODULE),
    )?;
    let token = dir.join("token");
    std::fs::create_dir_all(&token)?;
    std::fs::write(
        token.join("kryoptic.conf"),
        format!(
            "[[slots]]\nslot = 42\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n",
            token.join("token.sql").display()
        ),
    )?;
    shell_functions(&mut env)?;
    Ok(env)
}

/// The playground shell's functions: the `pq_*` helpers for hosts, enrollment
/// and bootstrap.
fn shell_functions(env: &mut String) -> Result<(), Error> {
    write!(
        env,
        r#"# pq_host NAME: act as host NAME.{DOMAIN} (its own KUIPA_ROOT).
pq_host() {{
    export PQ_HOST="$1.{DOMAIN}"
    export KUIPA_ROOT="$KUIPA_PLAYGROUND/hosts/$1"
    mkdir -p "$KUIPA_ROOT"
    PS1="[kuipa $1] \W \$ "
}}
# pq_down SERVER / pq_up: make a server unreachable for this shell, and back.
pq_down() {{
    local fqdn="$1"
    case "$fqdn" in *.*) ;; *) fqdn="$fqdn.{DOMAIN}" ;; esac
    export KUIPA_ENDPOINTS="$(printf '%s' "$KUIPA_ENDPOINTS" | tr ',' '\n' \
        | sed "s|^$fqdn=.*|$fqdn=http://127.0.0.1:9|" | paste -sd, -)"
    echo "$fqdn is now unreachable from this shell (pq_up restores it)"
}}
pq_up() {{ export KUIPA_ENDPOINTS="$KUIPA_PG_ENDPOINTS"; }}
# pq_bootstrap: what ipa-client-install does before an armoured kinit —
# realm-info from the verified advertisement, anonymous PKINIT with the
# advertised anchors, then kinit -T for the administrator.  (The generated
# krb5.conf names KDCs by FQDN; this KDC listens on a Unix socket.)
pq_bootstrap() {{
    local d="$KUIPA_PLAYGROUND/bootstrap"
    kuipa realm-info $PQ_SERVERS --krb5-dir "$d" || return
    sed "s|kdc = [^ ]*:88|kdc = $PQ_KDC_SOCKET|; s|master_kdc = [^ ]*:88|master_kdc = $PQ_KDC_SOCKET|" "$d/krb5.conf" > "$d/krb5.conf.new" || return
    mv "$d/krb5.conf.new" "$d/krb5.conf"
    KRB5_CONFIG="$d/krb5.conf" kinit -n -c "$d/armor.ccache" @{REALM} || return
    echo "anonymous PKINIT armour obtained with the advertised anchors"
    echo {ADMIN_PASSWORD} | KRB5_CONFIG="$d/krb5.conf" kinit -T "$d/armor.ccache" {ADMIN} >/dev/null || return
    echo "admin ticket obtained through the armoured exchange"
    klist
}}
# pq_password NAME: enroll NAME with the administrator's password, sealed in
# the PQ channel (the `ipa-client-install -p admin -w` habit).
pq_password() {{
    local name="$1"; shift
    pq_host "$name"
    echo {ADMIN_PASSWORD} | kuipa enroll $PQ_SERVERS --hostname "$PQ_HOST" --principal {ADMIN} "$@"
}}
# pq_offline NAME: prepare NAME, stage it with an admin ticket (what
# `ipa host-add --pq-stage` does), and enroll it offline from the bundle.
pq_offline() {{
    pq_host "$1"
    kuipa prepare --hostname "$PQ_HOST" || return
    echo {ADMIN_PASSWORD} | kinit {ADMIN} >/dev/null || return
    kuipa-playground stage --host "$PQ_HOST" --out "$KUIPA_ROOT/bundle" \
        --recipient "$KUIPA_ROOT/var/lib/ipa-client/ku/recipient.pub.jwk" || return
    kuipa enroll --bundle "$KUIPA_ROOT/bundle" --hostname "$PQ_HOST" \
        --enrollment-file "$KUIPA_PLAYGROUND/enroll/realm"
}}
"#,
    )?;
    shell_trust_functions(env)
}

/// The `pq_*` helpers for trust and the administrator's login.
fn shell_trust_functions(env: &mut String) -> Result<(), Error> {
    write!(
        env,
        r#"# pq_trust: install the realms this host's realm trusts ({TRUSTED_REALM}):
# their anchors, PKINIT chain and KDCs, verified through {REALM}.
# pq_admin_kinit: log in as the administrator, with a kuipa data directory
# of their own, for `kuipa seal`.
pq_admin_kinit() {{
    echo {ADMIN_PASSWORD} | kinit {ADMIN} >/dev/null || return
    export KUIPA_USER_DIR="$KUIPA_PLAYGROUND/users/admin"
    # Sessions stay inside the playground, not in the real runtime directory.
    export KUIPA_RUNTIME_DIR="$KUIPA_PLAYGROUND/run-user/admin"
    # The administrator's security key: the playground's software one.
    export KUIPA_SOFT_FIDO2="$KUIPA_PLAYGROUND/users/admin.fido2.json"
    klist
}}
# pq_as USER CMD...: run CMD as USER of this realm (bob or carol), with a
# ticket and a kuipa data directory of their own; logs them in the first
# time.
pq_as() {{
    local user="$1"
    shift
    local cc="$KUIPA_PLAYGROUND/users/$user.ccache"
    mkdir -p "$KUIPA_PLAYGROUND/users"
    [ -f "$cc" ] || echo {ADMIN_PASSWORD} | KRB5CCNAME="FILE:$cc" kinit "$user@{REALM}" >/dev/null || return
    KRB5CCNAME="FILE:$cc" KUIPA_USER_DIR="$KUIPA_PLAYGROUND/users/$user" \
        KUIPA_RUNTIME_DIR="$KUIPA_PLAYGROUND/run-user/$user" \
        KUIPA_SOFT_FIDO2="$KUIPA_PLAYGROUND/users/$user.fido2.json" "$@"
}}
# pq_passkey [ALG] [--pin PIN]: register a new IPA passkey (ALG mldsa65 by
# default; es256, es384, eddsa, rs256, mldsa44, mldsa87) on the logged-in
# user's software security key, as `ipa user-add-passkey --register` does;
# with --pin, set the key's PIN first.  pq_as USER pq_passkey for others.
pq_passkey() {{
    local alg=mldsa65 pin=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --pin) pin=(--pin "$2"); shift 2 ;;
            *) alg="$1"; shift ;;
        esac
    done
    local me
    me=$(klist 2>/dev/null | sed -n 's/^Default principal: //p')
    [ -n "$me" ] || {{ echo "nobody logged in: pq_admin_kinit first"; return 1; }}
    kuipa-playground passkey "${{pin[@]}}" --user "$me" --alg "$alg"
}}
# pq_token LABEL: make an ML-KEM-768 key LABEL on the playground's software
# PKCS#11 token (kryoptic; label kuipa, PIN 1234) and print its URI, for
# `kuipa seal device add VAULT --pkcs11 URI --module $PQ_TOKEN_MODULE`.
pq_token() {{
    local label="${{1:?usage: pq_token LABEL}}"
    [ -f "$PQ_TOKEN_MODULE" ] || {{ echo "no software token: install kryoptic"; return 1; }}
    local t=(pkcs11-tool --module "$PQ_TOKEN_MODULE")
    if [ ! -f "$KUIPA_PLAYGROUND/token/initialized" ]; then
        "${{t[@]}}" --init-token --label kuipa --so-pin 12345678 >/dev/null || return
        "${{t[@]}}" --token-label kuipa --login --so-pin 12345678 --init-pin --pin 1234 >/dev/null || return
        : > "$KUIPA_PLAYGROUND/token/initialized"
    fi
    "${{t[@]}}" --token-label kuipa --login --pin 1234 --keypairgen --key-type ML-KEM-768 \
        --label "$label" --id "$(printf '%s' "$label" | od -An -tx1 | tr -d ' \n')" >/dev/null || return
    echo "pkcs11:token=kuipa;object=$label"
}}
pq_trust() {{ kuipa trusted-realms "$@"; }}
"#,
    )?;
    shell_login_functions(env)
}

/// The `pq_*` helpers for logins in the trusted realm.
fn shell_login_functions(env: &mut String) -> Result<(), Error> {
    write!(
        env,
        r#"# pq_trusted_kinit [USER]: log in a user of {TRUSTED_REALM} on this host
# (default {TRUSTED_USER}; a bare name is taken as USER@{TRUSTED_REALM}):
# anonymous PKINIT armour from {TRUSTED_REALM}'s KDC with the chain kuipa
# installed, then an armoured kinit.  The ticket and the configuration (the
# realm's, plus the installed snippet with that KDC's socket instead of its
# FQDN) stay in $KUIPA_ROOT/trusted-login; use them with pq_trusted.
pq_trusted_kinit() {{
    local principal="${{1:-{TRUSTED_USER}}}"
    case "$principal" in *@*) ;; *) principal="$principal@{TRUSTED_REALM}" ;; esac
    local snippet="$KUIPA_ROOT/etc/krb5.conf.d/kuipa_trust_{trusted_file}"
    [ -f "$snippet" ] || {{ echo "no {TRUSTED_REALM} configuration on this host: run pq_trust"; return 1; }}
    local d="$KUIPA_ROOT/trusted-login"
    mkdir -p "$d"
    sed "s|kdc = [^ ]*:88|kdc = $PQ_TRUSTED_KDC_SOCKET|; s|master_kdc = [^ ]*:88|master_kdc = $PQ_TRUSTED_KDC_SOCKET|" "$snippet" > "$d/krb5.conf"
    local conf="$KRB5_CONFIG:$d/krb5.conf"
    printf '%s\n' "$conf" > "$d/config"
    KRB5_CONFIG="$conf" kinit -n -c "$d/armor.ccache" @{TRUSTED_REALM} || return
    echo "anonymous PKINIT armour from {TRUSTED_REALM}'s KDC, with the PKINIT chain kuipa installed"
    echo {ADMIN_PASSWORD} | KRB5_CONFIG="$conf" kinit -T "$d/armor.ccache" -c "$d/user.ccache" "$principal" >/dev/null || return
    echo "$principal logged in through the armoured exchange; try: pq_trusted kvno host/$PQ_HOST"
}}
# pq_trusted CMD...: run CMD as the user pq_trusted_kinit logged in, e.g.
# `pq_trusted klist` or `pq_trusted kvno host/$PQ_HOST` (a ticket for this
# {REALM} host, over the cross-realm trust).
pq_trusted() {{
    local d="$KUIPA_ROOT/trusted-login"
    [ -f "$d/user.ccache" ] || {{ echo "nobody logged in: run pq_trusted_kinit"; return 1; }}
    KRB5_CONFIG="$(cat "$d/config")" KRB5CCNAME="FILE:$d/user.ccache" "$@"
}}
"#,
        trusted_file = TRUSTED_REALM.replace('.', "_"),
    )?;
    shell_enroll_functions(env)
}

/// The `pq_*` helpers for enrolling and promoting hosts, and vouchers.
fn shell_enroll_functions(env: &mut String) -> Result<(), Error> {
    write!(
        env,
        r#"# pq_enroll NAME [kuipa enroll options]: enroll NAME with its OTP string.
pq_enroll() {{
    local name="$1"; shift
    pq_host "$name"
    kuipa enroll $PQ_SERVERS --hostname "$PQ_HOST" --enrollment-file "$KUIPA_PLAYGROUND/enroll/$name" "$@"
}}
# pq_tang [SERVER]: the tang-pqc pin configuration for SERVER's Tang
# service (default ipa1), e.g.
#   echo secret | tang-pqc encrypt "$(pq_tang)" > s.jwe; tang-pqc decrypt < s.jwe
pq_tang() {{
    local s="${{1:-ipa1}}"
    case "$s" in *.*) ;; *) s="$s.{DOMAIN}" ;; esac
    printf '{{"url":"%s","thp":"%s"}}\n' "$(cat "$KUIPA_PLAYGROUND/tang/$s.url")" \
        "$(cat "$KUIPA_PLAYGROUND/tang/$s.thp")"
}}
# pq_promote NAME: imitate a replica promotion's secret fetches (§18):
# the DM password hash, the RA agent key and the CA subsystem keys a
# promoting CA replica receives from a peer, with kuipa keys fetch.
# With --ca-less, only the fetches every replica makes (dm, ra).
pq_promote() {{
    local name="$1"; shift
    pq_host "$name"
    local d="$KUIPA_ROOT/promotion"; mkdir -p "$d"
    # The steps before this one already fetched some of it: a promotion
    # idempotently re-fetches what it does not have.
    [ -f "$d/dmhash" ] || kuipa keys fetch dm/DMHash --out "$d/dmhash" || return
    [ -f "$d/ra-agent.p12" ] || kuipa keys fetch ra/ipaCert --out "$d/ra-agent.p12" || return
    case " $* " in *" --ca-less "*) return 0;; esac
    for nickname in "caSigningCert cert-pki-ca" "ocspSigningCert cert-pki-ca" \
                    "auditSigningCert cert-pki-ca" "subsystemCert cert-pki-ca"; do
        [ -f "$d/$nickname.p12" ] || kuipa keys fetch "ca/$nickname" --out "$d/$nickname.p12" || return
    done
    echo "promotion material fetched into $d"
}}
# pq_voucher NAME [--bound] [--hostgroup G] [--lease-hours N] [kuipa enroll
# options]: enroll a new host NAME with a voucher in host group G
# (webservers): blind it, have the issuer ($KUIPA_PLAYGROUND/voucher,
# quota 100) sign it, unblind it, enroll.  With --bound, the voucher works
# only with the host's ephemeral key; with --lease-hours, the host lives
# that long.
pq_voucher() {{
    local name="$1"; shift
    pq_host "$name"
    local v="$KUIPA_PLAYGROUND/voucher" eph="$KUIPA_ROOT/voucher-ephemeral.jwk"
    local bind=() key=() lease=() group=webservers
    while :; do
        case "${{1-}}" in
            --bound)
                shift
                rm -f "$eph"
                local b
                b=$(kuipa voucher-key --out "$eph" --json | sed 's/.*"binding":"\([^"]*\)".*/\1/')
                bind=("--binding=$b") key=("--ephemeral-key=$eph") ;;
            --hostgroup) group="$2"; shift 2 ;;
            --lease-hours) lease=("--lease-hours=$2"); shift 2 ;;
            *) break ;;
        esac
    done
    kuipa-voucher request --public "$v/issuer.jwk" --realm {REALM} --fqdn "$PQ_HOST" \
        --hostgroup "$group" "${{bind[@]}}" "${{lease[@]}}" --state "$v/$name.state" \
        | kuipa-voucher sign --key "$v/issuer.pem" --quota "$v/quota.json" \
        | kuipa-voucher finish --state "$v/$name.state" > "$v/$name.voucher" || return
    kuipa-voucher show < "$v/$name.voucher"
    kuipa enroll $PQ_SERVERS --hostname "$PQ_HOST" --enrollment-file "$KUIPA_PLAYGROUND/enroll/realm" \
        --voucher-file "$v/$name.voucher" "${{key[@]}}" "$@"
}}
"#,
    )?;
    Ok(())
}

/// `ipa host-add --pq-stage`, the administrator side of §8.3.
fn stage(args: &[String]) -> Result<(), Error> {
    let host = option(args, "--host").ok_or("--host is required")?;
    let out = PathBuf::from(option(args, "--out").ok_or("--out is required")?);
    let pg =
        PathBuf::from(std::env::var("KUIPA_PLAYGROUND").map_err(|_| "run inside the playground")?);
    let anchor: Thumbprint = std::fs::read_to_string(pg.join("anchor"))?.trim().parse()?;
    let (mode, recipient) = match option(args, "--recipient") {
        Some(path) => (
            Mode::MachineKey,
            Some(tang_pqc::ExchangeKey::from_jwk_json(&std::fs::read(path)?)?),
        ),
        None if args.iter().any(|a| a == "--secret") => (Mode::Secret, None),
        None => return Err("--recipient JWK or --secret is required".into()),
    };
    let hours: u64 = option(args, "--hours").map_or(Ok(24), |h| h.parse())?;

    let endpoint = Endpoint::new(SERVERS[0], &Trust::FirstContact)?;
    let adv = VerifiedRealm::verify(
        &endpoint.advertisement(&[anchor])?,
        REALM,
        &[anchor],
        &Policy::default(),
        SystemTime::now(),
    )?;
    let admin = GssClientCred::ambient()
        .map_err(|e| format!("no admin ticket ({e}); run: kinit {ADMIN}"))?;
    let p = Prepared::new(
        &adv,
        Operation::Stage,
        &host,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )?;
    let cb = p.channel_binding()?;
    let (token, derived) = kuipa_gssapi::init_bound(
        &admin,
        &format!("ipa-ku@{}", adv.server()),
        &cb,
        &kerberos_prf_input(&cb),
        KERBEROS_BINDING_LEN,
    )?;
    let params = StageParams {
        mode,
        recipient,
        not_after: now() + hours * 3600,
    };
    let (request, pending) =
        p.with_kerberos(KerberosBinding::new(&derived)?)
            .seal(&token, &[], &params.to_bytes())?;
    let body = endpoint.post(&format!("stage/{}", request.kid()), request.to_bytes())?;
    let payload = pending.open(&Response::from_bytes(&body)?)?;
    let (bundle, secret) = parse_stage_result(payload.as_ref())?;
    std::fs::write(&out, bundle.to_bytes())?;
    let string = EnrollmentString::new(REALM, anchor, now() + 86_400, secret);
    println!("bundle for {host} written to {}", out.display());
    println!(
        "enrollment string: {}",
        String::from_utf8_lossy(string.encode().as_ref())
    );
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("stage") => stage(&args[1..]),
        Some("masters") => masters(&args[1..]),
        Some("recovery") => recovery(&args[1..]),
        Some("passkey") => passkey(&args[1..]),
        _ => Err("usage: kuipa-playground {run --env-file F [--hosts N] | stage --host FQDN (--recipient JWK | --secret) --out FILE}".into()),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kuipa-playground: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// `kuipa-playground masters [--add FQDN] [--remove FQDN] [--ca FQDN]`:
/// edit the modelled `cn=masters` list and CA roles, the way a replica
/// promotion adds the promoting host and `ipa-ca-install` records the CA
/// role.  The running playground applies the change and acknowledges it
/// in `masters.ack`; this waits for that, so the next command sees it.
fn masters(args: &[String]) -> Result<(), Error> {
    let pg =
        PathBuf::from(std::env::var("KUIPA_PLAYGROUND").map_err(|_| "run inside the playground")?);
    let path = pg.join("masters.json");
    let mut state: std::collections::BTreeMap<String, Vec<String>> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mut add: Option<String> = None;
    let mut remove: Option<String> = None;
    let mut ca: Option<String> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--add" => add = it.next().cloned(),
            "--remove" => remove = it.next().cloned(),
            "--ca" => ca = it.next().cloned(),
            _ => return Err(format!("unknown option: {arg}").into()),
        }
    }
    if let Some(fqdn) = add {
        state
            .entry("masters".into())
            .or_default()
            .push(fqdn.clone());
        println!("{fqdn} joined cn=masters (promotion)");
    }
    if let Some(fqdn) = remove {
        if let Some(list) = state.get_mut("masters") {
            list.retain(|s| *s != fqdn);
        }
        println!("{fqdn} left cn=masters (ipa-server-del)");
    }
    if let Some(fqdn) = ca {
        state.entry("ca".into()).or_default().push(fqdn.clone());
        println!("{fqdn} has the CA role (ipa-ca-install)");
    }
    std::fs::write(&path, serde_json::to_string_pretty(&state)?)?;
    let written = std::fs::read_to_string(&path)?;
    let ack = pg.join("masters.ack");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::fs::read_to_string(&ack).is_ok_and(|a| a == written) {
            println!("the playground applied the change");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    eprintln!("kuipa-playground: the playground did not acknowledge; is it running?");
    Ok(())
}
