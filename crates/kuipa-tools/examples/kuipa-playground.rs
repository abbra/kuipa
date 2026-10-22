//! An interactive kuipa realm: a real MIT KDC (with PKINIT), two IPA
//! servers running the daemon's HTTP router and anchor exchange over a
//! KDC-backed directory, each with its own anchor, pre-made OTP enrollment
//! strings (pinning ipa1's anchor) and an administrator.  A second realm,
//! `B.TEST`, with its own KDC, CA, server and user, is advertised as trusted
//! (§17).  Started by
//! `contrib/ci/local-ci.sh interactive`, which drops you into a shell inside
//! it.
//!
//! ```text
//! kuipa-playground run --env-file F [--hosts N]
//!     start the realm; write shell settings to F; serve until SIGINT/SIGTERM
//! kuipa-playground stage --host FQDN (--recipient JWK | --secret) --out FILE
//!     what `ipa host-add --pq-stage` would do, with the admin ticket in
//!     KRB5CCNAME; prints the enrollment string to use with the bundle
//! ```

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
const TRUSTED_REALM: &str = "B.TEST";
const TRUSTED_DOMAIN: &str = "b.test";
const TRUSTED_SERVER: &str = "ipa1.b.test";
const TRUSTED_USER: &str = "alice@B.TEST";

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

#[allow(clippy::too_many_lines)]
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
    let dir = realm.dir.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let trusted = Arc::new(
        Realm::start(TRUSTED_REALM, "playground-b").ok_or("the MIT KDC tools are not installed")?,
    );
    trusted.add_user(TRUSTED_USER, ADMIN_PASSWORD);
    let (trusted_anchor, trusted_directory, trusted_url) = start_trusted(&trusted, &rt)?;

    let directory = Arc::new(KdcDirectory::new(realm.clone(), &SERVERS, &[ADMIN]));
    // Write the initial `cn=masters` state and watch for changes from
    // `kuipa-playground masters` (the promotion story of §18): a thread
    // applies them to the directory and acknowledges them.
    {
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
    }
    // The playground realm's administrators allow offline vault sessions.
    directory.limits.lock().unwrap().offline_sessions = true;
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
    let Started {
        anchor,
        mut endpoints,
        servers,
    } = start_servers(&realm, &directory, &rt)?;
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
    // Without a secret: for the password and ticket paths, and bundles.
    let plain = EnrollmentString::new(REALM, anchor, now() + 86_400, None);
    std::fs::write(enroll_dir.join("realm"), plain.encode().as_ref())?;

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

    rt.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = term.recv() => Ok(()),
        }
    })?;
    drop(rt);
    drop(directory);
    drop(realm);
    drop(trusted);
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
    };
    let directory = Arc::new(KdcDirectory::new(realm.clone(), &[TRUSTED_SERVER], &[]));
    let app = Arc::new(App {
        server: Arc::new(EnrollServer::new(keys, info, delegation)),
        directory: directory.clone(),
        peers: None,
        limiter: kuipad::limit::Limiter::default(),
        tang: None,
        keys: None,
    });
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
    let url = format!("http://{}", listener.local_addr()?);
    rt.spawn(async move { axum::serve(listener, router(app)).await });
    Ok((*anchor.public().thumbprint(), directory, url))
}

/// Start every server on `rt`, each with its own anchor, and wait for the
/// anchor exchange.
fn start_servers(
    realm: &Arc<Realm>,
    directory: &Arc<KdcDirectory>,
    rt: &tokio::runtime::Runtime,
) -> Result<Started, Error> {
    let dir = &realm.dir;
    let mut listeners = Vec::new();
    let mut urls = Vec::new();
    for _ in SERVERS {
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))?;
        urls.push(format!("http://{}", listener.local_addr()?));
        listeners.push(listener);
    }
    let endpoints: Vec<String> = SERVERS
        .iter()
        .zip(&urls)
        .map(|(s, u)| format!("{s}={u}"))
        .collect();

    let voucher_key = start_issuer(dir)?;

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
        };
        anchors.push(*anchor.public().thumbprint());
        let enroll = Arc::new(EnrollServer::new(keys, info, delegation));
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
        let key_dir = dir.join(format!("keys-{server}"));
        std::fs::create_dir_all(&key_dir)?;
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
            limiter: kuipad::limit::Limiter::default(),
            tang,
            keys: None,
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
#[allow(clippy::too_many_lines)] // nearly all of it is the shell template
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
# pq_host NAME: act as host NAME.{DOMAIN} (its own KUIPA_ROOT).
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
    sed -i "s|kdc = [^ ]*:88|kdc = $PQ_KDC_SOCKET|; s|master_kdc = [^ ]*:88|master_kdc = $PQ_KDC_SOCKET|" "$d/krb5.conf"
    KRB5_CONFIG="$d/krb5.conf" kinit -n -c "$d/armor.ccache" @{realm} || return
    echo "anonymous PKINIT armour obtained with the advertised anchors"
    echo {password} | KRB5_CONFIG="$d/krb5.conf" kinit -T "$d/armor.ccache" {admin} >/dev/null || return
    echo "admin ticket obtained through the armoured exchange"
    klist
}}
# pq_password NAME: enroll NAME with the administrator's password, sealed in
# the PQ channel (the `ipa-client-install -p admin -w` habit).
pq_password() {{
    local name="$1"; shift
    pq_host "$name"
    echo {password} | kuipa enroll $PQ_SERVERS --hostname "$PQ_HOST" --principal {admin} "$@"
}}
# pq_offline NAME: prepare NAME, stage it with an admin ticket (what
# `ipa host-add --pq-stage` does), and enroll it offline from the bundle.
pq_offline() {{
    pq_host "$1"
    kuipa prepare --hostname "$PQ_HOST" || return
    echo {password} | kinit {admin} >/dev/null || return
    kuipa-playground stage --host "$PQ_HOST" --out "$KUIPA_ROOT/bundle" \
        --recipient "$KUIPA_ROOT/var/lib/ipa-client/ku/recipient.pub.jwk" || return
    kuipa enroll --bundle "$KUIPA_ROOT/bundle" --hostname "$PQ_HOST" \
        --enrollment-file "$KUIPA_PLAYGROUND/enroll/realm"
}}
# pq_trust: install the realms this host's realm trusts ({trusted_realm}):
# their anchors, PKINIT chain and KDCs, verified through {realm}.
# pq_admin_kinit: log in as the administrator, with a kuipa data directory
# of their own, for `kuipa seal`.
pq_admin_kinit() {{
    echo {password} | kinit {admin} >/dev/null || return
    export KUIPA_USER_DIR="$KUIPA_PLAYGROUND/users/admin"
    # Sessions stay inside the playground, not in the real runtime directory.
    export KUIPA_RUNTIME_DIR="$KUIPA_PLAYGROUND/run-user/admin"
    klist
}}
pq_trust() {{ kuipa trusted-realms "$@"; }}
# pq_trusted_kinit [USER]: log in a user of {trusted_realm} on this host
# (default {trusted_user}; a bare name is taken as USER@{trusted_realm}):
# anonymous PKINIT armour from {trusted_realm}'s KDC with the chain kuipa
# installed, then an armoured kinit.  The ticket and the configuration (the
# realm's, plus the installed snippet with that KDC's socket instead of its
# FQDN) stay in $KUIPA_ROOT/trusted-login; use them with pq_trusted.
pq_trusted_kinit() {{
    local principal="${{1:-{trusted_user}}}"
    case "$principal" in *@*) ;; *) principal="$principal@{trusted_realm}" ;; esac
    local snippet="$KUIPA_ROOT/etc/krb5.conf.d/kuipa_trust_{trusted_file}"
    [ -f "$snippet" ] || {{ echo "no {trusted_realm} configuration on this host: run pq_trust"; return 1; }}
    local d="$KUIPA_ROOT/trusted-login"
    mkdir -p "$d"
    sed "s|kdc = [^ ]*:88|kdc = $PQ_TRUSTED_KDC_SOCKET|; s|master_kdc = [^ ]*:88|master_kdc = $PQ_TRUSTED_KDC_SOCKET|" "$snippet" > "$d/krb5.conf"
    local conf="$KRB5_CONFIG:$d/krb5.conf"
    printf '%s\n' "$conf" > "$d/config"
    KRB5_CONFIG="$conf" kinit -n -c "$d/armor.ccache" @{trusted_realm} || return
    echo "anonymous PKINIT armour from {trusted_realm}'s KDC, with the PKINIT chain kuipa installed"
    echo {password} | KRB5_CONFIG="$conf" kinit -T "$d/armor.ccache" -c "$d/user.ccache" "$principal" >/dev/null || return
    echo "$principal logged in through the armoured exchange; try: pq_trusted kvno host/$PQ_HOST"
}}
# pq_trusted CMD...: run CMD as the user pq_trusted_kinit logged in, e.g.
# `pq_trusted klist` or `pq_trusted kvno host/$PQ_HOST` (a ticket for this
# {realm} host, over the cross-realm trust).
pq_trusted() {{
    local d="$KUIPA_ROOT/trusted-login"
    [ -f "$d/user.ccache" ] || {{ echo "nobody logged in: run pq_trusted_kinit"; return 1; }}
    KRB5_CONFIG="$(cat "$d/config")" KRB5CCNAME="FILE:$d/user.ccache" "$@"
}}
# pq_enroll NAME [kuipa enroll options]: enroll NAME with its OTP string.
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
# pq_voucher NAME [--bound] [kuipa enroll options]: enroll a new host NAME
# with a voucher in host group webservers: blind it, have the issuer
# ($KUIPA_PLAYGROUND/voucher, quota 100) sign it, unblind it, enroll.
# With --bound, the voucher works only with the host's ephemeral key.
pq_voucher() {{
    local name="$1"; shift
    pq_host "$name"
    local v="$KUIPA_PLAYGROUND/voucher" eph="$KUIPA_ROOT/voucher-ephemeral.jwk"
    local bind=() key=()
    if [ "$1" = --bound ]; then
        shift
        rm -f "$eph"
        local b
        b=$(kuipa voucher-key --out "$eph" --json | sed 's/.*"binding":"\([^"]*\)".*/\1/')
        bind=("--binding=$b") key=("--ephemeral-key=$eph")
    fi
    kuipa-voucher request --public "$v/issuer.jwk" --realm {REALM} --fqdn "$PQ_HOST" \
        --hostgroup webservers "${{bind[@]}}" --state "$v/$name.state" \
        | kuipa-voucher sign --key "$v/issuer.pem" --quota "$v/quota.json" \
        | kuipa-voucher finish --state "$v/$name.state" > "$v/$name.voucher" || return
    kuipa-voucher show < "$v/$name.voucher"
    kuipa enroll $PQ_SERVERS --hostname "$PQ_HOST" --enrollment-file "$KUIPA_PLAYGROUND/enroll/realm" \
        --voucher-file "$v/$name.voucher" "${{key[@]}}" "$@"
}}
"#,
        ccache = shell_quote(&format!("FILE:{}", dir.join("admin.ccache").display())),
        dir = shell_quote(&dir.display().to_string()),
        endpoints = shell_quote(endpoints),
        servers = shell_quote(&server_args),
        anchor = shell_quote(&anchor.to_string()),
        socket = shell_quote(&realm.socket.display().to_string()),
        trusted_realm = TRUSTED_REALM,
        trusted_user = TRUSTED_USER,
        trusted_file = TRUSTED_REALM.replace('.', "_"),
        trusted_socket = shell_quote(&trusted.socket.display().to_string()),
        dns = dns,
        realm = REALM,
        admin = ADMIN,
        password = ADMIN_PASSWORD,
    )?;
    Ok(env)
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
