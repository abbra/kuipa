//! `kuipad`: serve, or manage the server's keys.
//!
//! ```text
//! kuipad [serve] [--config FILE]
//! kuipad generate-keys [--config FILE]   create the keys, print the anchor
//! kuipad anchor [--config FILE]          print this server's anchor thumbprint
//! kuipad enrollment-string [--days N] [--head] [--config FILE]
//!                                                print ipa-ku1:REALM:<anchor>:<expiry>
//!                                                (with --head, ipa-ku2 with the anchor's
//!                                                vouch head: signature-free checks §4.9),
//!                                                to append :<OTP> to (default: 7 days)
//! kuipad rotate-anchor [--days N] [--config FILE]
//!                                                new anchor; the old one signs a succession
//!                                                to it, valid N days (default 400), and is
//!                                                deleted
//! kuipad rotate-keys [--join] [--escrow] [--trust] [--signing] [--config FILE]
//!                                                new keys (default: join, escrow, trust);
//!                                                the old ones are retired
//! kuipad trust-invitation [--days N] [--config FILE]
//!                                                invite another realm to trust this one
//!                                                (default: valid for 7 days)
//! kuipad establish-trust --invitation-file F --server S... [--config FILE]
//!                                                trust the realm that issued F
//! kuipad add-voucher-key --file JWK [--config FILE]
//!                                                accept vouchers under a voucher key (§9)
//! kuipad add-witness-key --file JWK [--config FILE]
//!                                                accept the transparency-log cosignatures
//!                                                of a witness (DESIGN-tlog.md §4)
//! kuipad tang-keygen [--config FILE]   Tang keys: serve post-quantum Tang
//!                                                at /ipa/ku/tang; prints the thumbprint
//! kuipad tang-rotate [--config FILE]   retire the Tang keys, create new ones
//! kuipad tang-thp [--config FILE]      the Tang signing keys' thumbprints
//! kuipad prune-keys [--join-days N] [--escrow-days N] [--config FILE]
//!                                                remove keys retired longer ago
//!                                                (default 14 and 400 days)
//! ```
//!
//! The daemon reads its keys at start: restart it after `rotate-keys` or
//! `prune-keys` (the socket stays open, so clients see no outage).

use std::process::ExitCode;
use std::sync::Arc;

use kuipa_enroll::EnrollServer;
use kuipa_enroll::server::Directory as _;
use kuipad::config::{self, Config};
use kuipad::directory::LdapDirectory;
use kuipad::http::{App, router};
use kuipad::keystore::{Changes, KeyStore, Retire, Rotation};
use kuipad::peers::{self, KeytabInitiator, Peers, Settings};
use kuipad::tang::TangKeys;

type Error = Box<dyn std::error::Error + Send + Sync>;

struct Args {
    command: String,
    config: String,
    flags: Vec<String>,
    options: Vec<(String, String)>,
}

impl Args {
    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    fn option(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.options
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn days(&self, name: &str, default: u64) -> Result<std::time::Duration, Error> {
        let days = match self.options.iter().find(|(n, _)| n == name) {
            Some((_, v)) => v
                .parse()
                .map_err(|_| format!("--{name} needs a number of days"))?,
            None => default,
        };
        Ok(std::time::Duration::from_secs(days * 86400))
    }
}

fn parse_args() -> Result<Args, Error> {
    let mut args = Args {
        command: "serve".into(),
        config: config::DEFAULT_PATH.into(),
        flags: Vec::new(),
        options: Vec::new(),
    };
    let mut it = std::env::args().skip(1).peekable();
    if let Some(first) = it.peek()
        && !first.starts_with("--")
    {
        args.command = it.next().unwrap_or_default();
    }
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => args.config = it.next().ok_or("--config needs a value")?,
            "--join" | "--escrow" | "--trust" | "--signing" => {
                args.flags.push(arg[2..].to_owned());
            }
            "--join-days" | "--escrow-days" | "--days" | "--invitation-file" | "--server"
            | "--file" => {
                let value = it.next().ok_or_else(|| format!("{arg} needs a value"))?;
                args.options.push((arg[2..].to_owned(), value));
            }
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    Ok(args)
}

async fn serve(cfg: Config) -> Result<(), Error> {
    let store = KeyStore::new(&cfg.key_dir);
    let keys = store.load()?;
    let anchor = if cfg.anchor {
        Some(store.anchor()?)
    } else {
        None
    };
    let keys_service = cfg.keys_service()?;
    if keys_service.is_some() {
        eprintln!("kuipad: serving the keys operation at /ipa/ku/keys");
    }
    let mut ldap = LdapDirectory::new(cfg.directory())?;
    if let Some(keys) = &keys_service {
        ldap.serve_keys(keys.clone());
    }
    let directory = Arc::new(ldap);
    let servers = directory.servers().unwrap_or_else(|e| {
        eprintln!("kuipad: cannot list servers ({e}); advertising only this one");
        vec![cfg.server.clone()]
    });
    let delegation = peers::initial_delegation(
        &store,
        anchor.as_ref(),
        &cfg.realm,
        &cfg.server,
        keys.signing.public(),
    )?;
    let info = cfg.realm_info(servers, anchor.as_ref().map(|a| *a.public().thumbprint()))?;
    let ca_certs = info.ca_certs.clone();
    let ledger = Arc::new(
        kuipad::ledger::FileLedger::open(
            &cfg.key_dir,
            &cfg.realm,
            &cfg.server,
            kuipa_enroll::merkle::TreeHash::for_signer(keys.signing.public().alg()),
        )?
        .with_witnesses(store.witness_keys()?),
    );
    eprintln!(
        "kuipad: transparency log {} at /ipa/ku/tlog ({} leaves)",
        ledger.id(),
        ledger.size()
    );
    let server = Arc::new(
        EnrollServer::new(keys, info, delegation)
            .with_policy(tang_pqc::Policy::from_system()?)
            .with_ledger(ledger.clone()),
    );
    let settings = Settings {
        me: cfg.server.clone(),
        realm: cfg.realm.clone(),
        peers: cfg.peers.clone(),
        discover: cfg.discover_peers,
        endpoints: cfg.peer_endpoints.clone(),
        interval: std::time::Duration::from_secs(cfg.peer_interval.max(5)),
        ca_certs,
        vouch_interval: std::time::Duration::from_secs(cfg.vouch_interval),
    };
    let initiator = Arc::new(KeytabInitiator::new(
        cfg.keytab.clone(),
        cfg.principal.clone(),
    ));
    let peers = Peers::new(
        settings,
        anchor,
        server.clone(),
        directory.clone(),
        initiator,
        store,
    )?;
    tokio::spawn(peers.clone().run());
    {
        let (server, directory) = (server.clone(), directory.clone());
        let configured = cfg.trusted_realms()?;
        let endpoints = cfg.peer_endpoints.clone();
        let every = std::time::Duration::from_secs(cfg.peer_interval.max(5) * 10);
        tokio::spawn(async move {
            let directory: Arc<dyn kuipa_enroll::Directory + Send + Sync> = directory;
            loop {
                kuipad::trust::refresh(&server, &directory, &configured, &endpoints).await;
                tokio::time::sleep(every).await;
            }
        });
    }
    let tang = TangKeys::new(&cfg.key_dir).server()?.map(Arc::new);
    if tang.is_some() {
        eprintln!("kuipad: serving post-quantum Tang at /ipa/ku/tang");
    }
    let app = router(Arc::new(App {
        server,
        directory,
        peers: Some(peers),
        limiter: kuipad::limit::Limiter::new(cfg.rate_limit),
        tang,
        keys: keys_service,
        ledger: Some(ledger),
    }));

    listen(app, &cfg.listen).await
}

/// Serve `app` on the socket-activated Unix socket, or else on `listen`
/// (`unix:<path>` or a TCP address).
async fn listen(app: axum::Router, listen: &str) -> Result<(), Error> {
    let mut fds = listenfd::ListenFd::from_env();
    if let Some(listener) = fds.take_unix_listener(0)? {
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        eprintln!("kuipad: serving on the socket-activated Unix socket");
        axum::serve(listener, app).await?;
    } else if let Some(path) = listen.strip_prefix("unix:") {
        let _ = std::fs::remove_file(path);
        let listener = tokio::net::UnixListener::bind(path)?;
        eprintln!("kuipad: serving on {path}");
        axum::serve(listener, app).await?;
    } else {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        eprintln!("kuipad: serving on {listen}");
        axum::serve(listener, app).await?;
    }
    Ok(())
}

/// Longest validity of an enrollment string, in days (§4.4).
const MAX_STRING_DAYS: u64 = 400;

/// `enrollment-string`: the string for this realm and this server's
/// anchor, without a secret, valid for `--days` (§4.4).  With `--head`,
/// a version 2 string that also pins the anchor's current vouch head
/// (§4.9), from the stored delegation's proof by this anchor: the host
/// then checks delegations with no signature at all.
fn enrollment_string(cfg: &Config, store: &KeyStore, args: &Args) -> Result<(), Error> {
    let days = args.days("days", 7)?;
    if days.is_zero() || days.as_secs() > MAX_STRING_DAYS * 86400 {
        return Err(format!("--days must be between 1 and {MAX_STRING_DAYS}").into());
    }
    let exp = tang_pqc::unix_seconds(std::time::SystemTime::now()) + days.as_secs();
    let head = args.flag("head").then(|| head_of(store)).transpose()?;
    let string = kuipa_enroll::enrollment::EnrollmentString::with_head(
        &cfg.realm,
        *store.anchor()?.public().thumbprint(),
        head,
        exp,
        None,
    );
    println!("{}", String::from_utf8_lossy(string.encode().as_ref()));
    Ok(())
}

/// The anchor's current vouch head (§4.9), from the stored delegation:
/// the `(size, root)` its own proof's vouch signed.
fn head_of(store: &KeyStore) -> Result<(u64, kuipa_enroll::merkle::Hash), Error> {
    let anchor = *store.anchor()?.public().thumbprint();
    let delegation = store.delegation()?.ok_or("no stored delegation")?;
    delegation.vouch_head(&anchor).ok_or_else(|| {
        "no vouch by this anchor in the stored delegation: wait for the next exchange round".into()
    })
}

/// `trust-invitation`: issue an invitation for another realm (§17.4).
fn trust_invitation(cfg: &Config, store: &KeyStore, args: &Args) -> Result<(), Error> {
    let anchor = store.anchor()?;
    let invitation =
        kuipa_enroll::trust::Invitation::new(&cfg.realm, *anchor.public().thumbprint())?;
    let days = args.days("days", 7)?;
    let not_after = tang_pqc::unix_seconds(std::time::SystemTime::now()) + days.as_secs();
    LdapDirectory::new(cfg.directory())?
        .add_trust_invitation(&invitation.secret_hash()?, not_after)?;
    println!("{}", String::from_utf8_lossy(invitation.encode().as_ref()));
    Ok(())
}

/// `establish-trust`: trust the realm that issued an invitation (§17.4).
fn establish_trust(cfg: &Config, store: &KeyStore, args: &Args) -> Result<(), Error> {
    let file = args
        .option("invitation-file")
        .ok_or("--invitation-file is required")?;
    let invitation = kuipa_enroll::trust::Invitation::parse(&std::fs::read(file)?)?;
    let servers = args.all("server");
    if servers.is_empty() {
        return Err("at least one --server of the inviting realm is required".into());
    }
    let keys = store.load()?;
    let anchor = if cfg.anchor {
        Some(store.anchor()?)
    } else {
        None
    };
    let delegation = peers::initial_delegation(
        store,
        anchor.as_ref(),
        &cfg.realm,
        &cfg.server,
        keys.signing.public(),
    )?;
    let directory = LdapDirectory::new(cfg.directory())?;
    let mut info = cfg.realm_info(
        directory
            .servers()
            .unwrap_or_else(|_| vec![cfg.server.clone()]),
        anchor.as_ref().map(|a| *a.public().thumbprint()),
    )?;
    // What the system crypto policy allows, as tang_pqc's default narrows to.
    let policy = tang_pqc::Policy::from_system()?;
    // The anchors this server's delegation is proven by.
    info.anchors = delegation.signers(&policy);
    let server = EnrollServer::new(keys, info, delegation).with_policy(policy);
    let (established, recorded) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(kuipad::trust::establish(
            &server,
            &invitation,
            &servers,
            &cfg.peer_endpoints,
            &directory,
        ))?;
    let p = &established.partner;
    println!(
        "trusted realm {} (domain {}, servers {:?})",
        p.realm, p.domain, p.servers
    );
    if !recorded {
        println!(
            "record it with the trust secret: ipa trust-add --type=ipa {} --trust_secret",
            p.realm
        );
        println!(
            "trust secret: {}",
            String::from_utf8_lossy(kuipad::trust::secret_text(&established).as_ref())
        );
        println!(
            "and add to `trusts` in the configuration: {}",
            serde_json::json!({
                "realm": p.realm, "domain": p.domain, "servers": p.servers,
                "anchors": p.anchors.iter().map(ToString::to_string).collect::<Vec<_>>(),
            })
        );
    }
    Ok(())
}

fn run(args: &Args) -> Result<(), Error> {
    let cfg = Config::load(&args.config)?;
    let store = KeyStore::new(&cfg.key_dir);
    match args.command.as_str() {
        "serve" => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(serve(cfg)),
        "generate-keys" => {
            println!("{}", store.generate()?.public().thumbprint());
            Ok(())
        }
        "anchor" | "enrollment-string" | "rotate-anchor" if !cfg.anchor => Err(
            "this server has no anchor role; enrollment strings use an anchor server's thumbprint"
                .into(),
        ),
        "anchor" => {
            println!("{}", store.anchor()?.public().thumbprint());
            Ok(())
        }
        "enrollment-string" => enrollment_string(&cfg, &store, args),
        "rotate-anchor" => {
            let days = args.days("days", MAX_STRING_DAYS)?;
            if days.is_zero() || days.as_secs() > MAX_STRING_DAYS * 86400 {
                return Err(format!("--days must be between 1 and {MAX_STRING_DAYS}").into());
            }
            let (old, new) = store.rotate_anchor(&cfg.realm, days)?;
            println!("{new}");
            eprintln!(
                "kuipad: anchor {old} replaced by {new}; its succession is valid for {} \
                 days.\nRestart kuipad, then issue new enrollment strings \
                 (enrollment-string) and replace pinned anchors in images.",
                days.as_secs() / 86400
            );
            Ok(())
        }
        "tang-keygen" => {
            println!("{}", TangKeys::new(&cfg.key_dir).generate()?);
            eprintln!("kuipad: restart the daemon to serve Tang");
            Ok(())
        }
        "tang-rotate" => {
            println!("{}", TangKeys::new(&cfg.key_dir).rotate()?);
            eprintln!("kuipad: restart the daemon to advertise the new keys");
            Ok(())
        }
        "tang-thp" => {
            for thp in TangKeys::new(&cfg.key_dir).thumbprints()? {
                println!("{thp}");
            }
            Ok(())
        }
        "add-witness-key" => {
            let file = args.option("file").ok_or("--file is required")?;
            println!("{}", store.add_witness_key(&std::fs::read(file)?)?);
            eprintln!("kuipad: restart the daemon to accept cosignatures by it");
            Ok(())
        }
        "add-voucher-key" => {
            let file = args.option("file").ok_or("--file is required")?;
            println!("{}", store.add_voucher_key(&std::fs::read(file)?)?);
            eprintln!("kuipad: restart the daemon to accept vouchers under it");
            Ok(())
        }
        "rotate-keys" => {
            let mut which = Rotation {
                retire: Retire {
                    join: args.flag("join"),
                    escrow: args.flag("escrow"),
                    trust: args.flag("trust"),
                },
                signing: args.flag("signing"),
            };
            if which == Rotation::default() {
                which.retire = Retire {
                    join: true,
                    escrow: true,
                    trust: true,
                };
            }
            report(&store.rotate(which)?);
            Ok(())
        }
        "trust-invitation" => trust_invitation(&cfg, &store, args),
        "establish-trust" => establish_trust(&cfg, &store, args),
        "prune-keys" => {
            report(&store.prune(args.days("join-days", 14)?, args.days("escrow-days", 400)?)?);
            Ok(())
        }
        other => Err(format!("unknown command {other:?}").into()),
    }
}

fn report(changes: &Changes) {
    for (what, names) in [
        ("created", &changes.created),
        ("retired", &changes.retired),
        ("removed", &changes.removed),
    ] {
        for name in names {
            println!("{what} {name}");
        }
    }
    if changes != &Changes::default() {
        println!("restart kuipad to use the changed keys");
    }
}

fn main() -> ExitCode {
    match parse_args().and_then(|a| run(&a)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kuipad: {e}");
            ExitCode::FAILURE
        }
    }
}
