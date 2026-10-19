//! `kuipa`: the host's post-quantum identity, by task (§3.1).
//!
//! ```text
//! kuipa prepare [--new]                     get ready to be enrolled offline
//! kuipa enroll [--server S... | --domain D] [--hostname H]
//!               [--enrollment-file F | --realm R]
//!               [--principal P [--password-file F] | --use-ccache |
//!                --voucher-file F [--ephemeral-key F] | --ldap-otp]
//!                                            enroll online: OTP (default, as
//!                                            a Kerberos key), a user's
//!                                            password (armoured kinit on the
//!                                            host), an existing Kerberos
//!                                            ticket, a voucher, or an OTP
//!                                            checked by LDAP (anchor only)
//! kuipa voucher-key --out F                 the ephemeral key to bind a
//!                                            voucher to; prints its binding
//! kuipa realm-info [--server S... | --domain D] --krb5-dir D
//!                   [--enrollment-file F | --realm R]
//!                                            Kerberos configuration for
//!                                            enrolling with an existing ticket
//! kuipa enroll --bundle F [--enrollment-file F] [--insecure-signed-only]
//!                                            enroll offline
//! kuipa complete                            finish an offline enrollment
//! kuipa rotate-keys                         new host keys
//! kuipa protect | unprotect                 seal / unseal the keytab on disk
//! kuipa trusted-realms                      accept users of the realms this
//!                                            realm trusts (their KDCs and
//!                                            PKINIT anchors, verified)
//! kuipa status | check [--server S]         is this host healthy?
//! kuipa leave                               remove kuipa state
//! ```
//!
//! Without `--server`, servers are found in DNS (`_ldap._tcp.<domain>` SRV
//! records, for `--domain` or the host's domain); every one must still
//! present a verified advertisement.
//!
//! Common options: `--json`; `--verbose` traces each step on standard error
//! (requests, responses, decisions, files written), `--trace` adds details,
//! and `KUIPA_TRACE` takes `tracing` filter directives instead.  Secrets
//! are never traced.  Secrets are read from files or standard input,
//! never from the command line: the enrollment string from
//! `--enrollment-file`, `KUIPA_ENROLLMENT_FILE`, or standard input; with
//! `--principal`, the password from `--password-file` or standard input.
//! From a pipe the enrollment string is the first line and the password the
//! next; on a terminal each is prompted for (the password without echo).
//!
//! `--realm R` replaces the enrollment string for `enroll` with a password,
//! ticket or voucher and for `realm-info`: the advertisement is verified
//! against the anchors pre-provisioned in `/etc/ipa/ku-anchors` (an image,
//! configuration management), and nothing but the password is read.  With
//! an enrollment file as well (`ipa-client-install -r`), `--realm` is a
//! cross-check instead: the string must be for realm R.
//!
//! Every advertisement must describe the deployment given here: its server
//! one of `--server` (or the servers found in DNS), its domain `--domain`
//! (or the one used for DNS), its realm the string's.  Otherwise `kuipa`
//! stops before sending anything (exit 1); it does not fail over.  Before
//! enrollment, only those servers are used as KDCs.
//!
//! With `--use-ccache`, the ticket in `KRB5CCNAME` is used as is; the caller
//! (normally `ipa-client-install`) prepares `KRB5_CONFIG` from
//! `kuipa realm-info`.  On an enrolled host without a system Kerberos
//! configuration for the realm, the configuration kuipa generated at
//! enrollment is used as a fallback.
//!
//! Exit status: 0 success, 75 retry later, 1 needs an administrator or
//! another error, 2 usage.

use std::io::{IsTerminal, Read};
use std::process::ExitCode;

use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::realm::Deployment;
use kuipa_tools::flows::{self, Auth, Outcome};
use kuipa_tools::paths::{self, Error, Paths};
use kuipa_tools::trace;
use native_ossl::util::SecretBuf;
use serde_json::Value;
use tang_pqc::Thumbprint;

const USAGE: &str = "usage: kuipa {prepare|enroll|voucher-key|realm-info|complete|rotate-keys|protect|unprotect|trusted-realms|status|check|leave} [options]";

#[derive(Default)]
struct Args {
    command: String,
    json: bool,
    flags: Vec<String>,
    options: Vec<(String, String)>,
}

const COMMANDS: &[&str] = &[
    "prepare",
    "enroll",
    "voucher-key",
    "realm-info",
    "complete",
    "rotate-keys",
    "protect",
    "unprotect",
    "trusted-realms",
    "status",
    "check",
    "leave",
];

/// Options that take a value; everything else starting with `--` is a flag.
const VALUED: &[&str] = &[
    "password-file",
    "krb5-dir",
    "server",
    "hostname",
    "principal",
    "enrollment-file",
    "domain",
    "bundle",
    "voucher-file",
    "ephemeral-key",
    "out",
    "realm",
];

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let command = it.next().ok_or(USAGE)?;
    if !COMMANDS.contains(&command.as_str()) {
        return Err(format!("unknown command {command:?}\n{USAGE}"));
    }
    let mut args = Args {
        command,
        ..Args::default()
    };
    while let Some(arg) = it.next() {
        let name = arg
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument {arg:?}"))?;
        if name == "json" {
            args.json = true;
        } else if VALUED.contains(&name) {
            let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
            args.options.push((name.into(), value));
        } else {
            args.flags.push(name.into());
        }
    }
    Ok(args)
}

impl Args {
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

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    /// `--enrollment-file`, or `KUIPA_ENROLLMENT_FILE` from the
    /// environment.
    fn enrollment_file(&self) -> Option<String> {
        self.option("enrollment-file")
            .map(str::to_owned)
            .or_else(|| std::env::var("KUIPA_ENROLLMENT_FILE").ok())
    }

    /// Secret input: the enrollment file and `--password-file`, or standard
    /// input.  From a pipe, the enrollment string is the first line and the
    /// password the next; on a terminal, each is prompted for (the password
    /// without echo).
    fn secrets(&self, want_string: bool, want_password: bool) -> Result<Secrets, Error> {
        let string_file = self.enrollment_file().filter(|f| f != "-");
        let password_file = self
            .option("password-file")
            .filter(|f| *f != "-")
            .map(str::to_owned);
        let need_stdin =
            (want_string && string_file.is_none()) || (want_password && password_file.is_none());
        let interactive = need_stdin && std::io::stdin().is_terminal();
        let mut piped = Vec::new().into_iter();
        if need_stdin && !interactive {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            let buf = SecretBuf::new(buf);
            piped = buf
                .as_ref()
                .split(|&b| b == b'\n')
                .map(|l| SecretBuf::from_slice(l.strip_suffix(b"\r").unwrap_or(l)))
                .collect::<Vec<_>>()
                .into_iter();
        }
        // An empty line or file is a missing secret, never an empty one.
        let mut take =
            |file: Option<&String>, what: &str, hidden: bool| -> Result<SecretBuf, Error> {
                let value = match file {
                    Some(path) => first_line(&SecretBuf::new(std::fs::read(path)?)),
                    None if interactive => prompt(what, hidden)?,
                    None => piped.next().unwrap_or_else(|| SecretBuf::with_len(0)),
                };
                if value.as_ref().is_empty() {
                    return Err(format!("missing {what}").into());
                }
                Ok(value)
            };
        let string = if want_string {
            Some(EnrollmentString::parse(
                take(string_file.as_ref(), "enrollment string", false)?.as_ref(),
            )?)
        } else {
            None
        };
        let password = if want_password {
            Some(Secret::new(
                take(password_file.as_ref(), "password", true)?.as_ref(),
            ))
        } else {
            None
        };
        Ok(Secrets { string, password })
    }

    /// The enrollment string only if one was explicitly given.
    fn optional_string(&self) -> Result<Option<EnrollmentString>, Error> {
        match self.enrollment_file() {
            Some(_) => Ok(self.secrets(true, false)?.string),
            None => Ok(None),
        }
    }

    /// What to verify the realm against, with the secrets: the enrollment
    /// string's realm and anchor, or else `--realm` and the pre-provisioned
    /// `/etc/ipa/ku-anchors`.  With both an enrollment string and
    /// `--realm` (`ipa-client-install -r`), the string must be for that
    /// realm: the realm then comes from two channels (§4.6).
    fn pins(&self, paths: &Paths, want_password: bool) -> Result<(Pins, Secrets), Error> {
        let realm = self.option("realm");
        if realm.is_some_and(str::is_empty) {
            return Err("--realm needs a realm".into());
        }
        if realm.is_none() || self.enrollment_file().is_some() {
            let secrets = self.secrets(true, want_password)?;
            let string = secrets
                .string
                .as_ref()
                .ok_or("enrollment string required")?;
            if let Some(realm) = realm
                && string.realm() != realm
            {
                return Err(format!(
                    "the enrollment string is for realm {}, not {realm} (--realm)",
                    string.realm()
                )
                .into());
            }
            flows::check_string(string)?;
            let pins = Pins {
                realm: string.realm().to_owned(),
                anchors: vec![*string.anchor()],
            };
            return Ok((pins, secrets));
        }
        let realm = realm.unwrap_or_default();
        let file = paths.anchors();
        let pinned = paths::read_anchor_pins(&file)
            .map_err(|e| format!("--realm: no pinned anchors in {}: {e}", file.display()))?;
        let anchors = paths::read_anchors(paths)?;
        if anchors.is_empty() {
            let why = if pinned.is_empty() {
                "no"
            } else {
                "only expired"
            };
            return Err(format!("--realm: {why} pinned anchors in {}", file.display()).into());
        }
        let pins = Pins {
            realm: realm.to_owned(),
            anchors,
        };
        Ok((pins, self.secrets(false, want_password)?))
    }

    /// The deployment to join, checked before any input is read: the
    /// `--server`s, or the realm's servers from DNS SRV records for
    /// `--domain`, else the host's domain.  The domain is part of it when
    /// given or used for the lookup: every advertisement must describe it
    /// (§4.6).
    fn deployment(&self) -> Result<Deployment, Error> {
        let servers = self.all("server");
        if !servers.is_empty() {
            return Ok(Deployment {
                servers,
                domain: self.option("domain").map(str::to_owned),
            });
        }
        let host = match self.option("hostname") {
            Some(h) => h.to_owned(),
            None => flows::hostname()?,
        };
        let domain = match self.option("domain") {
            Some(d) => d.to_owned(),
            None => kuipa_tools::dns::domain_of(&host)
                .ok_or("no --server, and no --domain to find servers in DNS")?
                .to_owned(),
        };
        let servers = kuipa_tools::dns::ipa_servers(&domain)
            .map_err(|e| format!("no --server given and none found in DNS: {e}"))?;
        Ok(Deployment {
            servers,
            domain: Some(domain),
        })
    }
}

fn first_line(bytes: &SecretBuf) -> SecretBuf {
    let first = bytes
        .as_ref()
        .split(|&b| b == b'\n')
        .next()
        .unwrap_or_default();
    SecretBuf::from_slice(first.strip_suffix(b"\r").unwrap_or(first))
}

/// Prompt on the terminal and read one line; with `hidden`, echo is off
/// while typing (`stty` on the terminal, so no terminal ioctls here).
fn prompt(what: &str, hidden: bool) -> Result<SecretBuf, Error> {
    let stty = |arg: &str| {
        std::fs::File::open("/dev/tty").ok().and_then(|tty| {
            std::process::Command::new("stty")
                .arg(arg)
                .stdin(tty)
                .status()
                .ok()
        })
    };
    eprint!("{}{}: ", what[..1].to_uppercase(), &what[1..]);
    if hidden {
        stty("-echo");
    }
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    if hidden {
        stty("echo");
        eprintln!();
    }
    read?;
    let value = SecretBuf::from_slice(line.trim_end_matches(['\n', '\r']).as_bytes());
    drop(SecretBuf::new(line.into_bytes()));
    Ok(value)
}

struct Secrets {
    string: Option<EnrollmentString>,
    password: Option<Secret>,
}

/// The realm to enroll in and the anchors that must vouch for its servers.
struct Pins {
    realm: String,
    anchors: Vec<Thumbprint>,
}

fn run(args: &Args) -> Result<Value, Error> {
    let paths = Paths::from_env();
    match args.command.as_str() {
        "prepare" => {
            let fqdn = args
                .option("hostname")
                .map_or_else(flows::hostname, |h| Ok(h.to_owned()))?;
            flows::prepare(&paths, args.flag("new"), &fqdn)
        }
        "enroll" => {
            if let Some(bundle) = args.option("bundle") {
                let string = args.optional_string()?;
                flows::enroll_bundle(
                    &paths,
                    &std::fs::read(bundle)?,
                    string.as_ref(),
                    args.flag("insecure-signed-only"),
                    args.option("hostname"),
                )
            } else {
                let deployment = args.deployment()?;
                let principal = args.option("principal");
                let ccache = args.flag("use-ccache");
                let (pins, secrets) = args.pins(&paths, principal.is_some() && !ccache)?;
                let mut string = secrets.string;
                let voucher = args.option("voucher-file");
                let auth = match (principal, ccache, secrets.password) {
                    _ if voucher.is_some() => Auth::Voucher {
                        voucher: Secret::new(&std::fs::read(voucher.unwrap_or_default())?),
                        ephemeral: args
                            .option("ephemeral-key")
                            .map(|f| std::fs::read(f).map(|k| Secret::new(&k)))
                            .transpose()?,
                    },
                    (_, true, _) => Auth::Ccache,
                    (Some(p), false, Some(password)) => Auth::Password {
                        principal: p.to_owned(),
                        password,
                    },
                    _ => {
                        let otp = string
                            .as_mut()
                            .ok_or("an OTP comes in an enrollment string, not with --realm")?
                            .take_secret()
                            .ok_or("the enrollment string has no OTP")?;
                        // Never chosen automatically: a fake KDC could
                        // otherwise force the weaker check (§5.3).
                        if args.flag("ldap-otp") {
                            Auth::LdapOtp(otp)
                        } else {
                            Auth::Otp(otp)
                        }
                    }
                };
                let fqdn = args
                    .option("hostname")
                    .map_or_else(flows::hostname, |h| Ok(h.to_owned()))?;
                flows::enroll_online(
                    &paths,
                    &pins.realm,
                    &pins.anchors,
                    &auth,
                    &fqdn,
                    &deployment,
                )
            }
        }
        "voucher-key" => {
            let out = args.option("out").ok_or("--out is required")?;
            let binding = kuipa_tools::voucher::ephemeral(std::path::Path::new(out))?;
            Ok(serde_json::json!({ "binding": tang_pqc::b64::encode(&binding) }))
        }
        "realm-info" => {
            let dir = args.option("krb5-dir").ok_or("--krb5-dir is required")?;
            let deployment = args.deployment()?;
            let (pins, _) = args.pins(&paths, false)?;
            flows::realm_info(
                &pins.realm,
                &pins.anchors,
                &deployment,
                std::path::Path::new(dir),
            )
        }
        "complete" => flows::complete(&paths),
        "rotate-keys" => flows::rotate_keys(&paths, None),
        "protect" => flows::protect(&paths),
        "unprotect" => flows::unprotect(&paths),
        "trusted-realms" => flows::trusted_realms(&paths),
        "status" => flows::status(&paths),
        "check" => flows::check(&paths, args.option("server")),
        "leave" => flows::leave(&paths),
        other => Err(format!("unknown command {other:?}\n{USAGE}").into()),
    }
}

fn print_human(value: &Value, indent: usize) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if v.is_object() || v.is_array() {
                    println!("{:indent$}{k}:", "");
                    print_human(v, indent + 2);
                } else {
                    println!(
                        "{:indent$}{k}: {}",
                        "",
                        v.as_str().map_or_else(|| v.to_string(), str::to_owned)
                    );
                }
            }
        }
        Value::Array(items) => {
            for v in items {
                if v.is_object() {
                    print_human(v, indent + 2);
                } else {
                    println!(
                        "{:indent$}- {}",
                        "",
                        v.as_str().map_or_else(|| v.to_string(), str::to_owned)
                    );
                }
            }
        }
        v => println!("{:indent$}{v}", ""),
    }
}

/// Fall back to the `krb5.conf` generated at enrollment when the caller
/// set no `KRB5_CONFIG`: the system file stays first, so a host configured
/// by `ipa-client-install` behaves as before.
fn krb5_config_fallback(paths: &Paths) {
    if std::env::var_os("KRB5_CONFIG").is_some() || !paths.krb5_conf().exists() {
        return;
    }
    let value = format!(
        "{}:{}",
        paths.system_krb5_conf().display(),
        paths.krb5_conf().display()
    );
    // SAFETY: called first thing in `main`, before this process starts any
    // thread, so nothing can read the environment concurrently.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("KRB5_CONFIG", value);
    }
}

fn main() -> ExitCode {
    krb5_config_fallback(&Paths::from_env());
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    trace::init(if args.flag("trace") {
        trace::Level::Details
    } else if args.flag("verbose") {
        trace::Level::Steps
    } else {
        trace::Level::Off
    });
    tracing::debug!("kuipa {}", args.command);
    match run(&args) {
        Ok(value) => {
            if args.json {
                println!("{value}");
            } else {
                print_human(&value, 0);
            }
            if value.get("ok") == Some(&Value::Bool(false)) {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("kuipa {}: {e}", args.command);
            match e.downcast_ref::<Outcome>() {
                Some(Outcome::RetryLater(_)) => ExitCode::from(75),
                _ => ExitCode::FAILURE,
            }
        }
    }
}
