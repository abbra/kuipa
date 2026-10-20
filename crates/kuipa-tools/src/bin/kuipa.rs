//! `kuipa`: the host's post-quantum identity, by task (§10.1).
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
//! kuipa advertisement [--server S... | --domain D]
//!                     [--enrollment-file F | --realm R]
//!                                            what each server
//!                                            advertises, verified, and the
//!                                            realm's anchor log: its
//!                                            landmark chain (§4.8)
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

use clap::{Parser, Subcommand};
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::realm::Deployment;
use kuipa_tools::flows::{self, Auth, Outcome};
use kuipa_tools::paths::{self, Error, Paths};
use kuipa_tools::trace;
use native_ossl::util::SecretBuf;
use serde_json::Value;
use tang_pqc::Thumbprint;

#[derive(Parser)]
#[command(
    about = "Manage this host's post-quantum identity in an IPA realm.",
    after_help = "Secrets are never taken from the command line: the enrollment \
string comes from --enrollment-file, $KUIPA_ENROLLMENT_FILE or standard input, the \
password from --password-file or standard input; on a terminal each is prompted for. \
Without --server, servers are found in DNS (_ldap._tcp.<domain> SRV records). \
Exit status: 0 success, 75 retry later, 1 needs an administrator or another error, \
2 usage."
)]
struct Cli {
    /// Print the result as one JSON object instead of text.
    #[arg(long, global = true)]
    json: bool,
    /// Trace each request, decision and file written on standard error.
    #[arg(long, global = true)]
    verbose: bool,
    /// Trace with wire details (`$KUIPA_TRACE` overrides with `tracing`
    /// filter directives).
    #[arg(long, global = true)]
    trace: bool,
    #[command(subcommand)]
    command: Command,
}

/// How to reach the deployment: servers given directly, or found in DNS
/// for `--domain` or the host's domain.  Every advertisement must
/// describe this deployment (§4.6).
#[derive(clap::Args)]
struct DeploymentInput {
    /// IPA server host; repeat for each server.  Found in DNS otherwise.
    #[arg(long, value_name = "HOST")]
    server: Vec<String>,
    /// Domain to look servers up in (default: this host's domain).
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,
    /// The host being enrolled (default: this host's FQDN).
    #[arg(long, value_name = "FQDN")]
    hostname: Option<String>,
}

/// What to verify the servers against: an enrollment string, or `--realm`
/// with anchors pre-provisioned in /etc/ipa/ku-anchors (§4.6).
#[derive(clap::Args)]
struct RealmInput {
    /// Enrollment string file; '-' reads standard input.  Defaults to
    /// `$KUIPA_ENROLLMENT_FILE`.
    #[arg(long, value_name = "FILE")]
    enrollment_file: Option<String>,
    /// Verify realm R against its pinned anchors instead of an enrollment
    /// string; with one given as well, R is a cross-check of its realm.
    #[arg(long, value_name = "REALM")]
    realm: Option<String>,
    /// Read the password from this file instead of standard input.
    #[arg(long, value_name = "FILE")]
    password_file: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Get ready to be enrolled offline; print the host's FQDN.
    Prepare {
        /// The host to prepare (default: this host's FQDN).
        #[arg(long, value_name = "FQDN")]
        hostname: Option<String>,
        /// Create a new machine key, replacing the existing one.
        #[arg(long)]
        new: bool,
    },
    /// Enroll online: OTP (default), a user's password, an existing
    /// Kerberos ticket, or a voucher; or offline from a prepared bundle.
    Enroll {
        #[command(flatten)]
        realm: RealmInput,
        #[command(flatten)]
        deployment: DeploymentInput,
        /// Enroll offline from a prepared bundle instead of online.
        #[arg(long, value_name = "FILE")]
        bundle: Option<String>,
        /// Enroll with a user's password (armoured kinit on this host).
        #[arg(long, value_name = "PRINCIPAL")]
        principal: Option<String>,
        /// Enroll with the ticket in $KRB5CCNAME as it is.
        #[arg(long)]
        use_ccache: bool,
        /// Enroll with this voucher (see kuipa-voucher).
        #[arg(long, value_name = "FILE")]
        voucher_file: Option<String>,
        /// The ephemeral key written by `kuipa voucher-key`.
        #[arg(long, value_name = "FILE")]
        ephemeral_key: Option<String>,
        /// Check the OTP through LDAP (anchor servers only).
        #[arg(long)]
        ldap_otp: bool,
        /// Accept a bundle that is only signed, not sealed.
        #[arg(long)]
        insecure_signed_only: bool,
    },
    /// Write the ephemeral key that binds a voucher to this host; print
    /// its binding, for kuipa-voucher's --binding.
    VoucherKey {
        /// Where to write the key.
        #[arg(long, value_name = "FILE")]
        out: String,
    },
    /// Print Kerberos configuration for enrolling with an existing ticket.
    RealmInfo {
        #[command(flatten)]
        realm: RealmInput,
        #[command(flatten)]
        deployment: DeploymentInput,
        /// Directory to write the realm's Kerberos configuration to.
        #[arg(long, value_name = "DIR")]
        krb5_dir: String,
    },
    /// Finish an offline enrollment.
    Complete,
    /// New host keys; re-seals the keytab where needed.
    RotateKeys,
    /// Seal the keytab on disk.
    Protect,
    /// Unseal the keytab on disk.
    Unprotect,
    /// Print the realms this realm trusts (their KDCs and PKINIT anchors,
    /// verified), so their users can log in here.
    TrustedRealms,
    /// Print what each server of the deployment advertises, verified
    /// against the enrollment string's anchor or the pre-provisioned
    /// pins, and the realm's anchor log (landmarks) it names (§4.8).
    Advertisement {
        #[command(flatten)]
        realm: RealmInput,
        #[command(flatten)]
        deployment: DeploymentInput,
    },
    /// Is this host healthy?
    Status,
    /// Check this host's enrollment against the realm.
    Check {
        /// Server to check (default: those recorded at enrollment).
        #[arg(long, value_name = "HOST")]
        server: Vec<String>,
    },
    /// Remove kuipa's state from this host.
    Leave,
}

impl Cli {
    /// Rebuild the loose option bag `run` reads, so the command handlers
    /// do not change with the parser.
    fn args(&self) -> Args {
        let mut args = Args {
            command: self.command.name().to_owned(),
            ..Args::default()
        };
        self.command.collect(&mut args);
        args
    }
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Command::Prepare { .. } => "prepare",
            Command::Enroll { .. } => "enroll",
            Command::VoucherKey { .. } => "voucher-key",
            Command::RealmInfo { .. } => "realm-info",
            Command::Complete => "complete",
            Command::RotateKeys => "rotate-keys",
            Command::Protect => "protect",
            Command::Unprotect => "unprotect",
            Command::TrustedRealms => "trusted-realms",
            Command::Advertisement { .. } => "advertisement",
            Command::Status => "status",
            Command::Check { .. } => "check",
            Command::Leave => "leave",
        }
    }

    fn collect(&self, a: &mut Args) {
        match self {
            Command::Prepare { hostname, new } => {
                a.set("hostname", hostname.as_deref());
                a.mark("new", *new);
            }
            Command::Enroll {
                realm,
                deployment,
                bundle,
                principal,
                use_ccache,
                voucher_file,
                ephemeral_key,
                ldap_otp,
                insecure_signed_only,
            } => {
                a.set("enrollment-file", realm.enrollment_file.as_deref());
                a.set("realm", realm.realm.as_deref());
                a.set("password-file", realm.password_file.as_deref());
                a.set_all("server", &deployment.server);
                a.set("domain", deployment.domain.as_deref());
                a.set("hostname", deployment.hostname.as_deref());
                a.set("bundle", bundle.as_deref());
                a.set("principal", principal.as_deref());
                a.set("voucher-file", voucher_file.as_deref());
                a.set("ephemeral-key", ephemeral_key.as_deref());
                a.mark("use-ccache", *use_ccache);
                a.mark("ldap-otp", *ldap_otp);
                a.mark("insecure-signed-only", *insecure_signed_only);
            }
            Command::VoucherKey { out } => a.set("out", Some(out.as_str())),
            Command::RealmInfo {
                realm,
                deployment,
                krb5_dir,
            } => {
                a.set("enrollment-file", realm.enrollment_file.as_deref());
                a.set("realm", realm.realm.as_deref());
                a.set("password-file", realm.password_file.as_deref());
                a.set_all("server", &deployment.server);
                a.set("domain", deployment.domain.as_deref());
                a.set("hostname", deployment.hostname.as_deref());
                a.set("krb5-dir", Some(krb5_dir.as_str()));
            }
            Command::Advertisement { realm, deployment } => {
                a.set("enrollment-file", realm.enrollment_file.as_deref());
                a.set("realm", realm.realm.as_deref());
                a.set("password-file", realm.password_file.as_deref());
                a.set_all("server", &deployment.server);
                a.set("domain", deployment.domain.as_deref());
                a.set("hostname", deployment.hostname.as_deref());
            }
            Command::Check { server } => a.set_all("server", server),
            _ => {}
        }
    }
}

/// The command and the options and flags as named strings.
#[derive(Default)]
struct Args {
    command: String,
    options: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn set(&mut self, name: &str, value: Option<&str>) {
        if let Some(v) = value {
            self.options.push((name.into(), v.to_owned()));
        }
    }

    fn set_all(&mut self, name: &str, values: &[String]) {
        self.options
            .extend(values.iter().map(|v| (name.into(), v.clone())));
    }

    fn mark(&mut self, name: &str, on: bool) {
        if on {
            self.flags.push(name.into());
        }
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
        "advertisement" => {
            let deployment = args.deployment()?;
            let (pins, _) = args.pins(&paths, false)?;
            Ok(flows::advertisements(
                &pins.realm,
                &pins.anchors,
                &deployment,
            ))
        }
        "status" => flows::status(&paths),
        "check" => flows::check(&paths, args.option("server")),
        "leave" => flows::leave(&paths),
        other => Err(format!("unknown command {other:?}").into()),
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
    let cli = Cli::parse();
    krb5_config_fallback(&Paths::from_env());
    trace::init(if cli.trace {
        trace::Level::Details
    } else if cli.verbose {
        trace::Level::Steps
    } else {
        trace::Level::Off
    });
    let args = cli.args();
    tracing::debug!("kuipa {}", args.command);
    match run(&args) {
        Ok(value) => {
            if cli.json {
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
