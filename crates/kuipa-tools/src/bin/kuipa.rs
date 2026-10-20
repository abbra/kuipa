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
//! kuipa protect | unprotect --keytab F      the same for another keytab: a
//!                                            service's or a user's
//! kuipa protect | unprotect --file F [--keytab K]
//!                                            the same for any file, sealed
//!                                            for K's principal (default: the
//!                                            host)
//! kuipa trusted-realms                      accept users of the realms this
//!                                            realm trusts (their KDCs and
//!                                            PKINIT anchors, verified)
//! kuipa advertisement [--server S... | --domain D]
//!                     [--enrollment-file F | --realm R]
//!                                            what each server
//!                                            advertises, verified, the
//!                                            realm's anchor log: its
//!                                            landmark chain (§4.8), and a
//!                                            per-key index: for every
//!                                            anchor or signing key seen,
//!                                            what it belongs to and where
//!                                            it appears
//! kuipa status | check [--server S]         is this host healthy?
//! kuipa seal …                              a user's own vaults: create,
//!                                            devices, seal and open files
//!                                            (runs as the user, with their
//!                                            ticket)
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
use kuipa_enroll::keytab::Principal;
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
    /// Seal the host keytab on disk, or another keytab or any file; run
    /// again to reseal what is there now.
    Protect {
        #[command(flatten)]
        target: ProtectTarget,
    },
    /// Put the host keytab, or another keytab or file, back on disk in
    /// plain form.
    Unprotect {
        #[command(flatten)]
        target: ProtectTarget,
    },
    /// Print the realms this realm trusts (their KDCs and PKINIT anchors,
    /// verified), so their users can log in here.
    TrustedRealms,
    /// Print what each server of the deployment advertises, verified
    /// against the enrollment string's anchor or the pre-provisioned
    /// pins, and the realm's anchor log (landmarks) it names.
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
    /// Seal your own files to a vault of yours: runs as you, with your
    /// Kerberos ticket.
    Seal {
        #[command(subcommand)]
        action: SealAction,
    },
}

/// `kuipa seal` subcommands.
#[derive(Subcommand)]
enum SealAction {
    /// Create a vault.
    Create {
        /// The vault's name.
        vault: String,
        #[command(flatten)]
        policy: PolicyInput,
    },
    /// Replace a vault's policy.
    Policy {
        /// The vault.
        vault: String,
        #[command(flatten)]
        policy: PolicyInput,
    },
    /// Register or remove this host's device key.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Seal a file to a vault (offline when this host has a recent
    /// description of the vault).
    File {
        /// The vault.
        vault: String,
        /// The file to seal.
        file: String,
        /// Where to write the sealed file (default: FILE.sealed).
        #[arg(long, value_name = "FILE")]
        out: Option<String>,
        /// Seal for offline sessions: opens without a server while one
        /// lasts, and only then.
        #[arg(long)]
        session: bool,
    },
    /// Open a sealed file.
    Open {
        /// The sealed file.
        sealed: String,
        /// Where to write the plaintext: a file, or `-` for standard output.
        #[arg(long, value_name = "FILE")]
        out: String,
        /// With `--out -`, write to standard output even when it is a
        /// terminal.
        #[arg(long)]
        force: bool,
        /// Read the device key's passphrase from this file.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
    },
    /// Open sealed files and seal them again to the vault's current
    /// devices.
    Reseal {
        /// The vault.
        vault: String,
        /// The sealed files, rewritten in place.
        sealed: Vec<String>,
        /// Read the device key's passphrase from this file.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
    },
    /// Start a session: until it ends, files of the vault open on this
    /// host without the passphrase or a ticket.
    Unlock {
        /// The vault.
        vault: String,
        /// Read the device key's passphrase from this file.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
        /// An offline session: files sealed with --session open without a
        /// server until it ends.
        #[arg(long)]
        offline: bool,
    },
    /// End the vault's session on this host.
    Lock {
        /// The vault.
        vault: String,
    },
    /// With registered sealing: make sealed files, and every copy of
    /// them, unopenable.
    Retire {
        /// The vault.
        vault: String,
        /// The sealed files.
        sealed: Vec<String>,
    },
    /// Describe a vault.
    Show {
        /// The vault.
        vault: String,
    },
    /// Describe all your vaults.
    List,
    /// Revoke a vault: no file sealed to it opens any more.
    Revoke {
        /// The vault.
        vault: String,
    },
}

/// `kuipa seal device` subcommands.
#[derive(Subcommand)]
enum DeviceAction {
    /// Register this host's device key in a vault, making it (under a
    /// passphrase) if this host has none, or using an ML-KEM key on a
    /// PKCS#11 token.
    Add {
        /// The vault.
        vault: String,
        /// Read the passphrase (or the token's PIN) from this file.
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<String>,
        /// The ML-KEM key on a token, as a `pkcs11:` URI.
        #[arg(long, value_name = "URI")]
        pkcs11: Option<String>,
        /// The token's PKCS#11 module.
        #[arg(
            long,
            value_name = "PATH",
            requires = "pkcs11",
            default_value = "/usr/lib64/p11-kit-proxy.so"
        )]
        module: String,
    },
    /// Remove a device from a vault.
    Remove {
        /// The vault.
        vault: String,
        /// The device's id (see `kuipa seal show`).
        id: String,
    },
}

/// A vault policy on the command line.
#[derive(clap::Args)]
struct PolicyInput {
    /// Factors an unlock needs besides the server: `device` (or
    /// `device=hardware-wrapped`, `device=hardware-bound`), `ticket`;
    /// comma-separated or repeated.
    #[arg(long, value_name = "FACTORS", value_delimiter = ',', required = true)]
    require: Vec<String>,
    /// How many days the vault lives (default: the realm's limit).
    #[arg(long, value_name = "DAYS")]
    expires: Option<u64>,
    /// Which delegated tickets satisfy `ticket`: `allow` or `refuse`.
    #[arg(long, value_name = "allow|refuse", conflicts_with = "ticket_via")]
    ticket_delegation: Option<String>,
    /// Accept delegated tickets only through these services.
    #[arg(long, value_name = "SERVICE")]
    ticket_via: Vec<String>,
    /// How many times, in all, the servers may open files of the vault.
    #[arg(long, value_name = "N")]
    max_unlocks: Option<u64>,
    /// Allow sessions of up to this many hours (`kuipa seal unlock`).
    #[arg(long, value_name = "HOURS")]
    session_hours: Option<u64>,
    /// Allow offline sessions of up to this many hours (`kuipa seal unlock
    /// --offline`), where the realm allows them.
    #[arg(long, value_name = "HOURS")]
    offline_hours: Option<u64>,
    /// How many days one offline-session key serves new files.
    #[arg(long, value_name = "DAYS", requires = "offline_hours")]
    epoch_days: Option<u64>,
    /// `registered`: sealing needs a server, and resealing or `kuipa seal
    /// retire` makes old copies unopenable (default: `offline`).
    #[arg(long, value_name = "offline|registered")]
    sealing: Option<String>,
}

impl PolicyInput {
    fn policy(&self) -> Result<kuipa_enroll::vault::Policy, Error> {
        use kuipa_enroll::vault::{Factors, Level, Policy, TicketDelegation};
        let mut factors = Factors::default();
        for f in &self.require {
            match f.trim() {
                "device" | "device=any" => factors.device = Some(Level::Any),
                "device=hardware-wrapped" => factors.device = Some(Level::HardwareWrapped),
                "device=hardware-bound" => factors.device = Some(Level::HardwareBound),
                "ticket" => factors.ticket = true,
                "passkey" => factors.passkey = true,
                other => return Err(format!("unknown factor {other:?}").into()),
            }
        }
        let ticket_delegation = match (
            self.ticket_delegation.as_deref(),
            self.ticket_via.is_empty(),
        ) {
            (_, false) => TicketDelegation::Via(self.ticket_via.clone()),
            (None | Some("allow"), true) => TicketDelegation::Allow,
            (Some("refuse"), true) => TicketDelegation::Refuse,
            (Some(other), true) => {
                return Err(format!("--ticket-delegation {other:?}: allow or refuse").into());
            }
        };
        let not_after = self
            .expires
            .map(|days| tang_pqc::unix_seconds(std::time::SystemTime::now()) + days * 86_400);
        let sealing = match self.sealing.as_deref() {
            None | Some("offline") => kuipa_enroll::vault::Sealing::Offline,
            Some("registered") => kuipa_enroll::vault::Sealing::Registered,
            Some(other) => return Err(format!("--sealing {other:?}: offline or registered").into()),
        };
        Ok(Policy {
            factors,
            ticket_delegation,
            not_after,
            sealing,
            max_unlocks: self.max_unlocks,
            sessions: kuipa_enroll::vault::Sessions {
                reauth: self.session_hours.map(|h| h * 3600),
                offline: self.offline_hours.map(|h| h * 3600),
                epoch: self.epoch_days.map(|d| d * 86_400),
            },
        })
    }
}

/// What `protect` and `unprotect` act on: the host keytab by default.
#[derive(clap::Args)]
struct ProtectTarget {
    /// Another keytab (a service's or a user's), sealed for its own
    /// principal; with --file, the keytab of the principal to seal the
    /// file for (default: the host keytab).
    #[arg(long, value_name = "FILE")]
    keytab: Option<String>,
    /// Any file, sealed for the principal of --keytab.
    #[arg(long, value_name = "FILE")]
    file: Option<String>,
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
            Command::Protect { .. } => "protect",
            Command::Unprotect { .. } => "unprotect",
            Command::TrustedRealms => "trusted-realms",
            Command::Advertisement { .. } => "advertisement",
            Command::Status => "status",
            Command::Check { .. } => "check",
            Command::Leave => "leave",
            Command::Seal { .. } => "seal",
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
            Command::Protect { target } | Command::Unprotect { target } => {
                a.set("keytab", target.keytab.as_deref());
                a.set("file", target.file.as_deref());
            }
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

    /// `--keytab` and `--file`, for `protect` and `unprotect`.
    fn protect_target(&self) -> flows::Target {
        let path = |name| self.option(name).map(std::path::PathBuf::from);
        match (path("file"), path("keytab")) {
            (Some(path), keytab) => flows::Target::File { path, keytab },
            (None, Some(keytab)) => flows::Target::Keytab(keytab),
            (None, None) => flows::Target::Host,
        }
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
        "protect" => flows::protect(&paths, &args.protect_target()),
        "unprotect" => flows::unprotect(&paths, &args.protect_target()),
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
// ── The result for a person ──────────────────────────────────────────────
//
// `--json` prints the object a flow built.  Without it the same values are
// labelled and their subject named: which host, which file on this host,
// which server vouched for what.  The JSON keys alone read the same on
// every host and never say where a value came from.

/// The rows of one block: labels are ours, values are the flow's.  Labels
/// are right-aligned to one column, so the values line up under it while
/// each row still reads `label: value` — `grep` for a label and its value
/// matches whatever else the block contains.  `Null` and a false flag are
/// not shown; an empty name or list says `none`, a list of names goes on
/// one line.
#[derive(Default)]
struct Rows {
    indent: usize,
    width: usize,
    lines: Vec<(String, String)>,
}

impl Rows {
    fn row(&mut self, label: &str, value: String) {
        self.width = self.width.max(label.len());
        self.lines.push((label.to_string(), value));
    }

    fn field(&mut self, label: &str, value: &Value) {
        if matches!(value, Value::Null | Value::Bool(false)) {
            return;
        }
        let text = match value {
            Value::Bool(true) => "yes".to_string(),
            Value::String(s) if s.is_empty() => "none".to_string(),
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Array(items) if items.iter().all(Value::is_string) => {
                let names: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                }
            }
            other => other.to_string(),
        };
        self.row(label, text);
    }

    /// A duration a flow measured against this host's clock, with its unit.
    fn left(&mut self, label: &str, value: &Value, unit: &str) {
        if value.is_null() {
            return;
        }
        self.row(
            label,
            format!("{} {unit} left", value.as_u64().unwrap_or_default()),
        );
    }

    /// A Unix time a flow recorded, as a date.  `synta`'s `GeneralizedTime`
    /// does the civil-date arithmetic, in UTC.
    fn until(&mut self, label: &str, value: &Value) {
        let Some(secs) = value.as_u64() else { return };
        match synta::GeneralizedTime::from_unix(i64::try_from(secs).unwrap_or(i64::MAX)) {
            Some(t) => self.row(
                label,
                format!(
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                    t.year, t.month, t.day, t.hour, t.minute, t.second
                ),
            ),
            None => self.row(label, secs.to_string()),
        }
    }

    /// A file on this host.
    fn path(&mut self, label: &str, path: &std::path::Path) {
        self.row(label, path.display().to_string());
    }

    /// Rows are only printed once the block is complete: the column width
    /// is the widest label it holds.  On a terminal the labels are
    /// emphasised, as `clap` emphasises its help; the padding is written
    /// before the escape codes, so the column is identical either way.
    fn print(&self) {
        if emphasise() {
            for (label, value) in &self.lines {
                println!(
                    "{:>indent$}{}\x1b[1m{label}\x1b[0m: {value}",
                    "",
                    " ".repeat(self.width - label.len()),
                    indent = self.indent,
                );
            }
        } else {
            for (label, value) in &self.lines {
                println!(
                    "{:>indent$}{:>width$}: {value}",
                    "",
                    label,
                    indent = self.indent,
                    width = self.width,
                );
            }
        }
    }
}

/// Whether to emphasise labels: `anstream`'s decision, the same one `clap`
/// applies to its own help (`$NO_COLOR`, `$CLICOLOR`, `$CLICOLOR_FORCE`,
/// `$TERM`, whether standard output is a terminal), so `kuipa --help` and a
/// rendered block agree on where emphasis goes.  Anything that is not an
/// ANSI terminal — a pipe, a Windows wincon console — gets plain labels.
fn emphasise() -> bool {
    anstream::AutoStream::choice(&std::io::stdout()) == anstream::ColorChoice::Always
}

/// Strings a flow collected, one per line under `heading`'s indent.
fn items(values: &Value, indent: &str) {
    for item in values.as_array().into_iter().flatten() {
        println!("{indent}{}", item.as_str().unwrap_or(&item.to_string()));
    }
}
/// This host, from its state file: the principal it holds keys for.
fn this_host(paths: &Paths) -> String {
    match paths::State::load(paths) {
        Ok(state) => format!(
            "{} (state file: {})",
            Principal::host(&state.fqdn, &state.realm),
            paths.state().display()
        ),
        // `State::load` says "this host is not enrolled with kuipa (no
        // state file)"; the sentence this is inserted into already names
        // this host, so keep only the reason.
        Err(e) => {
            let e = e.to_string();
            match e.strip_prefix("this host is ") {
                Some(reason) => format!("this host, {reason}"),
                None => format!("this host ({e})"),
            }
        }
    }
}

fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

/// Print one command's result: what it is about, where each value came
/// from, then the values themselves.
fn render(command: &str, args: &Args, value: &Value, paths: &Paths) {
    match command {
        "prepare" => render_prepare(value, paths),
        "enroll" => render_enroll(value, paths),
        "voucher-key" => render_voucher_key(args, value),
        "realm-info" => render_realm_info(value),
        "trusted-realms" => render_trusted_realms(value, paths),
        "advertisement" => render_advertisement(value, paths),
        "status" => render_status(value, paths),
        "check" => render_check(value, paths),
        "complete" => render_complete(value),
        "rotate-keys" => render_rotated(value, "New host keys"),
        "protect" if get(value, "contents").is_string() => render_protect_other(value),
        "protect" => render_protect(value),
        "unprotect" if get(value, "contents").is_string() => render_unprotect_other(value),
        "unprotect" => println!(
            "The keytab is plain on disk again; its holder is now {}.",
            get(value, "holder").as_str().unwrap_or("none")
        ),
        "leave" => println!(
            "{}: kuipa's own files are removed; the plain keytab is left for ipa-join --unenroll.",
            this_host(paths)
        ),
        // Every command above has a renderer; anything else shows the object.
        other => println!("{other}: {value}"),
    }
}
fn render_prepare(value: &Value, paths: &Paths) {
    println!(
        "A machine key for offline enrollment, made on this host and stored in {}:",
        paths.recipient().display()
    );
    let mut rows = Rows::default();
    rows.field("machine key thumbprint", get(value, "thumbprint"));
    rows.field("its public key", get(value, "public_key"));
    rows.field(
        "the IPA administrator stages it with",
        get(value, "admin_command"),
    );
    rows.print();
}

/// Identity and realm values of a join, as one aligned block.
fn identity_rows(rows: &mut Rows, value: &Value) {
    rows.field("principal", get(value, "principal"));
    rows.field("kvno", get(value, "kvno"));
    rows.field("issuer", get(value, "issuer"));
}

/// Files a command wrote on this host, as a nested block.
fn installed_rows(rows: &Rows, paths: &Paths) {
    println!("{:>indent$}installed here:", "", indent = rows.indent);
    let mut files = Rows {
        indent: rows.indent + 2,
        ..Rows::default()
    };
    files.path("host keys", &paths.keytab());
    files.path("IPA CA", &paths.ca());
    files.path("pinned anchors", &paths.anchors());
    files.path("PKINIT anchors", &paths.pkinit_anchors());
    files.path("Kerberos configuration", &paths.krb5_conf());
    files.path("state", &paths.state());
    files.print();
}

/// The steps an offline enrollment left for `complete`, if any.
fn pending_rows(value: &Value, done: &str) {
    let Some(pending) = value.get("pending").filter(|p| !p.is_null()) else {
        return;
    };
    println!("  {done} for {}:", get(pending, "fqdn"));
    let mut rows = Rows {
        indent: 2,
        ..Rows::default()
    };
    rows.until(
        "the staged bundle is usable until",
        get(pending, "not_after"),
    );
    println!("{:>2}deferred steps:", "");
    items(get(pending, "steps"), "    ");
}

fn render_enroll(value: &Value, paths: &Paths) {
    // An offline enrollment reports the same summary under `enrollment`,
    // plus the steps `complete` still has to do.
    let summary = value.get("enrollment").unwrap_or(value);
    println!(
        "Enrolled {} in {}: its keys, the realm's anchors, CA and Kerberos configuration all taken from {}'s verified advertisement.",
        get(summary, "principal").as_str().unwrap_or("this host"),
        get(summary, "realm").as_str().unwrap_or(""),
        get(summary, "issuer")
            .as_str()
            .unwrap_or("the issuing server")
    );
    let mut rows = Rows::default();
    identity_rows(&mut rows, summary);
    rows.field("realm", get(summary, "realm"));
    rows.field("IPA servers", get(summary, "servers"));
    rows.field("domain", get(summary, "domain"));
    rows.field("LDAP base", get(summary, "basedn"));
    rows.print();
    installed_rows(&rows, paths);
    pending_rows(
        value,
        "staged, to finish at first contact (`kuipa complete`)",
    );
}

fn render_voucher_key(args: &Args, value: &Value) {
    println!(
        "An ephemeral key for this host, written to {}; a voucher carries its binding so that only this host can open it:",
        args.option("out").unwrap_or("")
    );
    let mut rows = Rows::default();
    rows.field("binding for kuipa-voucher --binding", get(value, "binding"));
    rows.print();
}

fn render_realm_info(value: &Value) {
    println!(
        "Kerberos configuration for {}, from {}'s verified advertisement:",
        get(value, "realm").as_str().unwrap_or(""),
        get(value, "server")
            .as_str()
            .unwrap_or("the first usable server")
    );
    let mut rows = Rows::default();
    rows.field("realm", get(value, "realm"));
    rows.field("domain", get(value, "domain"));
    rows.field("KDCs", get(value, "servers"));
    rows.field("krb5.conf", get(value, "krb5_conf"));
    rows.field("PKINIT anchors", get(value, "pkinit_anchors"));
    rows.field("IPA CA", get(value, "ca"));
    rows.print();
}

fn render_trusted_realms(value: &Value, paths: &Paths) {
    println!(
        "Realms {} trusts, each verified through the servers it advertises and installed on this host:",
        get(value, "realm").as_str().unwrap_or("this realm")
    );
    for t in list(get(value, "trusted_realms")) {
        println!();
        let mut rows = Rows::default();
        rows.field("realm", get(t, "realm"));
        rows.field("what kuipa did", get(t, "status"));
        rows.field("verified through", get(t, "server"));
        rows.field("why it is not installed", get(t, "error"));
        rows.field("krb5.conf.d snippet", get(t, "krb5_conf"));
        if let Some(realm) = get(t, "realm").as_str() {
            rows.path("anchors, PKINIT anchors and CA", &paths.trust_dir(realm));
        }
        rows.print();
    }
}

fn render_advertisement(value: &Value, paths: &Paths) {
    println!(
        "What each server of the deployment advertises, verified against the anchors pinned in {}:",
        paths.anchors().display()
    );
    for s in list(get(value, "servers")) {
        println!();
        let server = get(s, "server").as_str().unwrap_or("server");
        if get(s, "ok") == &Value::Bool(false) {
            println!(
                "{server}: {}",
                get(s, "error").as_str().unwrap_or("unusable")
            );
            continue;
        }
        let mut rows = Rows::default();
        rows.field("server", get(s, "server"));
        rows.field("advertises realm", get(s, "realm"));
        rows.field("domain", get(s, "domain"));
        rows.field("KDCs", get(s, "kdcs"));
        rows.field("advertisement signed by", get(s, "signer"));
        rows.field("delegated by this pinned anchor", get(s, "proven_by"));
        rows.left("its delegation", get(s, "delegation_days_left"), "days");
        rows.left("the anchor's vouch", get(s, "vouch_hours_left"), "hours");
        rows.field("anchor successions it names", get(s, "rotated_anchors"));
        rows.field("join key", get(s, "join_key"));
        rows.field("escrow key", get(s, "escrow_key"));
        rows.field("CA certificates offered", get(s, "ca_certs"));
        rows.field("PKINIT anchors offered", get(s, "pkinit_anchors"));
        rows.field("its anchors", get(s, "anchors"));
        // `REALM (anchors …)`: a trusted realm is only useful to a reader
        // together with the anchors vouched for it (§17).
        let trusts = list(get(s, "trusts"))
            .into_iter()
            .map(|t| {
                let anchors = list(get(t, "anchors"))
                    .into_iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{} (anchors: {anchors})",
                    get(t, "realm").as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        rows.row(
            "realms it trusts",
            if trusts.is_empty() {
                "none".to_string()
            } else {
                trusts
            },
        );
        rows.field("anchor log head it names", get(s, "anchor_log_head"));
        rows.print();
        let landmarks = list(get(s, "landmarks"));
        if landmarks.is_empty() {
            println!("  anchor log: this server records none");
            continue;
        }
        println!("  its anchor log, every entry verified from sequence 0 up:");
        for l in landmarks {
            println!(
                "    sequence {} head {} (follows {})",
                get(l, "seq"),
                get(l, "head").as_str().unwrap_or(""),
                get(l, "prev").as_str().unwrap_or("")
            );
            let mut entry = Rows {
                indent: 4,
                ..Rows::default()
            };
            entry.field("anchors then current", get(l, "anchors"));
            entry.field("successions then current", get(l, "successions"));
            entry.print();
        }
    }
    anchor_index_rows(value);
}

/// The same facts read the other way round: one line per key, naming what
/// it is and everywhere it appears, so `grep <thumbprint>` answers the
/// question without reading every server block.  Labels are the
/// thumbprints, all the same width, so the values line up.
fn anchor_index_rows(value: &Value) {
    let names = |a: &Value, key: &str| {
        list(get(a, key))
            .into_iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let anchors = list(get(value, "anchors"));
    let pinned = list(get(value, "pinned"))
        .into_iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    println!();
    println!("  pinned on this host: {pinned}");
    if anchors.is_empty() {
        println!("  no server named an anchor, so nothing to index");
        return;
    }
    println!("  every key these servers named, and what it belongs to:");
    let mut rows = Rows {
        indent: 2,
        ..Rows::default()
    };
    for a in anchors {
        let key = get(a, "key").as_str().unwrap_or("key");
        let mut what: Vec<String> = Vec::new();
        if get(a, "pinned") == &Value::Bool(true) {
            what.push("pinned on this host".to_string());
        }
        let servers = names(a, "signer_of");
        if !servers.is_empty() {
            what.push(format!("signs {servers}' advertisements"));
        }
        let servers = names(a, "proves");
        if !servers.is_empty() {
            what.push(format!("proves the claim of {servers}"));
        }
        let current = names(a, "current_of");
        if !current.is_empty() {
            what.push(format!("a current anchor of {current}"));
        }
        let sequences = list(get(a, "log_sequences"))
            .into_iter()
            .filter_map(Value::as_u64)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if !sequences.is_empty() {
            what.push(format!("current in the anchor log at sequence {sequences}"));
        }
        let by = names(a, "replaced_by");
        if !by.is_empty() {
            what.push(format!("replaced by {by}"));
        }
        let old = names(a, "replaces");
        if !old.is_empty() {
            what.push(format!("replaces {old}"));
        }
        let realms = names(a, "trust_of");
        if !realms.is_empty() {
            what.push(format!("an anchor of the trusted realm {realms}"));
        }
        if current.is_empty() && sequences.is_empty() && by.is_empty() && old.is_empty() {
            // A signer, or a proof that only reaches the current anchor
            // through a succession: named, but no server here calls it an
            // anchor now.
            what.push("not an anchor of any server here".to_string());
        }
        rows.row(key, what.join("; "));
    }
    rows.print();
}

fn render_status(value: &Value, paths: &Paths) {
    println!("What kuipa has installed for {}", this_host(paths));
    if get(value, "enrolled") == &Value::Bool(false) {
        println!(
            "  enrolled: no{}",
            match get(value, "prepared") {
                Value::Bool(true) => ", though it is prepared for offline enrollment",
                _ => "",
            }
        );
        return;
    }
    let mut rows = Rows::default();
    identity_rows(&mut rows, value);
    rows.field("realm", get(value, "realm"));
    rows.field("IPA servers", get(value, "servers"));
    rows.field("anchors pinned here", get(value, "anchors"));
    rows.field("trusted realms installed", get(value, "trusted_realms"));
    rows.field("keytab held by", get(value, "protection"));
    rows.field(
        "also protected",
        &Value::Array(
            list(get(value, "protected"))
                .into_iter()
                .map(|p| {
                    Value::String(format!(
                        "{} ({} for {})",
                        get(p, "path").as_str().unwrap_or("?"),
                        get(p, "contents").as_str().unwrap_or("?"),
                        get(p, "principal").as_str().unwrap_or("?")
                    ))
                })
                .collect(),
        ),
    );
    rows.path("keytab", &paths.keytab());
    rows.path("krb5.conf fallback", &paths.krb5_conf());
    rows.path("IPA CA", &paths.ca());
    rows.path("PKINIT anchors", &paths.pkinit_anchors());
    rows.path("pinned anchors", &paths.anchors());
    let allowed: Vec<&str> = get(value, "policy")
        .as_object()
        .into_iter()
        .flat_map(|flags| flags.iter())
        .filter(|(_, allowed)| allowed.as_bool().unwrap_or(false))
        .map(|(kem, _)| kem.as_str())
        .collect();
    rows.field(
        "post-quantum KEMs this host allows",
        &Value::String(allowed.join(", ")),
    );
    rows.print();
    pending_rows(value, "an offline enrollment is unfinished");
}

fn render_check(value: &Value, paths: &Paths) {
    println!(
        "Health of {}, checked against the anchors pinned in {}:",
        this_host(paths),
        paths.anchors().display()
    );
    println!("  servers:");
    for s in list(get(value, "servers")) {
        let server = get(s, "server").as_str().unwrap_or("server");
        if get(s, "ok") == &Value::Bool(false) {
            println!(
                "    {server}: {}",
                get(s, "error").as_str().unwrap_or("unusable")
            );
            continue;
        }
        println!("    {server}: advertisement verified");
        let mut health = Rows {
            indent: 8,
            ..Rows::default()
        };
        health.left("delegation", get(s, "delegation_days_left"), "days");
        health.left("the anchor's vouch", get(s, "vouch_hours_left"), "hours");
        health.field(
            "verified only through rotated anchors",
            get(s, "rotated_anchors"),
        );
        health.print();
    }
    let mut host = Rows {
        indent: 2,
        ..Rows::default()
    };
    host.row(
        "a ticket with the host keys",
        if get(value, "kinit").as_bool().unwrap_or(false) {
            "yes".to_string()
        } else {
            "no".to_string()
        },
    );
    host.print();
    println!("  problems:");
    let problems = list(get(value, "problems"));
    if problems.is_empty() {
        println!("    none");
    } else {
        for p in problems {
            println!("    {}", p.as_str().unwrap_or(&p.to_string()));
        }
    }
}

fn render_complete(value: &Value) {
    println!(
        "The offline enrollment is finished: the staged keys were replaced by keys from {}'s KDC.",
        get(get(value, "rotated"), "issuer")
            .as_str()
            .unwrap_or("the issuing server")
    );
    let mut rows = Rows::default();
    identity_rows(&mut rows, get(value, "rotated"));
    rows.print();
    println!("  left for ipa-client-install on this host:");
    items(get(value, "remaining_for_ipa_client_install"), "    ");
}

fn render_rotated(value: &Value, what: &str) {
    println!(
        "{what}, issued by {}:",
        get(value, "issuer")
            .as_str()
            .unwrap_or("the issuing server")
    );
    let mut rows = Rows::default();
    identity_rows(&mut rows, value);
    rows.print();
}

fn render_protect(value: &Value) {
    println!(
        "The keytab is sealed on disk: opening it needs one of the realm's servers, as at boot."
    );
    let rotated = get(value, "rotated");
    println!(
        "Keys reissued before sealing, issued by {}:",
        get(rotated, "issuer")
            .as_str()
            .unwrap_or("the issuing server")
    );
    let mut rows = Rows::default();
    identity_rows(&mut rows, rotated);
    rows.field("sealed as", get(value, "sealed"));
    rows.print();
}

fn render_protect_other(value: &Value) {
    let path = get(value, "path").as_str().unwrap_or("the file");
    println!(
        "{path} is {} on disk: opening it needs one of the realm's servers, as at boot.",
        if get(value, "resealed").as_bool().unwrap_or(false) {
            "sealed again, as it is now"
        } else {
            "sealed"
        }
    );
    let mut rows = Rows::default();
    rows.field("holds", get(value, "contents"));
    rows.field("bindings registered for", get(value, "principal"));
    rows.field("registered by", get(value, "registered_by"));
    rows.field("servers that can unseal it", get(value, "servers"));
    rows.field("sealed as", get(value, "sealed"));
    rows.field("unsealed copy (tmpfs)", get(value, "unsealed_copy"));
    rows.print();
}

fn render_unprotect_other(value: &Value) {
    println!(
        "{} is plain on disk again.",
        get(value, "path").as_str().unwrap_or("The file")
    );
    if get(value, "retired").as_bool().unwrap_or(false) {
        println!(
            "  Its bindings for {} are retired: no copy of the sealed file opens any more.",
            get(value, "principal").as_str().unwrap_or("its principal")
        );
    } else {
        println!(
            "  Its bindings for {} are still registered ({}): a copy of the sealed file (in a backup or an old image) still opens until an administrator clears them, or until it is protected and unprotected again with a server reachable.",
            get(value, "principal").as_str().unwrap_or("its principal"),
            get(value, "retire_error")
                .as_str()
                .unwrap_or("no server answered")
        );
    }
}

fn list(value: &Value) -> Vec<&Value> {
    value
        .as_array()
        .map_or_else(Vec::new, |a| a.iter().collect())
}

/// A passphrase from `file`, or asked for on the terminal (twice when
/// `confirm`).
fn passphrase(file: Option<&str>, confirm: bool) -> Result<SecretBuf, Error> {
    let value = match file {
        Some(path) => first_line(&SecretBuf::new(std::fs::read(path)?)),
        None if std::io::stdin().is_terminal() => {
            let first = prompt("device key passphrase or token PIN", true)?;
            if confirm && prompt("the same passphrase again", true)?.as_ref() != first.as_ref() {
                return Err("the passphrases differ".into());
            }
            first
        }
        None => return Err("no passphrase: give --passphrase-file or run on a terminal".into()),
    };
    if value.as_ref().is_empty() {
        return Err("missing passphrase".into());
    }
    Ok(value)
}

/// `kuipa seal …`: as the user, with their ticket.
fn run_seal(paths: &Paths, action: &SealAction) -> Result<Value, Error> {
    let user = kuipa_tools::seal::UserPaths::from_env()?;
    let seal = kuipa_tools::seal::Seal::new(paths, &user, None);
    match action {
        SealAction::Create { vault, policy } => seal.create(vault, policy.policy()?),
        SealAction::Policy { vault, policy } => seal.set_policy(vault, policy.policy()?),
        SealAction::Device { action } => match action {
            DeviceAction::Add {
                vault,
                passphrase_file,
                pkcs11,
                module,
            } => {
                if let Some(uri) = pkcs11 {
                    let pin = passphrase(passphrase_file.as_deref(), false)?;
                    seal.add_token_device(vault, std::path::Path::new(module), uri, pin.as_ref())
                } else {
                    let first = !user.device_key().exists() && !user.token_device().exists();
                    let pass = passphrase(passphrase_file.as_deref(), first)?;
                    seal.add_device(vault, pass.as_ref())
                }
            }
            DeviceAction::Remove { vault, id } => seal.remove_device(vault, id),
        },
        SealAction::File {
            vault,
            file,
            out,
            session,
        } => {
            let out = out.clone().unwrap_or_else(|| format!("{file}.sealed"));
            let contents = std::fs::read(file)?;
            let sealed = if *session {
                seal.seal_session(vault, &contents)?
            } else {
                seal.seal(vault, &contents)?
            };
            paths::write_file(std::path::Path::new(&out), &sealed, 0o600)?;
            Ok(serde_json::json!({ "vault": vault, "file": file, "sealed": out }))
        }
        SealAction::Open {
            sealed,
            out,
            force,
            passphrase_file,
        } => {
            let target = kuipa_tools::output::Output::check(std::path::Path::new(out), *force)?;
            let bytes = std::fs::read(sealed)?;
            let pass = kuipa_tools::seal::Seal::needs_secret(&bytes)
                .then(|| passphrase(passphrase_file.as_deref(), false))
                .transpose()?;
            let plain = seal.open(&bytes, pass.as_ref().map(AsRef::as_ref))?;
            target.write(plain.as_ref())?;
            Ok(serde_json::json!({
                "sealed": sealed,
                "written": out,
                // Standard output holds the plaintext: print nothing else.
                "quiet": matches!(target, kuipa_tools::output::Output::Stdout),
            }))
        }
        SealAction::Reseal {
            vault,
            sealed,
            passphrase_file,
        } => {
            let pass = passphrase(passphrase_file.as_deref(), false)?;
            for path in sealed {
                let again = seal.reseal(vault, &std::fs::read(path)?, Some(pass.as_ref()))?;
                paths::write_file(std::path::Path::new(path), &again, 0o600)?;
            }
            Ok(serde_json::json!({ "vault": vault, "resealed": sealed }))
        }
        SealAction::Unlock {
            vault,
            passphrase_file,
            offline,
        } => {
            let pass = passphrase(passphrase_file.as_deref(), false)?;
            seal.unlock(vault, pass.as_ref(), *offline)
        }
        SealAction::Lock { vault } => seal.lock(vault),
        SealAction::Retire { vault, sealed } => {
            for path in sealed {
                seal.retire(vault, &std::fs::read(path)?)?;
            }
            Ok(serde_json::json!({ "vault": vault, "retired": sealed }))
        }
        SealAction::Show { vault } => seal.show(vault),
        SealAction::List => seal.list(),
        SealAction::Revoke { vault } => seal.revoke(vault),
    }
}

fn render_seal(value: &Value) {
    if let Some(until) = get(value, "session_until").as_u64() {
        if get(value, "offline").as_bool().unwrap_or(false) {
            println!(
                "Offline session started: files sealed with --session open on this host without any server until {until} (Unix time), or `kuipa seal lock`."
            );
        } else {
            println!(
                "Session started: files open on this host without the passphrase or a ticket until {until} (Unix time), or `kuipa seal lock`."
            );
        }
    }
    if let Some(vaults) = get(value, "vaults").as_array() {
        if vaults.is_empty() {
            println!("No vaults.");
        }
        for v in vaults {
            println!(
                "Vault {} ({}), {}:",
                get(v, "name").as_str().unwrap_or("?"),
                get(v, "owner").as_str().unwrap_or("?"),
                get(v, "state").as_str().unwrap_or("?")
            );
            let mut rows = Rows::default();
            rows.field("id", get(v, "id"));
            let policy = get(v, "policy");
            let factors = get(policy, "factors");
            let mut needs = Vec::new();
            if let Some(level) = get(factors, "device").as_str() {
                needs.push(format!("a registered device ({level})"));
            }
            if get(factors, "ticket").as_bool().unwrap_or(false) {
                needs.push("your Kerberos ticket".to_owned());
            }
            rows.row("opening needs", needs.join(" and "));
            rows.field("expires (Unix time)", get(policy, "not_after"));
            rows.field("unlocks so far", get(v, "unlocks"));
            rows.field("unlocks allowed", get(policy, "max_unlocks"));
            rows.field(
                "longest session (seconds)",
                get(get(policy, "sessions"), "reauth"),
            );
            rows.field("delegated tickets", get(policy, "ticket_delegation"));
            let devices: Vec<Value> = list(get(v, "devices"))
                .into_iter()
                .map(|d| {
                    Value::String(format!(
                        "{} ({}, {}): {}",
                        get(d, "label").as_str().unwrap_or("?"),
                        get(d, "type").as_str().unwrap_or("?"),
                        get(d, "level").as_str().unwrap_or("?"),
                        get(d, "id").as_str().unwrap_or("?"),
                    ))
                })
                .collect();
            rows.field("devices", &Value::Array(devices));
            rows.field("described by", get(v, "signed_by"));
            rows.print();
        }
    } else if let Some(out) = get(value, "sealed").as_str()
        && get(value, "file").is_string()
    {
        println!(
            "{} is sealed to vault {} as {out}.",
            get(value, "file").as_str().unwrap_or("The file"),
            get(value, "vault").as_str().unwrap_or("?")
        );
    } else if get(value, "written").is_string() {
        println!(
            "{} is open in {}.",
            get(value, "sealed").as_str().unwrap_or("The file"),
            get(value, "written").as_str().unwrap_or("?")
        );
    } else if get(value, "retired").is_array() {
        println!("No copy of these opens any more:");
        items(get(value, "retired"), "  ");
    } else if let Some(name) = get(value, "locked").as_str() {
        println!("Vault {name}'s session on this host has ended.");
    } else if get(value, "resealed").is_array() {
        println!("Sealed again to the vault's current devices:");
        items(get(value, "resealed"), "  ");
    } else {
        println!("{value}");
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let paths = Paths::from_env();
    krb5_config_fallback(&paths);
    trace::init(if cli.trace {
        trace::Level::Details
    } else if cli.verbose {
        trace::Level::Steps
    } else {
        trace::Level::Off
    });
    let args = cli.args();
    tracing::debug!("kuipa {}", args.command);
    let result = match &cli.command {
        Command::Seal { action } => run_seal(&paths, action),
        _ => run(&args),
    };
    match result {
        Ok(value) => {
            if value.get("quiet") == Some(&Value::Bool(true)) {
                // Standard output carries a secret; nothing else goes there.
            } else if cli.json {
                println!("{value}");
            } else if args.command == "seal" {
                render_seal(&value);
            } else {
                render(&args.command, &args, &value, &paths);
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
