//! `kuipa-voucher`: issue enrollment vouchers with blind signatures (§9).
//!
//! ```text
//! Issuer (holds the voucher key, sees only blinded requests):
//! kuipa-voucher keygen --key F [--alg ml-dsa-44|ml-dsa-65|ml-dsa-87]
//!                                   write the voucher key; print its public
//!                                   JWK (for kuipad add-voucher-key)
//! kuipa-voucher quota --quota F --limit N
//!                                   set how many vouchers may be issued
//! kuipa-voucher sign --key F --quota F
//!                                   sign the request on standard input;
//!                                   print the response
//!
//! Provisioner (knows what each voucher allows):
//! kuipa-voucher request --public JWK --realm R --fqdn H --server S [--hostgroup G]
//!                        [--days N] [--binding B] --state F
//!                                   blind a voucher; print the request
//! kuipa-voucher finish --state F   unblind the response on standard input;
//!                                   print the voucher
//! kuipa-voucher show               print the claims of the voucher on
//!                                   standard input
//! ```
//!
//! `--binding` is what `kuipa voucher-key` printed on the host: the voucher
//! then works only with that host's ephemeral key.  Without it the voucher
//! is a bearer credential until used.  Vouchers are valid for `--days`
//! (default 7) from now.
//!
//! Exit status: 0 success, 1 error, 2 usage.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use kuipa_enroll::voucher::{Claims, Voucher};
use kuipa_tools::paths::Error;
use kuipa_tools::voucher;
use native_ossl::util::SecretBuf;
use tang_pqc::{SignatureAlg, b64};

#[derive(Parser)]
#[command(
    about = "Issue enrollment vouchers with blind signatures.",
    after_help = "--binding is what `kuipa voucher-key` printed on the host: the \
voucher then works only with that host's ephemeral key.  Without it the voucher \
is a bearer credential until used.  Exit status: 0 success, 1 error, 2 usage."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a new voucher key and print its public JWK, for kuipad's
    /// add-voucher-key.
    Keygen {
        /// Key file to write.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        /// Signature algorithm: ml-dsa-44, ml-dsa-65 or ml-dsa-87.
        #[arg(long, value_name = "ALG", default_value = "ml-dsa-65")]
        alg: String,
    },
    /// Set how many vouchers may be issued in all.
    Quota {
        /// Quota file to update.
        #[arg(long, value_name = "FILE")]
        quota: PathBuf,
        /// Maximum number of vouchers.
        #[arg(long, value_name = "N")]
        limit: u64,
    },
    /// Sign the blinded request on standard input; print the response.
    Sign {
        /// The voucher key.
        #[arg(long, value_name = "FILE")]
        key: PathBuf,
        /// The quota file to count against.
        #[arg(long, value_name = "FILE")]
        quota: PathBuf,
    },
    /// Blind a voucher for a host; print the request for `sign`.
    Request {
        /// File holding the issuer's public JWK (what `keygen` printed).
        #[arg(long, value_name = "FILE")]
        public: PathBuf,
        /// The realm the voucher admits a host to.
        #[arg(long, value_name = "REALM")]
        realm: String,
        /// The host the voucher admits.
        #[arg(long, value_name = "FQDN")]
        fqdn: String,
        /// The IPA server that owns the voucher's single use.  A server
        /// that gets the join asks this one to spend the salt, so it must
        /// stay a member of the realm until the voucher is used or expires.
        #[arg(long, value_name = "FQDN")]
        server: String,
        /// Only hosts of this IPA host group.
        #[arg(long, value_name = "GROUP")]
        hostgroup: Option<String>,
        /// Days the voucher is valid from now.
        #[arg(long, value_name = "N", default_value = "7")]
        days: u64,
        /// The host lives this many hours from its join, and the realm
        /// then removes it (`DESIGN-ci.md` §1): for CI runners.
        #[arg(long, value_name = "HOURS")]
        lease_hours: Option<u64>,
        /// Binding from `kuipa voucher-key`, base64.  Base64url may
        /// start with `-`, so hyphen-leading values are allowed.
        #[arg(long, value_name = "BASE64", allow_hyphen_values = true)]
        binding: Option<String>,
        /// State file `finish` needs: the unblinding is kept there, not
        /// on the issuer.
        #[arg(long, value_name = "FILE")]
        state: PathBuf,
    },
    /// Unblind the response on standard input; print the voucher.
    Finish {
        /// The state file written by `request`.
        #[arg(long, value_name = "FILE")]
        state: PathBuf,
    },
    /// Print the claims of the voucher on standard input, as JSON.
    Show,
}

fn stdin() -> Result<SecretBuf, Error> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(SecretBuf::new(buf))
}

fn stdin_text() -> Result<String, Error> {
    Ok(String::from_utf8(stdin()?.as_ref().to_vec())?)
}

fn alg(name: &str) -> Result<SignatureAlg, Error> {
    name.to_ascii_uppercase()
        .parse()
        .map_err(|_| format!("unknown algorithm {name:?}").into())
}

fn run(command: Command) -> Result<(), Error> {
    match command {
        Command::Keygen { key, alg: name } => {
            let alg = alg(&name)?;
            println!("{}", voucher::keygen(&key, alg)?);
        }
        Command::Quota { quota, limit } => {
            let q = voucher::set_quota(&quota, limit)?;
            println!("{} of {} issued", q.issued, q.limit);
        }
        Command::Sign { key, quota } => {
            let response = voucher::sign(&key, &quota, &stdin_text()?)?;
            println!("{response}");
        }
        Command::Request {
            public,
            realm,
            fqdn,
            server,
            hostgroup,
            days,
            lease_hours,
            binding,
            state,
        } => {
            let lease = match lease_hours {
                Some(0) => return Err("--lease-hours must be at least 1".into()),
                Some(h) => h.checked_mul(3600).ok_or("--lease-hours is too large")?,
                None => 0,
            };
            let binding = match binding {
                Some(b) => Some(b64::decode(&b)?)
                    .filter(|b| kuipa_enroll::voucher::is_binding_len(b.len()))
                    .ok_or("--binding is not a binding")?,
                None => Vec::new(),
            };
            let now = tang_pqc::now();
            let validity = days
                .checked_mul(86400)
                .and_then(|s| now.checked_add(s))
                .ok_or("--days is too large")?;
            let claims = Claims {
                realm,
                fqdn: fqdn.to_ascii_lowercase(),
                server: server.to_ascii_lowercase(),
                hostgroup: hostgroup.unwrap_or_default(),
                not_before: now.saturating_sub(300),
                not_after: validity,
                lease,
                binding,
            };
            let request = voucher::request(&kuipa_tools::paths::read(&public)?, &claims, &state)?;
            println!("{request}");
        }
        Command::Finish { state } => {
            let v = voucher::finish(&state, &stdin_text()?)?;
            println!("{}", String::from_utf8_lossy(v.encode().as_ref()));
        }
        Command::Show => {
            let v = Voucher::parse(stdin()?.as_ref())?;
            let c = v.claims();
            println!(
                "{}",
                serde_json::json!({
                    "key": v.key().to_string(),
                    "realm": c.realm,
                    "fqdn": c.fqdn,
                    "server": c.server,
                    "hostgroup": c.hostgroup,
                    "not_before": c.not_before,
                    "not_after": c.not_after,
                    "lease": c.lease,
                    "bound": c.is_bound(),
                })
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    kuipa_tools::cli::finish("kuipa-voucher", run(cli.command))
}
