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
//! kuipa-voucher request --public JWK --realm R --fqdn H [--hostgroup G]
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
use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use kuipa_enroll::voucher::{Claims, Voucher};
use kuipa_tools::paths::Error;
use kuipa_tools::voucher;
use native_ossl::util::SecretBuf;
use tang_pqc::{SignatureAlg, b64, unix_seconds};

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
        key: String,
        /// Signature algorithm: ml-dsa-44, ml-dsa-65 or ml-dsa-87.
        #[arg(long, value_name = "ALG", default_value = "ml-dsa-65")]
        alg: String,
    },
    /// Set how many vouchers may be issued in all.
    Quota {
        /// Quota file to update.
        #[arg(long, value_name = "FILE")]
        quota: String,
        /// Maximum number of vouchers.
        #[arg(long, value_name = "N")]
        limit: String,
    },
    /// Sign the blinded request on standard input; print the response.
    Sign {
        /// The voucher key.
        #[arg(long, value_name = "FILE")]
        key: String,
        /// The quota file to count against.
        #[arg(long, value_name = "FILE")]
        quota: String,
    },
    /// Blind a voucher for a host; print the request for `sign`.
    Request {
        /// The issuer's public JWK (printed by `keygen`).
        #[arg(long, value_name = "FILE")]
        public: String,
        /// The realm the voucher admits a host to.
        #[arg(long, value_name = "REALM")]
        realm: String,
        /// The host the voucher admits.
        #[arg(long, value_name = "FQDN")]
        fqdn: String,
        /// Only hosts of this IPA host group.
        #[arg(long, value_name = "GROUP")]
        hostgroup: Option<String>,
        /// Days the voucher is valid from now.
        #[arg(long, value_name = "N", default_value = "7")]
        days: String,
        /// Binding from `kuipa voucher-key`, base64.  Base64url may
        /// start with `-`, so hyphen-leading values are allowed.
        #[arg(long, value_name = "BASE64", allow_hyphen_values = true)]
        binding: Option<String>,
        /// State file `finish` needs: the unblinding is kept there, not
        /// on the issuer.
        #[arg(long, value_name = "FILE")]
        state: String,
    },
    /// Unblind the response on standard input; print the voucher.
    Finish {
        /// The state file written by `request`.
        #[arg(long, value_name = "FILE")]
        state: String,
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
    match name.to_ascii_lowercase().as_str() {
        "ml-dsa-44" => Ok(SignatureAlg::MlDsa44),
        "ml-dsa-65" => Ok(SignatureAlg::MlDsa65),
        "ml-dsa-87" => Ok(SignatureAlg::MlDsa87),
        _ => Err(format!("unknown algorithm {name:?}").into()),
    }
}

fn run(command: Command) -> Result<(), Error> {
    match command {
        Command::Keygen { key, alg: name } => {
            let alg = alg(&name)?;
            println!("{}", voucher::keygen(Path::new(&key), alg)?);
        }
        Command::Quota { quota, limit } => {
            let q = voucher::set_quota(Path::new(&quota), limit.parse()?)?;
            println!("{} of {} issued", q.issued, q.limit);
        }
        Command::Sign { key, quota } => {
            let response = voucher::sign(Path::new(&key), Path::new(&quota), &stdin_text()?)?;
            println!("{response}");
        }
        Command::Request {
            public,
            realm,
            fqdn,
            hostgroup,
            days,
            binding,
            state,
        } => {
            let days: u64 = days.parse()?;
            let binding = match binding {
                Some(b) => b64::decode(&b)?
                    .try_into()
                    .map_err(|_| "--binding is not a binding")?,
                None => [0; 32],
            };
            let now = unix_seconds(std::time::SystemTime::now());
            let validity = days
                .checked_mul(86400)
                .and_then(|s| now.checked_add(s))
                .ok_or("--days is too large")?;
            let claims = Claims {
                realm,
                fqdn: fqdn.to_ascii_lowercase(),
                hostgroup: hostgroup.unwrap_or_default(),
                not_before: now.saturating_sub(300),
                not_after: validity,
                binding,
            };
            let request = voucher::request(&std::fs::read(&public)?, &claims, Path::new(&state))?;
            println!("{request}");
        }
        Command::Finish { state } => {
            let v = voucher::finish(Path::new(&state), &stdin_text()?)?;
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
                    "hostgroup": c.hostgroup,
                    "not_before": c.not_before,
                    "not_after": c.not_after,
                    "bound": c.is_bound(),
                })
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kuipa-voucher: {e}");
            ExitCode::FAILURE
        }
    }
}
