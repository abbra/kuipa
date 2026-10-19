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

use kuipa_enroll::voucher::{Claims, Voucher};
use kuipa_tools::paths::Error;
use kuipa_tools::voucher;
use native_ossl::util::SecretBuf;
use tang_pqc::{SignatureAlg, b64, unix_seconds};

const USAGE: &str = "usage: kuipa-voucher {keygen|quota|sign|request|finish|show} [options]";

const VALUED: &[&str] = &[
    "key",
    "alg",
    "quota",
    "limit",
    "public",
    "realm",
    "fqdn",
    "hostgroup",
    "days",
    "binding",
    "state",
];

struct Args {
    command: String,
    options: Vec<(String, String)>,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut it = std::env::args().skip(1);
        let command = it.next().ok_or(USAGE)?;
        let mut options = Vec::new();
        while let Some(arg) = it.next() {
            let name = arg
                .strip_prefix("--")
                .filter(|n| VALUED.contains(n))
                .ok_or_else(|| format!("unexpected argument {arg:?}\n{USAGE}"))?;
            let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
            options.push((name.to_owned(), value));
        }
        Ok(Self { command, options })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn need(&self, name: &str) -> Result<&str, Error> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required").into())
    }
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

fn run(args: &Args) -> Result<(), Error> {
    match args.command.as_str() {
        "keygen" => {
            let alg = alg(args.get("alg").unwrap_or("ml-dsa-65"))?;
            println!("{}", voucher::keygen(Path::new(args.need("key")?), alg)?);
        }
        "quota" => {
            let q =
                voucher::set_quota(Path::new(args.need("quota")?), args.need("limit")?.parse()?)?;
            println!("{} of {} issued", q.issued, q.limit);
        }
        "sign" => {
            let response = voucher::sign(
                Path::new(args.need("key")?),
                Path::new(args.need("quota")?),
                &stdin_text()?,
            )?;
            println!("{response}");
        }
        "request" => {
            let days: u64 = args.get("days").unwrap_or("7").parse()?;
            let binding = match args.get("binding") {
                Some(b) => b64::decode(b)?
                    .try_into()
                    .map_err(|_| "--binding is not a binding")?,
                None => [0; 32],
            };
            let now = unix_seconds(std::time::SystemTime::now());
            let claims = Claims {
                realm: args.need("realm")?.to_owned(),
                fqdn: args.need("fqdn")?.to_ascii_lowercase(),
                hostgroup: args.get("hostgroup").unwrap_or_default().to_owned(),
                not_before: now.saturating_sub(300),
                not_after: now + days * 86400,
                binding,
            };
            let public = std::fs::read(args.need("public")?)?;
            let request = voucher::request(&public, &claims, Path::new(args.need("state")?))?;
            println!("{request}");
        }
        "finish" => {
            let v = voucher::finish(Path::new(args.need("state")?), &stdin_text()?)?;
            println!("{}", String::from_utf8_lossy(v.encode().as_ref()));
        }
        "show" => {
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
        other => return Err(format!("unknown command {other:?}\n{USAGE}").into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("kuipa-voucher: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kuipa-voucher: {e}");
            ExitCode::FAILURE
        }
    }
}
