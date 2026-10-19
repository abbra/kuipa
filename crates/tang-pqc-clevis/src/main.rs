//! `tang-pqc`: post-quantum Tang from the command line, and its Clevis pin.
//!
//! ```text
//! tang-pqc adv URL [--ca FILE]         list the signing keys URL advertises
//! tang-pqc encrypt CONFIG < IN > JWE   encrypt for a Tang server (CONFIG: JSON)
//! tang-pqc decrypt < JWE > OUT         recover the key and decrypt
//! ```
//!
//! Installed (or linked) as `clevis-encrypt-tang-pqc` and
//! `clevis-decrypt-tang-pqc`, it is the Clevis pin `tang-pqc`:
//!
//! ```text
//! clevis encrypt tang-pqc '{"url":"https://ipa1.example.test/ipa/ku/tang","thp":"…"}' < IN > JWE
//! clevis decrypt < JWE > OUT
//! clevis luks bind -d /dev/vda2 tang-pqc '{"url":…,"thp":…}'
//! ```
//!
//! Exit status: 0 success, 1 error, 2 usage.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tang_pqc_clevis::{Config, Error};

#[derive(Parser)]
#[command(
    about = "Post-quantum Tang from the command line (the Tang side of the \
tang-pqc Clevis pin).",
    long_about = "Installed (or linked) as clevis-encrypt-tang-pqc and \
clevis-decrypt-tang-pqc, the same binary is the Clevis pin `tang-pqc`:\n  \
clevis encrypt tang-pqc '{\"url\":…,\"thp\":…}' < IN > JWE\n  clevis decrypt < JWE \
> OUT\n  clevis luks bind -d /dev/vda2 tang-pqc '{\"url\":…,\"thp\":…}'",
    after_help = "Exit status: 0 success, 1 error, 2 usage."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the thumbprints of the signing keys URL advertises.
    Adv {
        /// Tang server base URL, e.g.
        /// `<https://ipa1.example.test/ipa/ku/tang>`.
        url: String,
        /// A PEM file to verify an https server against.
        #[arg(long, value_name = "FILE")]
        ca: Option<String>,
    },
    /// Encrypt standard input for a Tang server; print the JWE.
    ///
    /// CONFIG is JSON:
    /// {"url":"https://…","thp":"…","adv":"…","ca":"…"}; thp must be a
    /// thumbprint listed by `adv`.
    Encrypt {
        /// The server pin configuration, as JSON.
        config: String,
    },
    /// Recover the key from the JWE on standard input; print the plaintext.
    Decrypt,
}
const ENCRYPT_USAGE: &str = r"Usage: clevis encrypt tang-pqc CONFIG < PLAINTEXT > JWE

Encrypts using a post-quantum Tang (tang-pqc) binding server policy

This command uses the following configuration properties:

  url: <string>   The base URL of the Tang server (REQUIRED)

  thp: <string>   The thumbprint of a trusted signing key (REQUIRED;
                  `tang-pqc adv URL` lists them)

  adv: <string>   A filename containing a trusted advertisement

  ca:  <string>   A PEM file to verify an https server against
";

fn stdin() -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn encrypt(config: &str) -> Result<(), Error> {
    let config = Config::parse(config)?;
    let jwe = tang_pqc_clevis::encrypt(&config, &stdin()?)?;
    println!("{jwe}");
    Ok(())
}

fn decrypt() -> Result<(), Error> {
    let jwe = String::from_utf8(stdin()?)?;
    let plaintext = tang_pqc_clevis::decrypt(&jwe)?;
    std::io::stdout().write_all(plaintext.as_ref())?;
    Ok(())
}

fn adv(url: &str, ca: Option<&str>) -> Result<(), Error> {
    let config = Config {
        url: url.to_owned(),
        thp: None,
        adv: None,
        ca: ca.map(PathBuf::from),
    };
    for thp in tang_pqc_clevis::signing_keys(&config)? {
        println!("{thp}");
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().collect();
    let name = args
        .first()
        .and_then(|a| std::path::Path::new(a).file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    args.remove(0);
    let (prog, result) = match name.as_str() {
        "clevis-encrypt-tang-pqc" => {
            if args.first().map(String::as_str) == Some("--summary") {
                println!("Encrypts using a post-quantum Tang (tang-pqc) binding server policy");
                return ExitCode::SUCCESS;
            }
            if std::io::stdin().is_terminal() || args.len() != 1 {
                eprint!("{ENCRYPT_USAGE}");
                return ExitCode::from(2);
            }
            (name.clone(), encrypt(&args[0]))
        }
        "clevis-decrypt-tang-pqc" => (name.clone(), decrypt()),
        _ => {
            let cli = Cli::parse();
            let result = match cli.command {
                Command::Adv { url, ca } => adv(&url, ca.as_deref()),
                Command::Encrypt { config } => encrypt(&config),
                Command::Decrypt => decrypt(),
            };
            ("tang-pqc".to_owned(), result)
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{prog}: {e}");
            ExitCode::FAILURE
        }
    }
}
