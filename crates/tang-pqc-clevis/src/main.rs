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
use std::process::ExitCode;

use tang_pqc_clevis::{Config, Error};

const USAGE: &str = "usage: tang-pqc {adv URL [--ca FILE] | encrypt CONFIG | decrypt}";
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

fn adv(args: &[String]) -> Result<(), Error> {
    let url = args.first().ok_or(USAGE)?;
    let ca = match args.get(1..) {
        Some([flag, file]) if flag == "--ca" => Some(file.into()),
        Some([]) | None => None,
        _ => return Err(USAGE.into()),
    };
    let config = Config {
        url: url.clone(),
        thp: None,
        adv: None,
        ca,
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
            let result = match args.first().map(String::as_str) {
                Some("adv") => adv(&args[1..]),
                Some("encrypt") if args.len() == 2 => encrypt(&args[1]),
                Some("decrypt") if args.len() == 1 => decrypt(),
                _ => {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
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
