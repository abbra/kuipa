//! `kuipa-gitsign`: sign and verify git commits and tags with
//! Kerberos-bound statements (`DESIGN-sign.md`), as git's
//! `gpg.x509.program`:
//!
//! ```text
//! git config gpg.format x509
//! git config gpg.x509.program kuipa-gitsign
//! git config user.signingkey kuipa      # any value: the ticket decides
//! git commit -S …; git verify-commit HEAD
//! ```
//!
//! Git signs by running `kuipa-gitsign --status-fd=2 -bsau <key>` with
//! the payload on standard input, and takes the armored signature from
//! standard output; it verifies by running `kuipa-gitsign
//! --status-fd=<fd> --verify <signature file> -` with the payload on
//! standard input, and reads gpg-style status lines from `<fd>`.  The
//! signer is the principal of the default ticket, not the signing key;
//! the purpose is `git-commit` (`KUIPA_GITSIGN_PURPOSE` overrides it).
//! Verification is offline, against this host's pinned anchors.
//!
//! Forges show these signatures as unverified: they know gpg, ssh and
//! S/MIME signatures, not kuipa's.

use std::io::{Read, Write};
use std::process::ExitCode;

use kuipa_enroll::sign::{Bundle, Digest, DigestAlg, Request};
use kuipa_tools::paths::{Paths, PublicState};

const BEGIN: &str = "-----BEGIN SIGNED MESSAGE-----";
const END: &str = "-----END SIGNED MESSAGE-----";

type Error = Box<dyn std::error::Error + Send + Sync>;

/// Armor `bytes` the way git recognises an x509 signature.
fn armor(bytes: &[u8]) -> String {
    let b64 = tang_pqc::b64::encode(bytes);
    let mut out = format!("{BEGIN}\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

fn dearmor(text: &str) -> Result<Vec<u8>, Error> {
    let body = text
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(b, _)| b)
        .ok_or("not a kuipa-gitsign signature")?;
    let joined: String = body.split_whitespace().collect();
    Ok(tang_pqc::b64::decode(&joined)?)
}

/// Where status lines go: `--status-fd=1` is standard output, anything
/// else standard error.
fn status_fd(args: &[String]) -> u32 {
    args.iter()
        .find_map(|a| a.strip_prefix("--status-fd="))
        .and_then(|n| n.parse().ok())
        .unwrap_or(2)
}

fn status(fd: u32, line: &str) {
    let line = format!("[GNUPG:] {line}\n");
    if fd == 1 {
        let _ = std::io::stdout().write_all(line.as_bytes());
    } else {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

fn payload() -> Result<Vec<u8>, Error> {
    let mut data = Vec::new();
    std::io::stdin().read_to_end(&mut data)?;
    Ok(data)
}

fn sign(args: &[String]) -> Result<(), Error> {
    let purpose = std::env::var("KUIPA_GITSIGN_PURPOSE").unwrap_or_else(|_| "git-commit".into());
    let asked = Request {
        purpose,
        digests: vec![Digest::of(DigestAlg::Sha256, &payload()?)?],
    };
    let host = Paths::from_env();
    let bundles = kuipa_tools::sign::request(&host, None, &asked)?;
    let bundle = bundles.first().ok_or("the server answered no bundle")?;
    std::io::stdout().write_all(armor(&bundle.to_bytes()).as_bytes())?;
    // Git requires this line before it accepts the signature.
    status(status_fd(args), "SIG_CREATED D 22 8 00 0 kuipa");
    Ok(())
}

fn verify(args: &[String]) -> Result<bool, Error> {
    let fd = status_fd(args);
    let file = args
        .iter()
        .skip_while(|a| *a != "--verify")
        .nth(1)
        .ok_or("--verify needs the signature file")?;
    let bundle = Bundle::from_bytes(&dearmor(&std::fs::read_to_string(file)?)?)?;
    let host = Paths::from_env();
    let public = PublicState::load(&host)?;
    let anchors = kuipa_tools::paths::read_anchors(&host)?;
    status(fd, "NEWSIG");
    match bundle.verify(
        &payload()?,
        &public.realm,
        &anchors,
        &tang_pqc::Policy::from_system()?,
    ) {
        Ok(v) => {
            let id = format!("{}#{}", v.log, v.index);
            status(fd, &format!("GOODSIG {id} {}", v.principal));
            status(fd, &format!("VALIDSIG {id} {} {}", v.iat, v.iat));
            status(fd, "TRUST_FULLY 0 shell");
            eprintln!(
                "kuipa-gitsign: Good signature by {} for {}, stated by {} at {}",
                v.principal,
                v.purpose,
                v.server,
                kuipa_tools::text::date(v.iat).unwrap_or_else(|| v.iat.to_string())
            );
            Ok(true)
        }
        Err(e) => {
            status(fd, "BADSIG kuipa unknown");
            eprintln!("kuipa-gitsign: BAD signature: {e}");
            Ok(false)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.iter().any(|a| a == "--verify") {
        verify(&args).map(|good| {
            if good {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        })
    } else if args
        .iter()
        .any(|a| a == "--sign" || (a.starts_with('-') && !a.starts_with("--") && a.contains('s')))
    {
        sign(&args).map(|()| ExitCode::SUCCESS)
    } else {
        Err(
            "usage: kuipa-gitsign (-bsau KEY | --verify SIGNATURE -), as git's gpg.x509.program"
                .into(),
        )
    };
    result.unwrap_or_else(|e| {
        eprintln!("kuipa-gitsign: {e}");
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn armor_round_trips_and_is_git_shaped() {
        let bytes: Vec<u8> = (0..=255).collect();
        let armored = armor(&bytes);
        assert!(armored.starts_with(BEGIN));
        assert!(
            armored
                .lines()
                .all(|l| l.len() <= 64 || l.starts_with("-----"))
        );
        assert_eq!(dearmor(&armored).unwrap(), bytes);
        assert!(dearmor("-----BEGIN PGP SIGNATURE-----\nAA\n").is_err());
        assert_eq!(status_fd(&["--status-fd=1".into()]), 1);
        assert_eq!(status_fd(&[]), 2);
    }
}
