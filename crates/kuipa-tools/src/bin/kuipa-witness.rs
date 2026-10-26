//! `kuipa-witness`: cosign the realm's transparency-log heads
//! (DESIGN-tlog.md §4).
//!
//! ```text
//! kuipa-witness keygen --key FILE [--alg ml-dsa-44|ml-dsa-65|ml-dsa-87]
//!                          a witness key (private JWK, 0600); prints the
//!                          public JWK for `kuipad add-witness-key`
//! kuipa-witness run --key FILE --state FILE --server S… [--anchor THP…]
//!                   [--interval SECS] [--once]
//!                          cosign each server's head when it extends the
//!                          last one cosigned
//! ```
//!
//! The witness fetches only public routes and posts only cosignatures.
//! Its key is the default profile's witness algorithm, ML-DSA-44, unless
//! the system crypto policy refuses it (a CNSA 2.0 policy: ML-DSA-87).
//! Exit status for `run --once`: 0 when no log is forked, 2 otherwise.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use tang_pqc::{SignatureAlg, SigningKey};

#[derive(Parser)]
#[command(
    name = "kuipa-witness",
    about = "Cosign a realm's transparency-log heads that extend the last ones cosigned."
)]
struct Cli {
    /// Print reports as JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Make a witness key.
    Keygen {
        /// The private key file to write (mode 0600).
        #[arg(long)]
        key: PathBuf,
        /// ml-dsa-44 (the default where allowed), ml-dsa-65 or ml-dsa-87.
        #[arg(long)]
        alg: Option<String>,
    },
    /// Cosign the servers' heads.
    Run {
        /// The witness's private key file.
        #[arg(long)]
        key: PathBuf,
        /// The last head cosigned per log.
        #[arg(long)]
        state: PathBuf,
        /// The servers to witness; repeatable.
        #[arg(long, required = true)]
        server: Vec<String>,
        /// Anchors to verify the servers' advertisements with; repeatable.
        /// Default: this host's pinned anchors.
        #[arg(long, allow_hyphen_values = true)]
        anchor: Vec<String>,
        /// Seconds between passes (default 60).
        #[arg(long, default_value = "60")]
        interval: u64,
        /// One pass, then exit.
        #[arg(long)]
        once: bool,
    },
}

fn algorithm(name: Option<&str>) -> Result<SignatureAlg, String> {
    match name {
        Some("ml-dsa-44") => Ok(SignatureAlg::MlDsa44),
        Some("ml-dsa-65") => Ok(SignatureAlg::MlDsa65),
        Some("ml-dsa-87") => Ok(SignatureAlg::MlDsa87),
        Some(other) => Err(format!("unknown algorithm {other:?}")),
        // The witness role defaults to ML-DSA-44; a policy without it
        // (CNSA 2.0) falls back to what it allows.
        None => match SignatureAlg::MlDsa44.allowed_by_system() {
            Ok(true) => Ok(SignatureAlg::MlDsa44),
            Ok(false) => SignatureAlg::preferred().map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
    }
}

fn keygen(key: &std::path::Path, alg: Option<&str>) -> Result<String, String> {
    if key.exists() {
        return Err(format!("{} already exists", key.display()));
    }
    let signing = SigningKey::generate(algorithm(alg)?).map_err(|e| e.to_string())?;
    let private = signing.to_jwk().map_err(|e| e.to_string())?;
    kuipa_tools::paths::write_file(key, private.as_ref(), 0o600).map_err(|e| e.to_string())?;
    Ok(signing.public().to_jwk_json())
}

fn report(json: bool, value: &serde_json::Value) {
    if json {
        println!("{value}");
        return;
    }
    for row in value["servers"].as_array().into_iter().flatten() {
        println!(
            "{:>10}  {}: {} leaves",
            row["state"].as_str().unwrap_or_default(),
            row["server"].as_str().unwrap_or_default(),
            row["size"].as_u64().unwrap_or_default()
        );
    }
}

fn forked(value: &serde_json::Value) -> bool {
    value["servers"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|r| r["state"] == "forked")
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Command::Keygen { key, alg } => match keygen(key, alg.as_deref()) {
            Ok(public) => {
                println!("{public}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("kuipa-witness keygen: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Run {
            key,
            state,
            server,
            anchor,
            interval,
            once,
        } => {
            let signing = match std::fs::read(key)
                .map_err(|e| e.to_string())
                .and_then(|b| SigningKey::from_jwk(&b).map_err(|e| e.to_string()))
            {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("kuipa-witness: {}: {e}", key.display());
                    return ExitCode::FAILURE;
                }
            };
            let anchors: Result<Vec<tang_pqc::Thumbprint>, _> =
                anchor.iter().map(|a| a.parse()).collect();
            let Ok(anchors) = anchors else {
                eprintln!("kuipa-witness: bad --anchor thumbprint");
                return ExitCode::from(2);
            };
            loop {
                match kuipa_tools::witness::pass(&signing, server, &anchors, state) {
                    Ok(value) => {
                        report(cli.json, &value);
                        if *once {
                            return if forked(&value) {
                                ExitCode::from(2)
                            } else {
                                ExitCode::SUCCESS
                            };
                        }
                    }
                    Err(e) => {
                        eprintln!("kuipa-witness: {e}");
                        if *once {
                            return ExitCode::FAILURE;
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs((*interval).max(1)));
            }
        }
    }
}
