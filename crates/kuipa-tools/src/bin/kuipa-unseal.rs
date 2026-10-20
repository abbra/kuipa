//! `kuipa-unseal`: the unattended unseal path (§10.5, §7.3, §7.4, §7.5).
//!
//! ```text
//! kuipa-unseal            file mode: write /run/ipa/krb5.keytab
//! kuipa-unseal --memfd    gssproxy keytab_loader: write the keytab to the
//!                          memfd inherited as file descriptor 3
//! kuipa-unseal --all      boot: the host keytab if protected, and the
//!                          unsealed copy of every other protected keytab
//!                          and file
//! kuipa-unseal --sealed S [--out F | --memfd]
//!                          one sealed keytab or file: to F, to fd 3, or to
//!                          its unsealed copy when kuipa protected it
//! ```
//!
//! `--verbose` / `--trace` (or `KUIPA_TRACE`) trace the requests on
//! standard error, as for `kuipa`.
//!
//! Runs in its own SELinux domain: it only reads the sealed keytabs and
//! files, anchors and CA, talks to the IPA servers, and writes the result.
//! It has no Kerberos client rights, so it never rebinds; `kuipa
//! rotate-keys` (on a timer) refreshes the host keytab's bindings.
//!
//! Exit status: 0 success, 75 no server could unseal (retry later), 1 error.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use kuipa_tools::flows::{self, Outcome};
use kuipa_tools::paths::{self, Error, Paths, State};
use kuipa_tools::trace;

#[derive(Parser)]
#[command(
    about = "Unseal the machine keytab, or another sealed keytab or file, without \
a human: the unattended unseal path used at boot and by gssproxy's keytab_loader.",
    after_help = "This runs in its own SELinux domain: it only reads the sealed \
keytabs and files, anchors and CA, talks to the IPA servers, and writes the result.  \
It has no Kerberos client rights, so it never rebinds; `kuipa rotate-keys` (on a \
timer) refreshes the host keytab's bindings.  Exit status: 0 success, 75 no server \
could unseal (retry later), 1 error, 2 usage."
)]
struct Args {
    /// Write the keytab to the memfd inherited as file descriptor 3
    /// (`gssproxy keytab_loader`) instead of `/run/ipa/krb5.keytab`.
    #[arg(long, conflicts_with_all = ["all", "out"])]
    memfd: bool,
    /// Unseal the host keytab if it is protected, and every other keytab
    /// and file `kuipa protect` sealed, each to its unsealed copy.
    #[arg(long, conflicts_with = "sealed")]
    all: bool,
    /// A sealed keytab or file to unseal instead of the host keytab.
    #[arg(long, value_name = "FILE")]
    sealed: Option<PathBuf>,
    /// Where to write what `--sealed` holds (default: its unsealed copy,
    /// for one `kuipa protect` sealed).
    #[arg(long, value_name = "FILE", requires = "sealed")]
    out: Option<PathBuf>,
    #[command(flatten)]
    tracing: Tracing,
}

#[derive(clap::Args)]
struct Tracing {
    /// Trace each request and decision on standard error.
    #[arg(long)]
    verbose: bool,
    /// Trace with wire details (`$KUIPA_TRACE` overrides with `tracing`
    /// filter directives).
    #[arg(long)]
    trace: bool,
}

/// The loader protocol: gssproxy passes a memfd as fd 3.
fn write_memfd(bytes: &[u8]) -> Result<(), Error> {
    let mut fd = std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/self/fd/3")?;
    fd.write_all(bytes)?;
    Ok(())
}

fn unseal_one(paths: &Paths, sealed: &Path, out: Option<&Path>, memfd: bool) -> Result<(), Error> {
    let bytes = flows::unseal_file(paths, sealed)?;
    if memfd {
        return write_memfd(bytes.as_ref());
    }
    if let Some(out) = out {
        return paths::write_file(out, bytes.as_ref(), 0o600);
    }
    let state = State::load(paths)?;
    let item = state
        .protected
        .iter()
        .find(|p| paths::sealed_for(&p.path) == sealed)
        .ok_or("kuipa did not protect this file: give --out or --memfd")?;
    let copy = paths.run_copy(&item.path);
    paths::write_file(&copy, bytes.as_ref(), item.mode)?;
    std::os::unix::fs::chown(&copy, Some(item.uid), Some(item.gid))?;
    Ok(())
}

fn run(args: &Args) -> Result<(), Error> {
    let paths = Paths::from_env();
    if args.all {
        flows::unseal_all(&paths)?;
        return Ok(());
    }
    if let Some(sealed) = &args.sealed {
        let sealed = std::path::absolute(sealed)?;
        return unseal_one(&paths, &sealed, args.out.as_deref(), args.memfd);
    }
    let keytab = flows::unseal(&paths)?;
    let bytes = keytab.to_mit()?;
    if args.memfd {
        write_memfd(bytes.as_ref())
    } else {
        paths::write_file(&paths.run_keytab(), bytes.as_ref(), 0o600)
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    trace::init(if args.tracing.trace {
        trace::Level::Details
    } else if args.tracing.verbose {
        trace::Level::Steps
    } else {
        trace::Level::Off
    });
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kuipa-unseal: {e}");
            if e.downcast_ref::<Outcome>()
                .is_some_and(|o| matches!(o, Outcome::RetryLater(_)))
            {
                ExitCode::from(75)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
