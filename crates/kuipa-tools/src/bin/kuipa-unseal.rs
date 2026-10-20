//! `kuipa-unseal`: the unattended unseal path (§10.5, §7.3, §7.4, §7.5).
//!
//! ```text
//! kuipa-unseal            file mode: write /run/ipa/krb5.keytab
//! kuipa-unseal --memfd    gssproxy keytab_loader: write the keytab to the
//!                          memfd inherited as file descriptor 3
//! kuipa-unseal --all      boot: the host keytab if protected, and the
//!                          unsealed copy of every other protected keytab
//!                          and file
//! kuipa-unseal --sealed S [--out F | --out - [--force] | --memfd]
//!                          one sealed keytab or file: to F, to standard
//!                          output, to fd 3, or to its unsealed copy when
//!                          kuipa protected it
//! ```
//!
//! `--out -` writes to standard output as it is (a pipe or a file the shell
//! opened), and refuses a terminal unless `--force`: keys and secrets do not
//! belong in a scrollback.  Any other `--out` must name a regular file or
//! nothing yet, outside `/dev`: it is replaced atomically, which for a
//! symlink such as `/dev/stdout` would replace the link itself.
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

use std::io::{IsTerminal, Write};
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
    /// Where to write what `--sealed` holds, `-` for standard output
    /// (default: its unsealed copy, for one `kuipa protect` sealed).
    #[arg(long, value_name = "FILE", requires = "sealed")]
    out: Option<PathBuf>,
    /// With `--out -`, write to standard output even when it is a terminal.
    #[arg(long, requires = "out")]
    force: bool,
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

/// Where `--out` sends what was unsealed.
#[derive(Clone, Copy)]
enum Output<'a> {
    Stdout,
    File(&'a Path),
}

/// Check `--out` before anything is sent to a server.
fn output(out: &Path, force: bool) -> Result<Output<'_>, Error> {
    if out == Path::new("-") {
        if std::io::stdout().is_terminal() && !force {
            return Err("standard output is a terminal: redirect it, or give --force".into());
        }
        return Ok(Output::Stdout);
    }
    let absolute = std::path::absolute(out)?;
    if absolute.starts_with("/dev") {
        return Err(format!("--out {}: use `--out -` for standard output", out.display()).into());
    }
    match std::fs::symlink_metadata(out) {
        Ok(m) if !m.file_type().is_file() => Err(format!(
            "--out {}: not a regular file (it would be replaced, not written to)",
            out.display()
        )
        .into()),
        _ => Ok(Output::File(out)),
    }
}

fn unseal_one(
    paths: &Paths,
    sealed: &Path,
    out: Option<Output<'_>>,
    memfd: bool,
) -> Result<(), Error> {
    let bytes = flows::unseal_file(paths, sealed)?;
    if memfd {
        return write_memfd(bytes.as_ref());
    }
    match out {
        Some(Output::Stdout) => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(bytes.as_ref())?;
            stdout.flush()?;
            return Ok(());
        }
        Some(Output::File(out)) => return paths::write_file(out, bytes.as_ref(), 0o600),
        None => {}
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
        let out = args
            .out
            .as_deref()
            .map(|o| output(o, args.force))
            .transpose()?;
        return unseal_one(&paths, &sealed, out, args.memfd);
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
