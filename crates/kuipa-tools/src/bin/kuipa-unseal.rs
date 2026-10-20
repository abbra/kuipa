//! `kuipa-unseal`: the unattended unseal path (§10.5, §7.3, §7.4).
//!
//! ```text
//! kuipa-unseal            file mode: write /run/ipa/krb5.keytab
//! kuipa-unseal --memfd    gssproxy keytab_loader: write the keytab to the
//!                          memfd inherited as file descriptor 3
//! ```
//!
//! `--verbose` / `--trace` (or `KUIPA_TRACE`) trace the requests on
//! standard error, as for `kuipa`.
//!
//! Runs in its own SELinux domain: it only reads the sealed keytab, anchors
//! and CA, talks to the IPA servers, and writes the result.  It has no
//! Kerberos client rights, so it never rebinds; `kuipa rotate-keys` (on a
//! timer) refreshes the bindings.
//!
//! Exit status: 0 success, 75 no server could unseal (retry later), 1 error.

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use kuipa_tools::flows::{self, Outcome};
use kuipa_tools::paths::{self, Error, Paths};
use kuipa_tools::trace;

#[derive(Parser)]
#[command(
    about = "Unseal the machine keytab without a human: the unattended unseal \
path used at boot and by gssproxy's keytab_loader.",
    after_help = "This runs in its own SELinux domain: it only reads the sealed \
keytab, anchors and CA, talks to the IPA servers, and writes the result.  It has \
no Kerberos client rights, so it never rebinds; `kuipa rotate-keys` (on a timer) \
refreshes the bindings.  Exit status: 0 success, 75 no server could unseal (retry \
later), 1 error, 2 usage."
)]
struct Args {
    /// Write the keytab to the memfd inherited as file descriptor 3
    /// (`gssproxy keytab_loader`) instead of `/run/ipa/krb5.keytab`.
    #[arg(long)]
    memfd: bool,
    /// Trace each request and decision on standard error.
    #[arg(long)]
    verbose: bool,
    /// Trace with wire details (`$KUIPA_TRACE` overrides with `tracing`
    /// filter directives).
    #[arg(long)]
    trace: bool,
}

fn run(memfd: bool) -> Result<(), Error> {
    let paths = Paths::from_env();
    let keytab = flows::unseal(&paths)?;
    let bytes = keytab.to_mit()?;
    if memfd {
        // The loader protocol: gssproxy passes a memfd as fd 3.
        let mut fd = std::fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/fd/3")?;
        fd.write_all(bytes.as_ref())?;
    } else {
        paths::write_file(&paths.run_keytab(), bytes.as_ref(), 0o600)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();
    trace::init(if args.trace {
        trace::Level::Details
    } else if args.verbose {
        trace::Level::Steps
    } else {
        trace::Level::Off
    });
    match run(args.memfd) {
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
