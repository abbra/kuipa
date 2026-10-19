//! `kuipa-unseal`: the unattended unseal path (§3, §7.3, §7.5).
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

use kuipa_tools::flows::{self, Outcome};
use kuipa_tools::paths::{self, Error, Paths};
use kuipa_tools::trace;

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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let memfd = args.iter().any(|a| a == "--memfd");
    trace::init(if args.iter().any(|a| a == "--trace") {
        trace::Level::Details
    } else if args.iter().any(|a| a == "--verbose") {
        trace::Level::Steps
    } else {
        trace::Level::Off
    });
    match run(memfd) {
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
