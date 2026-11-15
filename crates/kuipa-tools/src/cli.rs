//! What the command-line tools share: the tracing flags and the exit status.

use std::process::ExitCode;

use crate::flows::Outcome;
use crate::paths::Error;
use crate::trace;

/// The `--verbose` and `--trace` flags.
#[derive(clap::Args)]
pub struct Tracing {
    /// Trace each request, decision and file written on standard error.
    #[arg(long, global = true)]
    verbose: bool,
    /// Trace with wire details (`$KUIPA_TRACE` overrides with `tracing`
    /// filter directives).
    #[arg(long, global = true)]
    trace: bool,
}

impl Tracing {
    /// Install the subscriber these flags (or `$KUIPA_TRACE`) ask for.
    pub fn init(&self) {
        trace::init(if self.trace {
            trace::Level::Details
        } else if self.verbose {
            trace::Level::Steps
        } else {
            trace::Level::Off
        });
    }
}

/// Report a failure of `prog` on standard error and map it to the exit
/// status: 75 when the caller should retry later, 1 otherwise.
#[must_use]
pub fn finish(prog: &str, result: Result<(), Error>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{prog}: {e}");
            if Outcome::is_retry(&e) {
                ExitCode::from(75)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
