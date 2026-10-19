//! Tracing for the commands: what is requested from which server, what
//! comes back and what is written, on standard error (standard output
//! carries the result).
//!
//! `--verbose` shows each step, `--trace` adds the details below them.
//! `KUIPA_TRACE` takes `tracing-subscriber` filter directives instead
//! (`debug`, `kuipa_tools=trace,kuipa_gssapi=debug`, …) and wins over
//! both flags.  Secrets — OTPs, passwords, keys, GSS-API tokens — are never
//! traced, only their sizes and thumbprints.

use tracing_subscriber::EnvFilter;

/// How much to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// Nothing (the default).
    Off,
    /// Each step: requests, responses, decisions, files (`--verbose`).
    Steps,
    /// Steps and their details (`--trace`).
    Details,
}

/// The crates whose events are shown.
const CRATES: [&str; 3] = ["kuipa_tools", "kuipa_gssapi", "kuipa"];

/// Install the subscriber for `level`, or for `KUIPA_TRACE` when set.
pub fn init(level: Level) {
    let filter = match std::env::var("KUIPA_TRACE") {
        Ok(directives) if !directives.is_empty() => EnvFilter::new(directives),
        _ => {
            let level = match level {
                Level::Off => return,
                Level::Steps => "debug",
                Level::Details => "trace",
            };
            EnvFilter::new(
                CRATES
                    .iter()
                    .map(|c| format!("{c}={level}"))
                    .collect::<Vec<_>>()
                    .join(","),
            )
        }
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_target(false)
        .compact()
        .try_init();
}
