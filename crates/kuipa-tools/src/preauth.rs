//! Asking a human for what an enrollment needs (§10.4): the prompts the
//! tools read secrets from, and the front end of an armoured AS exchange,
//! where the KDC — not kuipa — decides what to ask for.

use std::io::IsTerminal;

use kuipa_gssapi::{GssError, NoPreauth, Preauth};
use native_ossl::util::SecretBuf;

use crate::paths::Error;

/// Prompt on the terminal and read one line; with `hidden`, echo is off
/// while typing (`stty` on the terminal, so no terminal ioctls here).
///
/// # Errors
///
/// I/O errors.  An empty line is returned as an empty secret: a caller that
/// needs one refuses it.
pub fn prompt(what: &str, hidden: bool) -> Result<SecretBuf, Error> {
    let stty = |arg: &str| {
        std::fs::File::open("/dev/tty").ok().and_then(|tty| {
            // Absolute path: the tools run as root during enrollment,
            // and a PATH-resolved binary there is a planted one.
            std::process::Command::new("/bin/stty")
                .arg(arg)
                .stdin(tty)
                .status()
                .ok()
        })
    };
    eprint!("{}{}: ", what[..1].to_uppercase(), &what[1..]);
    if hidden {
        stty("-echo");
    }
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    if hidden {
        stty("echo");
        eprintln!();
    }
    read?;
    let value = SecretBuf::from_slice(line.trim_end_matches(['\n', '\r']).as_bytes());
    drop(SecretBuf::new(line.into_bytes()));
    Ok(value)
}

/// The front end of an armoured AS exchange: every question the KDC offers
/// is asked here, in place of libkrb5's own POSIX reader, so a challenge and
/// the answer for it reach the terminal `kuipa` runs on.
pub struct Terminal;

impl Preauth for Terminal {
    fn prompt(&self, label: &str) -> Result<Vec<u8>, GssError> {
        ask(label, false)
    }

    fn secret(&self, label: &str) -> Result<Vec<u8>, GssError> {
        ask(label, true)
    }
}

/// [`prompt`] with the error type the GSSAPI layer reports.
fn ask(label: &str, hidden: bool) -> Result<Vec<u8>, GssError> {
    prompt(label, hidden)
        .map(|answer| answer.as_ref().to_vec())
        .map_err(|e| GssError::Preauth {
            detail: e.to_string(),
        })
}

/// The front end for an exchange started from here: prompting while standard
/// input is a terminal, refusing otherwise — so a join fed from a pipe still
/// answers a password with the secret it was given, and a realm that wants a
/// second factor says so instead of reading from a pipe that holds none.
#[must_use]
pub fn for_stdin() -> Box<dyn Preauth> {
    if std::io::stdin().is_terminal() {
        Box::new(Terminal)
    } else {
        Box::new(NoPreauth)
    }
}
