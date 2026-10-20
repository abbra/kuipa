//! Where a tool writes a secret it was asked to output: standard output,
//! or a file replaced atomically (§10.5).

use std::io::{IsTerminal, Write};
use std::path::Path;

use crate::paths::{self, Error};

/// Where `--out` sends a secret.
#[derive(Clone, Copy, Debug)]
pub enum Output<'a> {
    /// Standard output, as it is.
    Stdout,
    /// A file, written atomically with mode 0600.
    File(&'a Path),
}

impl<'a> Output<'a> {
    /// Check `--out` before anything is sent to a server: `-` is standard
    /// output, refused on a terminal unless `force`; anything else must be
    /// a regular file or nothing yet, outside `/dev`, since an atomic
    /// replace of a symlink such as `/dev/stdout` replaces the link.
    ///
    /// # Errors
    ///
    /// A refusal naming the reason.
    pub fn check(out: &'a Path, force: bool) -> Result<Self, Error> {
        if out == Path::new("-") {
            if std::io::stdout().is_terminal() && !force {
                return Err("standard output is a terminal: redirect it, or give --force".into());
            }
            return Ok(Self::Stdout);
        }
        let absolute = std::path::absolute(out)?;
        if absolute.starts_with("/dev") {
            return Err(
                format!("--out {}: use `--out -` for standard output", out.display()).into(),
            );
        }
        match std::fs::symlink_metadata(out) {
            Ok(m) if !m.file_type().is_file() => Err(format!(
                "--out {}: not a regular file (it would be replaced, not written to)",
                out.display()
            )
            .into()),
            _ => Ok(Self::File(out)),
        }
    }

    /// Write `bytes`.
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn write(self, bytes: &[u8]) -> Result<(), Error> {
        match self {
            Self::Stdout => {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(bytes)?;
                stdout.flush()?;
                Ok(())
            }
            Self::File(out) => paths::write_file(out, bytes, 0o600),
        }
    }
}
