//! The `keys` operation's server side (§18): handler execution with
//! runas, and the audit line every fetch writes.
//!
//! The handlers are FreeIPA's executables (`ipa-custodia-dmldap` and
//! friends), spawned directly on the blocking pool with the user each
//! namespace names (§18.5): root for `dm` and `ra`, `pkiuser` for the
//! NSS handlers.  `ca_wrapped` is export-only, so it never runs
//! `--import`.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use kuipa_enroll::keys::{KeysAnswer, KeysFetch, MAX_VALUE, Namespace};

/// One namespace's handler (§18.5).
#[derive(Clone, Debug)]
pub struct Handler {
    /// The executable.
    pub command: PathBuf,
    /// The user to run it as (`root` or `pkiuser`); None keeps the
    /// daemon's own user.
    pub runas: Option<String>,
}

/// The `keys` configuration (§18.5).
pub struct Keys {
    handlers: Vec<(Namespace, Handler)>,
    /// The audit line prefix: one line per fetch, to stderr until the
    /// daemon grows a file destination.
    audit: Mutex<Vec<String>>,
}

/// A handler run failed.
#[derive(Debug)]
pub struct HandlerError(pub String);

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HandlerError {}

impl Keys {
    /// From the configuration's handler table; `None` where the table
    /// names no executable for a namespace, disabling it.
    #[must_use]
    pub fn new(handlers: Vec<(Namespace, Handler)>) -> Self {
        Self {
            handlers,
            audit: Mutex::new(Vec::new()),
        }
    }

    /// Run the handler for `fetch` and answer with its value (§18.2).
    ///
    /// # Errors
    ///
    /// A [`HandlerError`] naming what failed: no handler for the
    /// namespace, the user does not exist, the handler failed, or its
    /// value is too large.
    pub fn fetch(&self, fetch: &KeysFetch) -> Result<KeysAnswer, HandlerError> {
        let (_, handler) = self
            .handlers
            .iter()
            .find(|(n, _)| *n == fetch.namespace)
            .ok_or_else(|| HandlerError(format!("no handler for {}", fetch.namespace.label())))?;
        let mut cmd = Command::new(&handler.command);
        cmd.args(["--export", "-"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(user) = &handler.runas {
            // The daemon runs as root behind httpd; the playground and
            // tests run unprivileged, where a runas user that is not
            // ourselves would need privileges we do not have.  Set the
            // user only when it differs from ours.
            if !same_user(user) {
                runas(&mut cmd, user)?;
            }
        }
        if fetch.namespace == Namespace::CaWrapped {
            // The wrap algorithm the caller chose (§18.3), validated by
            // the wire format's allowlist before any handler runs.
            let alg = fetch.alg.map_or_else(
                || "2.16.840.1.101.3.4.1.42".to_owned(),
                |a| a.oid().to_owned(),
            );
            cmd.arg(&alg);
        }
        let out = cmd
            .output()
            .map_err(|e| HandlerError(format!("{}: {e}", handler.command.display())))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(HandlerError(format!(
                "{} failed ({}): {}",
                handler.command.display(),
                out.status,
                stderr.trim()
            )));
        }
        if out.stdout.len() > MAX_VALUE {
            return Err(HandlerError("handler value too large".into()));
        }
        Ok(KeysAnswer { value: out.stdout })
    }

    /// The audit line for one fetch (§18.2), and the decision's reason
    /// when it was refused.
    ///
    /// # Panics
    ///
    /// Only when another thread panicked while holding the audit lock.
    pub fn audit(&self, line: String) {
        // One line per fetch, the parity `/var/log/ipa-custodia.audit.log`
        // needs: caller, namespace, nickname, decision.  The daemon logs
        // to stderr for now; a file destination comes with deployment.
        eprintln!("kuipad: keys: {line}");
        let mut audit = self.audit.lock().expect("audit lock");
        audit.push(line);
        // Bounded memory: keep the recent tail.
        let len = audit.len();
        if len > 1024 {
            audit.drain(..len - 1024);
        }
    }
}

/// Whether `user` names our own uid (no privilege change needed).
fn same_user(user: &str) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let uid = std::fs::metadata("/proc/self").map_or(0, |m| m.uid());
    let name = user_name(uid);
    name.as_deref().is_some_and(|n| n == user)
}

/// The name of `uid`, from `/etc/passwd` (no libc dependency).
fn user_name(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        match fields.as_slice() {
            [name, _, id, ..] if id.parse::<u32>().is_ok_and(|i| i == uid) => {
                Some((*name).to_owned())
            }
            _ => None,
        }
    })
}

/// The uid of `user`, and set both uid and gid (the user's primary group)
/// on `cmd`, as the direct-runas spawn of §18.5.
fn runas(cmd: &mut Command, user: &str) -> Result<(), HandlerError> {
    use std::os::unix::process::CommandExt as _;
    let passwd = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| HandlerError(format!("reading /etc/passwd: {e}")))?;
    let (uid, gid) = passwd
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            match fields.as_slice() {
                [name, _, uid, _, _, _, _] if *name == user => Some((
                    uid.parse::<u32>().ok()?,
                    line.split(':').nth(3)?.parse::<u32>().ok()?,
                )),
                _ => None,
            }
        })
        .ok_or_else(|| HandlerError(format!("no such user: {user}")))?;
    cmd.uid(uid).gid(gid);
    Ok(())
}
