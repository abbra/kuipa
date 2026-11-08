//! The `keys` operation's server side (§18): handler execution with
//! runas, and the audit line every fetch writes.
//!
//! The handlers are FreeIPA's executables (`ipa-custodia-dmldap` and
//! friends), spawned directly on the blocking pool with the user each
//! namespace names (§18.5): root for `dm` and `ra`, `pkiuser` for the
//! NSS handlers.  `ca_wrapped` is export-only, so it never runs
//! `--import`.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
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
    broker: Option<PathBuf>,
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
            broker: None,
            handlers,
            audit: Mutex::new(Vec::new()),
        }
    }

    /// Send exports to the privileged local custody broker.
    #[must_use]
    pub fn broker(path: PathBuf) -> Self {
        Self {
            handlers: Vec::new(),
            broker: Some(path),
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
        if let Some(path) = &self.broker {
            let mut stream = UnixStream::connect(path)
                .map_err(|e| HandlerError(format!("custody broker: {e}")))?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(60)))
                .map_err(|e| HandlerError(format!("custody broker: {e}")))?;
            let request = fetch.to_bytes().map_err(|e| HandlerError(e.to_string()))?;
            stream
                .write_all(&request)
                .and_then(|()| stream.shutdown(Shutdown::Write))
                .map_err(|e| HandlerError(format!("custody broker: {e}")))?;
            let mut response = Vec::new();
            stream
                .take((MAX_VALUE + 4097) as u64)
                .read_to_end(&mut response)
                .map_err(|e| HandlerError(format!("custody broker: {e}")))?;
            return match response.split_first() {
                Some((0, value)) if value.len() <= MAX_VALUE => Ok(KeysAnswer {
                    value: value.to_vec(),
                }),
                Some((1, message)) if message.len() <= 4096 => Err(HandlerError(format!(
                    "custody broker: {}",
                    String::from_utf8_lossy(message)
                ))),
                _ => Err(HandlerError("invalid custody broker response".into())),
            };
        }
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
            // The broker runs configured handlers as their required identities.
            if !same_user(user) {
                runas(&mut cmd, user)?;
            }
        }
        // The NSS handlers take the nickname as a flag; `ca_wrapped` also
        // takes the wrap algorithm the caller chose (§18.3), validated by
        // the wire format's allowlist before any handler runs.  `dm` and
        // `ra` have one secret and take neither.
        match fetch.namespace {
            Namespace::Ca => {
                cmd.args(["--nickname", &fetch.nickname]);
            }
            Namespace::CaWrapped => {
                let alg = fetch.alg.map_or_else(
                    || "2.16.840.1.101.3.4.1.42".to_owned(),
                    |a| a.oid().to_owned(),
                );
                cmd.args(["--nickname", &fetch.nickname, "--algorithm", &alg]);
            }
            _ => {}
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

    /// Serve fixed-format custody requests on an inherited private socket.
    ///
    /// # Errors
    ///
    /// A listener failure.
    pub fn serve_broker(&self, listener: UnixListener) -> std::io::Result<()> {
        for stream in listener.incoming() {
            if let Err(error) = self.serve_request(stream?) {
                eprintln!("kuipad: custody broker request: {error}");
            }
        }
        Ok(())
    }

    fn serve_request(&self, mut stream: UnixStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(60)))?;
        let result = (|| -> Result<KeysAnswer, HandlerError> {
            let mut request = Vec::new();
            (&mut stream)
                .take(1025)
                .read_to_end(&mut request)
                .map_err(|e| HandlerError(e.to_string()))?;
            if request.len() > 1024 {
                return Err(HandlerError("custody request too large".into()));
            }
            let fetch = KeysFetch::from_bytes(&request).map_err(|e| HandlerError(e.to_string()))?;
            self.fetch(&fetch)
        })();
        let response = match result {
            Ok(answer) => {
                let mut response = Vec::with_capacity(answer.value.len() + 1);
                response.push(0);
                response.extend_from_slice(&answer.value);
                response
            }
            Err(error) => {
                eprintln!("kuipad: custody broker: {error}");
                b"\x01custody export failed".to_vec()
            }
        };
        stream.write_all(&response)
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuipa_enroll::keys::WrapAlg;

    /// A handler that prints its arguments, one line.  `/bin/echo` and not a
    /// script we write: the test tmpdir may be mounted noexec.
    fn echo_keys(namespace: Namespace) -> Keys {
        Keys::new(vec![(
            namespace,
            Handler {
                command: "/bin/echo".into(),
                runas: None,
            },
        )])
    }

    fn run(keys: &Keys, namespace: Namespace, nickname: &str, alg: Option<WrapAlg>) -> String {
        let fetch = KeysFetch {
            namespace,
            nickname: nickname.to_owned(),
            alg,
        };
        let answer = keys.fetch(&fetch).unwrap();
        String::from_utf8(answer.value).unwrap().trim().to_owned()
    }

    #[test]
    fn nss_handlers_get_their_flags() {
        let ca = echo_keys(Namespace::Ca);
        assert_eq!(
            run(&ca, Namespace::Ca, "subsystemCert cert-pki-ca", None),
            "--export - --nickname subsystemCert cert-pki-ca"
        );
        let wrapped = echo_keys(Namespace::CaWrapped);
        assert_eq!(
            run(
                &wrapped,
                Namespace::CaWrapped,
                "lwca",
                Some(WrapAlg::Aes256Wrap)
            ),
            "--export - --nickname lwca --algorithm 2.16.840.1.101.3.4.1.45"
        );
        assert_eq!(
            run(&wrapped, Namespace::CaWrapped, "lwca", None),
            "--export - --nickname lwca --algorithm 2.16.840.1.101.3.4.1.42"
        );
    }

    #[test]
    fn single_secret_handlers_get_no_nickname() {
        let dm = echo_keys(Namespace::Dm);
        assert_eq!(run(&dm, Namespace::Dm, "DMHash", None), "--export -");
    }

    #[test]
    fn broker_exports_only_configured_namespaces() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!(
            "kuipad-broker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&dir).expect("create fixture");
        let handler = dir.join("handler");
        std::fs::write(
            &handler,
            "#!/bin/sh\n\
             [ \"$1\" = --export ] && [ \"$2\" = - ] || exit 1\n\
             case \"$3:$4:$5:$6\" in\n\
             :::) printf dmhash;;\n\
             --nickname:certificate::) printf certificate;;\n\
             --nickname:certificate:--algorithm:2.16.840.1.101.3.4.1.45) printf wrapped;;\n\
             *) exit 1;;\n\
             esac\n",
        )
        .expect("write handler");
        std::fs::set_permissions(&handler, std::fs::Permissions::from_mode(0o700))
            .expect("make handler executable");
        let path = dir.join("broker.sock");
        let listener = UnixListener::bind(&path).expect("bind broker");
        let thread = std::thread::spawn(move || {
            let keys = Keys::new(
                [Namespace::Dm, Namespace::Ca, Namespace::CaWrapped]
                    .into_iter()
                    .map(|namespace| {
                        (
                            namespace,
                            Handler {
                                command: handler.clone(),
                                runas: None,
                            },
                        )
                    })
                    .collect(),
            );
            for _ in 0..4 {
                keys.serve_request(listener.accept().expect("accept").0)
                    .expect("reply");
            }
        });
        let proxy = Keys::broker(path.clone());
        let mut fetch = KeysFetch {
            namespace: Namespace::Dm,
            nickname: String::new(),
            alg: None,
        };
        assert_eq!(proxy.fetch(&fetch).expect("export").value, b"dmhash");
        fetch.namespace = Namespace::Ca;
        fetch.nickname = "certificate".into();
        assert_eq!(
            proxy.fetch(&fetch).expect("CA export").value,
            b"certificate"
        );
        fetch.namespace = Namespace::CaWrapped;
        fetch.alg = Some(kuipa_enroll::keys::WrapAlg::Aes256Wrap);
        assert_eq!(
            proxy.fetch(&fetch).expect("wrapped export").value,
            b"wrapped"
        );
        fetch.namespace = Namespace::Ra;
        fetch.alg = None;
        assert!(proxy.fetch(&fetch).is_err());
        thread.join().expect("broker thread");
        std::fs::remove_dir_all(dir).expect("remove fixture");
    }
}
