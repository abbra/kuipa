//! An ephemeral MIT Kerberos realm for integration tests: `kdb5_util`,
//! `kadmin.local` and `krb5kdc` from the system, the KDC on a Unix socket
//! (MIT krb5 1.22+) so realms need no ports, and MIT's PKINIT with a test CA
//! so anonymous PKINIT works.  Adapted from kurbu5-pkinit's
//! `tests/system/pkinit/setup.py`.

#![allow(clippy::struct_field_names, clippy::too_many_lines)]

use std::fs;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::certs::{KdcChain, kdc_chain};

/// A running test realm.  Stops the KDC and removes its files on drop.
pub struct Realm {
    pub realm: String,
    pub dir: PathBuf,
    pub socket: PathBuf,
    pub krb5_conf: PathBuf,
    pub kdc_conf: PathBuf,
    pub ca_pem: PathBuf,
    pub chain: KdcChain,
    kdc: Child,
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn pem(der: &[u8]) -> Vec<u8> {
    synta_certificate::der_to_pem("CERTIFICATE", der)
}

impl Realm {
    /// Start a realm, or `None` when the MIT KDC tools are not installed
    /// (a failure instead when `KUIPA_REQUIRE_KDC` is set, as in CI).
    pub fn start(realm: &str, name: &str) -> Option<Self> {
        if !["krb5kdc", "kdb5_util", "kadmin.local", "kinit"]
            .iter()
            .all(|t| have(t))
        {
            assert!(
                std::env::var_os("KUIPA_REQUIRE_KDC").is_none(),
                "KUIPA_REQUIRE_KDC is set but the MIT krb5 KDC tools are not installed"
            );
            eprintln!("skipping: MIT krb5 KDC tools not installed");
            return None;
        }
        // sun_path is 108 bytes: keep the socket directory short.
        let dir = PathBuf::from(format!("/tmp/kuipa-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("kdc.sock");
        let chain = kdc_chain(realm);
        let ca_pem = dir.join("ca.pem");
        fs::write(&ca_pem, pem(&chain.ca_der)).unwrap();
        fs::write(dir.join("kdc.pem"), pem(&chain.kdc_der)).unwrap();
        fs::write(dir.join("kdc-key.pem"), &chain.kdc_key_pem).unwrap();
        let domain = realm.to_lowercase();
        let krb5_conf = dir.join("krb5.conf");
        fs::write(
            &krb5_conf,
            format!(
                "[libdefaults]\n\
                 \x20 default_realm = {realm}\n\
                 \x20 rdns = false\n\
                 \x20 dns_canonicalize_hostname = false\n\
                 \x20 dns_lookup_kdc = false\n\
                 \x20 no_addresses = true\n\
                 [realms]\n\
                 \x20 {realm} = {{\n\
                 \x20   kdc = {sock}\n\
                 \x20   pkinit_anchors = FILE:{ca}\n\
                 \x20 }}\n\
                 [domain_realm]\n\
                 \x20 .{domain} = {realm}\n\
                 \x20 {domain} = {realm}\n",
                sock = socket.display(),
                ca = ca_pem.display(),
            ),
        )
        .unwrap();
        let kdc_conf = dir.join("kdc.conf");
        fs::write(
            &kdc_conf,
            format!(
                "[kdcdefaults]\n\
                 \x20 kdc_listen = {sock}\n\
                 \x20 kdc_tcp_listen = \"\"\n\
                 [dbmodules]\n\
                 \x20 db = {{\n\
                 \x20   db_library = db2\n\
                 \x20   database_name = {d}/db\n\
                 \x20 }}\n\
                 [realms]\n\
                 \x20 {realm} = {{\n\
                 \x20   database_module = db\n\
                 \x20   acl_file = {d}/acl\n\
                 \x20   key_stash_file = {d}/stash\n\
                 \x20   kdc_listen = {sock}\n\
                 \x20   kdc_tcp_listen = \"\"\n\
                 \x20   max_life = 1h\n\
                 \x20   supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal\n\
                 \x20   default_principal_flags = +preauth\n\
                 \x20   pkinit_identity = FILE:{d}/kdc.pem,{d}/kdc-key.pem\n\
                 \x20   pkinit_anchors = FILE:{ca}\n\
                 \x20   pkinit_eku_checking = none\n\
                 \x20 }}\n\
                 [logging]\n\
                 \x20 kdc = FILE:{d}/kdc.log\n",
                sock = socket.display(),
                d = dir.display(),
                ca = ca_pem.display(),
            ),
        )
        .unwrap();
        fs::write(dir.join("acl"), format!("*/admin@{realm} *\n")).unwrap();

        let mut me = Self {
            realm: realm.into(),
            dir,
            socket,
            krb5_conf,
            kdc_conf,
            ca_pem,
            chain,
            kdc: Command::new("true").stdin(Stdio::piped()).spawn().unwrap(),
        };
        me.run(
            "kdb5_util",
            &["create", "-r", realm, "-s", "-P", "master-pw"],
        );
        me.kadmin(&["addprinc", "-randkey", "WELLKNOWN/ANONYMOUS"]);
        let log = fs::File::create(me.dir.join("kdc.stdout")).unwrap();
        // A watchdog shell owns the KDC and holds a pipe from this process:
        // when the pipe closes -- on drop, or because the test process
        // ended, panicked or was killed -- it stops the KDC and removes the
        // realm's files, so nothing outlives the tests.
        me.kdc = Command::new("sh")
            .args([
                "-c",
                r#"krb5kdc -n -r "$1" & k=$!
                   read _
                   kill "$k"; wait "$k"
                   [ -n "$KUIPA_KEEP_REALM" ] || rm -rf "$2""#,
                "kdc-watchdog",
                realm,
                me.dir.to_str().unwrap(),
            ])
            .envs(me.env())
            .stdin(Stdio::piped())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&me.socket).is_err() {
            assert!(
                Instant::now() < deadline,
                "KDC did not start; see {}",
                me.dir.display()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Some(me)
    }

    /// The environment every Kerberos tool and library call needs.
    pub fn env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("KRB5_CONFIG", self.krb5_conf.display().to_string()),
            ("KRB5_KDC_PROFILE", self.kdc_conf.display().to_string()),
        ]
    }

    fn run(&self, cmd: &str, args: &[&str]) -> String {
        let out = Command::new(cmd)
            .args(args)
            .envs(self.env())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{cmd} {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Run a `kadmin.local` query.
    pub fn kadmin(&self, query: &[&str]) -> String {
        self.run("kadmin.local", &["-r", &self.realm, "-q", &query.join(" ")])
    }

    /// Does `principal` exist?
    pub fn has(&self, principal: &str) -> bool {
        let out = Command::new("kadmin.local")
            .args(["-r", &self.realm, "-q", &format!("getprinc {principal}")])
            .envs(self.env())
            .output()
            .unwrap();
        !String::from_utf8_lossy(&out.stderr).contains("does not exist")
    }

    /// Randomise `principal`'s keys (creating it if needed) and return the
    /// new keytab: server-side key generation, as `KEYTAB_GET` does.
    pub fn new_keys(&self, principal: &str) -> Vec<u8> {
        if !self.has(principal) {
            self.kadmin(&["addprinc", "-randkey", principal]);
        }
        let kt = self
            .dir
            .join(format!("kt-{}", principal.replace(['/', '@'], "_")));
        let _ = fs::remove_file(&kt);
        self.kadmin(&["ktadd", "-k", &kt.display().to_string(), principal]);
        fs::read(&kt).unwrap()
    }

    /// A user with a password.
    pub fn add_user(&self, principal: &str, password: &str) {
        self.kadmin(&["addprinc", "-pw", password, principal]);
    }

    /// This KDC's half of a two-way trust with realm `partner`: both
    /// cross-realm `krbtgt` principals, with keys derived from `secret`
    /// (no spaces).  Both realms doing this with the same secret is what
    /// FreeIPA's `trust-add --trust_secret` does (DESIGN §17.4).
    pub fn cross_realm(&self, partner: &str, secret: &str) {
        for principal in [
            format!("krbtgt/{partner}@{}", self.realm),
            format!("krbtgt/{}@{partner}", self.realm),
        ] {
            self.kadmin(&["addprinc", "-pw", secret, &principal]);
        }
    }

    /// `kinit` with a password into `ccache`, optionally armoured with the
    /// ticket in `armor`; `config` overrides the realm's `krb5.conf`.
    pub fn kinit(
        &self,
        principal: &str,
        password: &str,
        ccache: &Path,
        armor: Option<&Path>,
        config: Option<&Path>,
    ) {
        let mut cmd = Command::new("kinit");
        cmd.envs(self.env());
        if let Some(c) = config {
            cmd.env("KRB5_CONFIG", c);
        }
        cmd.arg("-c").arg(ccache);
        if let Some(a) = armor {
            cmd.arg("-T").arg(a);
        }
        let mut child = cmd
            .arg(principal)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{password}").unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "kinit {principal}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Anonymous PKINIT (`kinit -n`) into `ccache`, with `config`.
    pub fn kinit_anonymous(&self, ccache: &Path, config: &Path) -> Result<(), String> {
        let out = Command::new("kinit")
            .envs(self.env())
            .env("KRB5_CONFIG", config)
            .arg("-n")
            .arg("-c")
            .arg(ccache)
            .arg(format!("@{}", self.realm))
            .output()
            .unwrap();
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }
}

impl Drop for Realm {
    fn drop(&mut self) {
        // Closing the watchdog's stdin stops the KDC and removes the files.
        drop(self.kdc.stdin.take());
        let _ = self.kdc.wait();
    }
}
