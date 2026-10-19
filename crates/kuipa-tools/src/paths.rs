//! Where the client keeps things, and atomic private writes.
//!
//! All paths hang off a root (`KUIPA_ROOT`, default `/`) so the tools can
//! be exercised without touching the system.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use kuipa_enroll::delegation::CLOCK_SKEW;
use serde::{Deserialize, Serialize};

/// Client paths.
#[derive(Clone, Debug)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    /// Paths under `KUIPA_ROOT`, or `/`.
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(std::env::var_os("KUIPA_ROOT").map_or_else(|| PathBuf::from("/"), PathBuf::from))
    }

    /// Paths under `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn at(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// `/etc/krb5.keytab`.
    #[must_use]
    pub fn keytab(&self) -> PathBuf {
        self.at("etc/krb5.keytab")
    }

    /// `/run/ipa/krb5.keytab`: the unsealed keytab in file mode (§7.3).
    #[must_use]
    pub fn run_keytab(&self) -> PathBuf {
        self.at("run/ipa/krb5.keytab")
    }

    /// `/etc/ipa/krb5.keytab.sealed`.
    #[must_use]
    pub fn sealed(&self) -> PathBuf {
        self.at("etc/ipa/krb5.keytab.sealed")
    }

    /// `/etc/ipa/ca.crt`.
    #[must_use]
    pub fn ca(&self) -> PathBuf {
        self.at("etc/ipa/ca.crt")
    }

    /// `/etc/ipa/ku-anchors`: one thumbprint per line, optionally followed
    /// by its expiry in Unix seconds (pre-provisioned pins).
    #[must_use]
    pub fn anchors(&self) -> PathBuf {
        self.at("etc/ipa/ku-anchors")
    }

    fn state_dir(&self) -> PathBuf {
        self.at("var/lib/ipa-client/ku")
    }

    /// The client state.
    #[must_use]
    pub fn state(&self) -> PathBuf {
        self.state_dir().join("state.json")
    }

    /// PKINIT anchors from the realm (PEM), for anonymous PKINIT armour.
    #[must_use]
    pub fn pkinit_anchors(&self) -> PathBuf {
        self.state_dir().join("pkinit-anchors.pem")
    }

    /// The `krb5.conf` generated from verified realm data: a fallback for
    /// hosts whose system configuration does not know the realm.
    #[must_use]
    pub fn krb5_conf(&self) -> PathBuf {
        self.state_dir().join("krb5.conf")
    }

    /// `/etc/krb5.conf`.
    #[must_use]
    pub fn system_krb5_conf(&self) -> PathBuf {
        self.at("etc/krb5.conf")
    }

    /// The mode A recipient key (§9.2).
    #[must_use]
    pub fn recipient(&self) -> PathBuf {
        self.state_dir().join("recipient.jwk")
    }

    /// The recipient's public key, for the administrator.
    #[must_use]
    pub fn recipient_public(&self) -> PathBuf {
        self.state_dir().join("recipient.pub.jwk")
    }

    /// Steps left after an offline enrollment (§9.4).
    #[must_use]
    pub fn pending(&self) -> PathBuf {
        self.state_dir().join("pending.json")
    }

    fn trust_anchor_dir(&self) -> PathBuf {
        self.at("etc/ipa/ku-anchors.d")
    }

    /// `/etc/ipa/ku-anchors.d/<REALM>`: the anchors pinned for a trusted
    /// realm, used to verify that realm's objects only (§17).  `realm` must
    /// be a safe name ([`kuipa_enroll::realm::is_safe_name`]).
    #[must_use]
    pub fn trust_anchors(&self, realm: &str) -> PathBuf {
        self.trust_anchor_dir().join(realm)
    }

    /// A trusted realm's PKINIT anchors and CA.
    #[must_use]
    pub fn trust_dir(&self, realm: &str) -> PathBuf {
        self.state_dir().join("trusts").join(realm)
    }

    /// `/etc/krb5.conf.d/kuipa_trust_<REALM>`: the trusted realm's KDCs and
    /// PKINIT anchors.  MIT `includedir` reads only names of letters,
    /// digits, `-` and `_`, so `.` becomes `_`.
    #[must_use]
    pub fn trust_krb5_conf(&self, realm: &str) -> PathBuf {
        self.at("etc/krb5.conf.d")
            .join(format!("kuipa_trust_{}", realm.replace('.', "_")))
    }

    /// The trusted realms installed on this host.
    #[must_use]
    pub fn trusted_realms(&self) -> Vec<String> {
        let mut realms: Vec<String> = fs::read_dir(self.trust_anchor_dir())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| kuipa_enroll::realm::is_safe_name(n) && !n.ends_with(".kuipa-tmp"))
            .collect();
        realms.sort();
        realms
    }
}

/// Errors from the tools.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Write `data` atomically with `mode`, creating parent directories.
///
/// # Errors
///
/// I/O errors.
pub fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("kuipa-tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    // Replace a symlink itself, never its target.
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        fs::remove_file(path)?;
    }
    fs::rename(&tmp, path)?;
    tracing::debug!(
        "wrote {} ({} bytes, mode {mode:o})",
        path.display(),
        data.len()
    );
    Ok(())
}

/// Remove a file if it exists.
///
/// # Errors
///
/// I/O errors other than "not found".
pub fn remove(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        Err(_) => Ok(()),
        Ok(()) => {
            tracing::debug!("removed {}", path.display());
            Ok(())
        }
    }
}

/// Where the unsealed keytab lives (§7.3, §7.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Holder {
    /// Plain `/etc/krb5.keytab`.
    #[default]
    None,
    /// Sealed; unsealed into tmpfs at boot.
    File,
}

/// Persistent client state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// Kerberos realm.
    pub realm: String,
    /// This host's FQDN.
    pub fqdn: String,
    /// Servers, issuing server first.
    pub servers: Vec<String>,
    /// Keytab protection.
    #[serde(default)]
    pub holder: Holder,
}

impl State {
    /// Load.
    ///
    /// # Errors
    ///
    /// "not enrolled" when missing, or a parse error.
    pub fn load(paths: &Paths) -> Result<Self, Error> {
        let bytes = fs::read(paths.state())
            .map_err(|_| "this host is not enrolled with kuipa (no state file)")?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Store.
    ///
    /// # Errors
    ///
    /// I/O errors.
    #[allow(clippy::missing_panics_doc)] // serialising plain data cannot fail
    pub fn store(&self, paths: &Paths) -> Result<(), Error> {
        write_file(
            &paths.state(),
            &serde_json::to_vec_pretty(self).expect("serialisable"),
            0o600,
        )
    }
}

/// Write DER certificates as one PEM file.
///
/// # Errors
///
/// I/O errors.
pub fn write_pem(path: &Path, certs: &[Vec<u8>]) -> Result<(), Error> {
    let mut pem = Vec::new();
    for cert in certs {
        pem.extend_from_slice(&synta_certificate::der_to_pem("CERTIFICATE", cert));
    }
    write_file(path, &pem, 0o644)
}

/// Read the pinned anchors.
///
/// # Errors
///
/// I/O errors or a malformed thumbprint.
pub fn read_anchors(paths: &Paths) -> Result<Vec<tang_pqc::Thumbprint>, Error> {
    read_anchors_from(&paths.anchors())
}

/// Read an anchors file, leaving out pins that have expired.
///
/// # Errors
///
/// I/O errors or a malformed line.
pub fn read_anchors_from(path: &Path) -> Result<Vec<tang_pqc::Thumbprint>, Error> {
    let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
    Ok(read_anchor_pins(path)?
        .into_iter()
        .filter(|(_, exp)| exp.is_none_or(|e| now <= e.saturating_add(CLOCK_SKEW)))
        .map(|(a, _)| a)
        .collect())
}

/// Every pin in an anchors file, `<thumbprint> [<expiry>]` per line, with
/// its expiry (Unix seconds) if it has one.  Lists written from server
/// responses have none: they are refreshed at every rekey.  Pins
/// provisioned by other means (images, configuration management) should,
/// for the same reason enrollment strings do (§4.4).  An
/// `epoch <seq> <hash>` line (§4.8) is skipped here; see
/// [`read_epoch_from`].
///
/// # Errors
///
/// I/O errors or a malformed line.
pub fn read_anchor_pins(path: &Path) -> Result<Vec<(tang_pqc::Thumbprint, Option<u64>)>, Error> {
    Ok(read_anchors_file(path)?.0)
}

/// The anchor epoch watermark stored in an anchors file (§4.8): the
/// `(seq, head)` of the last entry of the anchor log this host has
/// verified, from the `epoch <seq> <hash>` line, if it has one.
///
/// # Errors
///
/// I/O errors or a malformed line.
pub fn read_epoch_from(path: &Path) -> Result<Option<(u64, [u8; 32])>, Error> {
    Ok(read_anchors_file(path)?.1)
}

/// What an anchors file holds: pins with optional expiries, and the
/// optional epoch watermark (§4.8).
type AnchorsFile = (
    Vec<(tang_pqc::Thumbprint, Option<u64>)>,
    Option<(u64, [u8; 32])>,
);

fn read_anchors_file(path: &Path) -> Result<AnchorsFile, Error> {
    let text = fs::read_to_string(path)?;
    let mut pins = Vec::new();
    let mut epoch = None;
    for l in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let mut fields = l.split_whitespace();
        let first = fields.next().unwrap_or_default();
        if first == "epoch" {
            let seq = fields
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("{}: bad epoch sequence in {l:?}", path.display()))?;
            let head = fields
                .next()
                .map(str::parse)
                .transpose()?
                .map(|t: tang_pqc::Thumbprint| *t.as_bytes())
                .ok_or_else(|| format!("{}: bad epoch hash in {l:?}", path.display()))?;
            if fields.next().is_some() {
                return Err(format!("{}: unexpected text after {l:?}", path.display()).into());
            }
            // Keep the newest, whatever order the lines are in.
            if epoch.is_none_or(|(s, _)| seq > s) {
                epoch = Some((seq, head));
            }
            continue;
        }
        let anchor = first.parse()?;
        let exp = fields
            .next()
            .map(|e| {
                e.parse::<u64>()
                    .map_err(|_| format!("{}: bad expiry {e:?}", path.display()))
            })
            .transpose()?;
        if fields.next().is_some() {
            return Err(format!("{}: unexpected text after {l:?}", path.display()).into());
        }
        pins.push((anchor, exp));
    }
    Ok((pins, epoch))
}

/// Write the pinned anchors.
///
/// # Errors
///
/// I/O errors.
pub fn write_anchors(paths: &Paths, anchors: &[tang_pqc::Thumbprint]) -> Result<(), Error> {
    write_anchors_to(&paths.anchors(), "kuipa realm anchors", anchors)
}

/// Write the pinned anchors and the anchor epoch watermark (§4.8).
///
/// # Errors
///
/// I/O errors.
pub fn write_anchors_epoch(
    paths: &Paths,
    anchors: &[tang_pqc::Thumbprint],
    epoch: Option<(u64, [u8; 32])>,
) -> Result<(), Error> {
    write_anchor_pins(
        &paths.anchors(),
        "kuipa realm anchors",
        &anchors.iter().map(|a| (*a, None)).collect::<Vec<_>>(),
        epoch,
    )
}

/// Write an anchors file with a `# comment` first line.
///
/// # Errors
///
/// I/O errors.
pub fn write_anchors_to(
    path: &Path,
    comment: &str,
    anchors: &[tang_pqc::Thumbprint],
) -> Result<(), Error> {
    write_anchor_pins(
        path,
        comment,
        &anchors.iter().map(|a| (*a, None)).collect::<Vec<_>>(),
        None,
    )
}

/// Write an anchors file with expiry-bearing pins and an optional epoch
/// watermark (§4.8).
///
/// # Errors
///
/// I/O errors.
pub fn write_anchor_pins(
    path: &Path,
    comment: &str,
    pins: &[(tang_pqc::Thumbprint, Option<u64>)],
    epoch: Option<(u64, [u8; 32])>,
) -> Result<(), Error> {
    use std::fmt::Write as _; // appending to a String cannot fail
    let mut text = format!("# {comment}\n");
    if let Some((seq, head)) = epoch {
        writeln!(
            text,
            "epoch {seq} {}",
            tang_pqc::Thumbprint::from_bytes(head)
        )
        .expect("a String sink never fails");
    }
    for (a, exp) in pins {
        text.push_str(&a.to_string());
        if let Some(e) = exp {
            write!(text, " {e}").expect("a String sink never fails");
        }
        text.push('\n');
    }
    write_file(path, text.as_bytes(), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_file_with_expiry() {
        let dir = std::env::temp_dir().join(format!("kuipa-paths-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pq-anchors");
        let (a, b, c) = (
            tang_pqc::Thumbprint::from_bytes([1; 32]),
            tang_pqc::Thumbprint::from_bytes([2; 32]),
            tang_pqc::Thumbprint::from_bytes([3; 32]),
        );
        let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
        let head = tang_pqc::Thumbprint::from_bytes([9; 32]);
        let text = format!(
            "# provisioned\n{a}\n\n{b} {}\n{c} {}\nepoch 7 {head}\n",
            now + 3600,
            now - CLOCK_SKEW - 1
        );
        fs::write(&path, text).unwrap();
        assert_eq!(
            read_anchor_pins(&path).unwrap(),
            vec![
                (a, None),
                (b, Some(now + 3600)),
                (c, Some(now - CLOCK_SKEW - 1))
            ]
        );
        assert_eq!(
            read_epoch_from(&path).unwrap(),
            Some((7, [9; 32])),
            "the watermark rides with the pins"
        );
        assert_eq!(
            read_anchors_from(&path).unwrap(),
            vec![a, b],
            "expired pin left out"
        );

        for bad in [
            format!("{a} soon\n"),
            format!("{a} 1 2\n"),
            "short\n".into(),
            "epoch nope xx\n".into(),
            "epoch 7 notahash\n".into(),
        ] {
            fs::write(&path, bad).unwrap();
            assert!(read_anchor_pins(&path).is_err());
        }
        // Written lists carry no expiry and read back unchanged.
        write_anchors_to(&path, "test", &[a, b]).unwrap();
        assert_eq!(read_anchors_from(&path).unwrap(), vec![a, b]);
        assert_eq!(
            read_epoch_from(&path).unwrap(),
            None,
            "no watermark written"
        );
        write_anchor_pins(&path, "test", &[(a, Some(now + 3600))], Some((3, [4; 32]))).unwrap();
        assert_eq!(
            read_anchor_pins(&path).unwrap(),
            vec![(a, Some(now + 3600))]
        );
        assert_eq!(read_epoch_from(&path).unwrap(), Some((3, [4; 32])));
        fs::remove_dir_all(&dir).unwrap();
    }
}
