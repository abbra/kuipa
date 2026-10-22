//! Where the client keeps things, and atomic private writes.
//!
//! All paths hang off a root (`KUIPA_ROOT`, default `/`) so the tools can
//! be exercised without touching the system.

use std::fmt::Write as _;
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

    /// `/run/ipa/kuipa/<escaped path>`: the unsealed copy of a protected
    /// keytab or file other than the host keytab (§7.5).  The name is the
    /// absolute path with `/` as `-` and anything but ASCII letters,
    /// digits, `_` and `.` (and `-` itself) as `\xNN`, as `systemd-escape
    /// --path` writes it.
    #[must_use]
    pub fn run_copy(&self, path: &Path) -> PathBuf {
        let mut name = String::new();
        for b in path.to_string_lossy().trim_start_matches('/').bytes() {
            match b {
                b'/' => name.push('-'),
                b'.' if name.is_empty() => name.push_str("\\x2e"),
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.' => name.push(char::from(b)),
                _ => {
                    let _ = write!(name, "\\x{b:02x}");
                }
            }
        }
        self.at("run/ipa/kuipa").join(name)
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

    /// `realm.json`: the public part of the state (realm, FQDN, servers),
    /// world-readable, for users' `kuipa seal` (§7.6.9).
    #[must_use]
    pub fn public_state(&self) -> PathBuf {
        self.state_dir().join("realm.json")
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

    /// The mode A recipient key (§8.2).
    #[must_use]
    pub fn recipient(&self) -> PathBuf {
        self.state_dir().join("recipient.jwk")
    }

    /// The recipient's public key, for the administrator.
    #[must_use]
    pub fn recipient_public(&self) -> PathBuf {
        self.state_dir().join("recipient.pub.jwk")
    }

    /// Steps left after an offline enrollment (§8.4).
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

/// Where the unsealed keytab lives (§7.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Holder {
    /// Plain `/etc/krb5.keytab`.
    #[default]
    None,
    /// Sealed; unsealed into tmpfs at boot.
    File,
}

/// `<path>.sealed`: where a protected keytab or file other than the host
/// keytab is kept sealed (§7.5).
#[must_use]
pub fn sealed_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".sealed");
    PathBuf::from(name)
}

/// What a [`Protected`] entry holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Contents {
    /// A keytab, sealed for its own principal.
    Keytab,
    /// Any other file, sealed for the principal of [`Protected::keytab`].
    File,
}

/// A keytab or file protected besides the host keytab (§7.5): sealed in
/// [`sealed_for`]`(path)`, unsealed into [`Paths::run_copy`]`(path)`, and
/// `path` a symlink to that copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protected {
    /// A keytab or a file.
    pub contents: Contents,
    /// Where it is used (absolute).
    pub path: PathBuf,
    /// The principal on whose entry its bindings are registered.
    pub principal: String,
    /// The keytab whose keys authenticate its registrations: the keytab
    /// itself, or the one a file was sealed with.
    pub keytab: PathBuf,
    /// Permission bits, owner and group of the unsealed copy: the
    /// original file's.
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
}

/// What any user of the host may know: realm, FQDN and servers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PublicState {
    /// Kerberos realm.
    pub realm: String,
    /// This host's FQDN.
    pub fqdn: String,
    /// Servers, issuing server first.
    pub servers: Vec<String>,
}

impl PublicState {
    /// Load `realm.json`.
    ///
    /// # Errors
    ///
    /// "not enrolled" when missing, or a parse error.
    pub fn load(paths: &Paths) -> Result<Self, Error> {
        let bytes = fs::read(paths.public_state())
            .map_err(|_| "this host is not enrolled with kuipa (no realm.json)")?;
        Ok(serde_json::from_slice(&bytes)?)
    }
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
    /// Other keytabs and files that are protected (§7.5).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected: Vec<Protected>,
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
        )?;
        let public = PublicState {
            realm: self.realm.clone(),
            fqdn: self.fqdn.clone(),
            servers: self.servers.clone(),
        };
        write_file(
            &paths.public_state(),
            &serde_json::to_vec_pretty(&public).expect("serialisable"),
            0o644,
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
        .filter(|p| p.exp.is_none_or(|e| now <= e.saturating_add(CLOCK_SKEW)))
        .map(|p| p.anchor)
        .collect())
}

/// Every pin in an anchors file, `<thumbprint> [<expiry> [<size>
/// <root>]]` per line, with its expiry (Unix seconds) and its vouch
/// head (§4.9) if they have one.  Lists written from server responses
/// carry the head and no expiry: both are refreshed at every rekey.
/// Pins provisioned by other means (images, configuration management)
/// should carry an expiry, for the same reason enrollment strings do
/// (§4.4).  An `epoch <seq> <hash>` line (§4.8) is skipped here; see
/// [`read_epoch_from`].
///
/// # Errors
///
/// I/O errors or a malformed line.
pub fn read_anchor_pins(path: &Path) -> Result<Vec<Pin>, Error> {
    Ok(read_anchors_file(path)?.0)
}

/// One pin of an anchors file: the thumbprint, an optional expiry, the
/// vouch heads (§4.9) pinned next to it, and whether the pin is frozen.
///
/// The heads are a **window** (DESIGN-claim-logs.md §1): every head
/// the host verified for the anchor, oldest first, at most
/// [`MAX_HEAD_WINDOW`] of them.  A claim under any of them verifies
/// head-wise, since every prefix of the claim log is the tree an
/// earlier vouch signed; a claim older than the oldest falls back to a
/// signature proof — unless the pin is frozen, which removes the
/// fallback (DESIGN-claim-logs.md §2): what the head covers is all the
/// pin ever accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The pinned anchor.
    pub anchor: tang_pqc::Thumbprint,
    /// When the pin expires (Unix seconds).
    pub exp: Option<u64>,
    /// The pinned vouch heads (§4.9), oldest first: a window over the
    /// anchor's claim log.
    pub heads: Vec<(u64, [u8; 32])>,
    /// The pin never falls back to a signature proof
    /// (DESIGN-claim-logs.md §2): what the heads cover is all it
    /// accepts, for the host's lifetime, moved only by an operator.
    pub frozen: bool,
}

/// Most heads kept in one pin's window (DESIGN-claim-logs.md §1.2):
/// enough to cover a month of daily re-vouching with room for
/// refreshes in between, small enough that a pin line stays a line.
pub const MAX_HEAD_WINDOW: usize = 4;

/// Merge a verified advertisement's heads into the host's pins
/// (DESIGN-claim-logs.md §1.2–§1.3): a head that extends a pin's
/// window is appended (the window trimmed to [`MAX_HEAD_WINDOW`], the
/// oldest dropped first); a head whose size is lower — the anchor
/// restarted its log, a claim was dropped — ends the window and
/// starts a fresh one; a head already in the window keeps it.  A pin
/// with no head yet starts its window at the new one.  Frozen pins
/// keep exactly what they had.  The consistency check (that the old
/// window's heads are prefixes of the new tree) is the caller's, on
/// the claim-log pages between the sizes; this only merges what
/// verified.
///
/// Returns the merged pins and whether any window was truncated (a
/// restart), for the caller to report.
#[must_use]
pub fn merge_windows(pins: &[Pin], heads: &[AnchorHead]) -> (Vec<Pin>, bool) {
    let mut restarted = false;
    let mut out = pins.to_vec();
    for (anchor, head) in heads {
        let Some(pin) = out.iter_mut().find(|p| &p.anchor == anchor) else {
            // A new anchor: its pin starts at the new head.
            out.push(Pin {
                anchor: *anchor,
                exp: None,
                heads: head.map_or_else(Vec::new, |h| vec![h]),
                frozen: false,
            });
            continue;
        };
        let Some((size, root)) = head else { continue };
        if pin.frozen {
            // What the head covers is all the pin ever accepts
            // (DESIGN-claim-logs.md §2): the operator moves it, not
            // the exchange.
            continue;
        }
        if pin.heads.iter().any(|(s, _)| s == size) {
            continue; // Already pinned: the window keeps it.
        }
        match pin.heads.last() {
            Some((newest, _)) if *newest < *size => {
                pin.heads.push((*size, *root));
                let cut = pin.heads.len().saturating_sub(MAX_HEAD_WINDOW);
                pin.heads.drain(..cut);
            }
            Some(_) => {
                // Lower than the window's newest: the log restarted.
                restarted = true;
                pin.heads = vec![(*size, *root)];
            }
            None => pin.heads = vec![(*size, *root)],
        }
    }
    (out, restarted)
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
type AnchorsFile = (Vec<Pin>, Option<(u64, [u8; 32])>);

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
        // The rest is `[<expiry>] [<size> <root>]… [frozen]`: an expiry
        // is a decimal number, a head is a number followed by a
        // thumbprint, and a lone number is an expiry.  The field after
        // the first number tells an expiry from a size.  The head pairs
        // are a window, oldest first (DESIGN-claim-logs.md §1.2), and
        // `frozen` (DESIGN-claim-logs.md §2) removes the signature
        // fallback.
        let mut rest: Vec<&str> = fields.collect();
        let frozen = rest.last().is_some_and(|f| *f == "frozen");
        if frozen {
            rest.pop();
            if rest.is_empty() {
                // Frozen pins a head (DESIGN-claim-logs.md §2): what
                // the head covers is what the pin accepts.
                return Err(format!("{}: frozen without a head in {l:?}", path.display()).into());
            }
        }
        let (exp, heads) = match rest.as_slice() {
            [] => (None, Vec::new()),
            [e] => (Some(parse_expiry(e, l, path)?), Vec::new()),
            // `<size> <root>` with no expiry, then more pairs: the
            // first field is a number and the second a thumbprint.
            // Checked before the expiry form, which would otherwise
            // read the first root as the expiry's size.
            [e, size, ..] if looks_like_head(e, size) => {
                let mut heads = parse_pairs(&rest, l, path)?;
                check_window(&heads, l, path)?;
                (None, std::mem::take(&mut heads))
            }
            [e, size, root, tail @ ..] => {
                let root = parse_root(root, l, path)?;
                let first = (parse_size(size, l, path)?, root);
                let mut heads = vec![first];
                heads.extend(parse_pairs(tail, l, path)?);
                (Some(parse_expiry(e, l, path)?), heads)
            }
            _ => {
                return Err(format!("{}: unexpected text after {l:?}", path.display()).into());
            }
        };
        check_window(&heads, l, path)?;
        if heads.len() > MAX_HEAD_WINDOW {
            return Err(format!(
                "{}: more than {MAX_HEAD_WINDOW} heads in {l:?}",
                path.display()
            )
            .into());
        }
        pins.push(Pin {
            anchor,
            exp,
            heads,
            frozen,
        });
    }
    Ok((pins, epoch))
}

fn parse_expiry(field: &str, line: &str, path: &Path) -> Result<u64, Error> {
    field
        .parse()
        .map_err(|_| format!("{}: bad expiry in {line:?}", path.display()).into())
}

fn parse_size(field: &str, line: &str, path: &Path) -> Result<u64, Error> {
    let size = field
        .parse()
        .map_err(|_| format!("{}: bad head size in {line:?}", path.display()))?;
    if size == 0 {
        return Err(format!("{}: zero head size in {line:?}", path.display()).into());
    }
    Ok(size)
}

/// Whether `size`-then-`root` reads as a head pair whose first field
/// is a size, not an expiry followed by one: the second field parses
/// as a thumbprint either way, so the first is the size when what
/// follows the pair is another pair or the line's end — in practice,
/// an expiry is never followed by a number that is itself followed by
/// a thumbprint.
fn looks_like_head(first: &str, second: &str) -> bool {
    first.parse::<u64>().is_ok() && second.parse::<tang_pqc::Thumbprint>().is_ok()
}

/// Parse `<size> <root>` pairs, oldest first.
///
/// # Errors
///
/// A malformed size or root.
fn parse_pairs(fields: &[&str], line: &str, path: &Path) -> Result<Vec<(u64, [u8; 32])>, Error> {
    if !fields.len().is_multiple_of(2) {
        return Err(format!("{}: odd head fields in {line:?}", path.display()).into());
    }
    fields
        .chunks(2)
        .map(|pair| {
            Ok((
                parse_size(pair[0], line, path)?,
                parse_root(pair[1], line, path)?,
            ))
        })
        .collect()
}

/// A window's heads must strictly grow (DESIGN-claim-logs.md §1.2):
/// the file is an administrator's assertion and must round-trip.
///
/// # Errors
///
/// A duplicate or shrinking head.
fn check_window(heads: &[(u64, [u8; 32])], line: &str, path: &Path) -> Result<(), Error> {
    for pair in heads.windows(2) {
        if pair[1].0 <= pair[0].0 {
            return Err(format!("{}: head sizes must grow in {line:?}", path.display()).into());
        }
    }
    Ok(())
}

fn parse_root(field: &str, line: &str, path: &Path) -> Result<[u8; 32], Error> {
    field
        .parse()
        .map(|t: tang_pqc::Thumbprint| *t.as_bytes())
        .map_err(|_| format!("{}: bad head root in {line:?}", path.display()).into())
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
    write_anchors_epoch_with_heads(
        paths,
        &anchors.iter().map(|a| (*a, None)).collect::<Vec<_>>(),
        epoch,
    )
}

/// [`write_anchors_epoch`] with the anchors'
/// vouch heads (§4.9), aligned with `anchors`: `None` where the server
/// knew no head.
///
/// # Errors
///
/// I/O errors.
pub fn write_anchors_epoch_with_heads(
    paths: &Paths,
    anchors: &[AnchorHead],
    epoch: Option<(u64, [u8; 32])>,
) -> Result<(), Error> {
    write_anchor_pins(
        &paths.anchors(),
        "kuipa realm anchors",
        &anchors
            .iter()
            .map(|(a, head)| Pin {
                anchor: *a,
                exp: None,
                heads: head.map_or_else(Vec::new, |h| vec![h]),
                frozen: false,
            })
            .collect::<Vec<_>>(),
        epoch,
    )
}

/// An anchor with its current vouch head (§4.9), as server responses
/// deliver them: `None` where the server knew no head.
pub type AnchorHead = (tang_pqc::Thumbprint, Option<(u64, [u8; 32])>);

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
    write_anchor_thumbs(path, comment, anchors, None)
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
    pins: &[Pin],
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
    for pin in pins {
        text.push_str(&pin.anchor.to_string());
        if let Some(e) = pin.exp {
            write!(text, " {e}").expect("a String sink never fails");
        }
        for (size, root) in &pin.heads {
            write!(text, " {size} {}", tang_pqc::Thumbprint::from_bytes(*root))
                .expect("a String sink never fails");
        }
        if pin.frozen {
            text.push_str(" frozen");
        }
        text.push('\n');
    }
    write_file(path, text.as_bytes(), 0o644)
}

/// Write an anchors file with plain thumbprint pins (no expiry, no
/// head) and an optional epoch watermark (§4.8).
///
/// # Errors
///
/// I/O errors.
pub fn write_anchor_thumbs(
    path: &Path,
    comment: &str,
    anchors: &[tang_pqc::Thumbprint],
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
    for a in anchors {
        text.push_str(&a.to_string());
        text.push('\n');
    }
    write_file(path, text.as_bytes(), 0o644)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)] // one pin-file grammar, one test
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
                Pin {
                    anchor: a,
                    exp: None,
                    heads: Vec::new(),
                    frozen: false
                },
                Pin {
                    anchor: b,
                    exp: Some(now + 3600),
                    heads: Vec::new(),
                    frozen: false
                },
                Pin {
                    anchor: c,
                    exp: Some(now - CLOCK_SKEW - 1),
                    heads: Vec::new(),
                    frozen: false
                },
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

        let root = |n: u8| tang_pqc::Thumbprint::from_bytes([n; 32]);
        for bad in [
            format!("{a} soon\n"),
            format!("{a} 1 2 3\n"),
            // A lone number is an expiry; two numbers are not a head.
            format!("{a} 0 {}\n", root(9)),
            format!("{a} 1 2\n"),
            format!("{a} 1 2 3 4\n"),
            format!("{a} x {}\n", root(9)),
            // Windows (DESIGN-claim-logs.md §1.2): sizes must grow, at
            // most MAX_HEAD_WINDOW, in pairs.
            format!("{a} 5 {} 5 {}\n", root(1), root(2)),
            format!("{a} 5 {} 4 {}\n", root(1), root(2)),
            format!(
                "{a} 1 {} 2 {} 3 {} 4 {} 5 {}\n",
                root(1),
                root(2),
                root(3),
                root(4),
                root(5)
            ),
            format!("{a} 1 {} 2\n", root(1)),
            // Frozen needs heads.
            format!("{a} frozen\n"),
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
        // A pin with a head and no expiry: written by rekeys, the shape
        // server responses produce.
        write_anchor_pins(
            &path,
            "test",
            &[Pin {
                anchor: a,
                exp: None,
                heads: vec![(5, [8; 32])],
                frozen: false,
            }],
            None,
        )
        .unwrap();
        assert_eq!(
            read_anchor_pins(&path).unwrap(),
            vec![Pin {
                anchor: a,
                exp: None,
                heads: vec![(5, [8; 32])],
                frozen: false,
            }]
        );
        write_anchor_pins(
            &path,
            "test",
            &[Pin {
                anchor: a,
                exp: Some(now + 3600),
                heads: vec![(3, [4; 32])],
                frozen: false,
            }],
            Some((3, [4; 32])),
        )
        .unwrap();
        assert_eq!(
            read_anchor_pins(&path).unwrap(),
            vec![Pin {
                anchor: a,
                exp: Some(now + 3600),
                heads: vec![(3, [4; 32])],
                frozen: false,
            }]
        );
        assert_eq!(read_epoch_from(&path).unwrap(), Some((3, [4; 32])));

        // A window round-trips: several heads, oldest first, and the
        // frozen marker (DESIGN-claim-logs.md §1.2, §2).
        let window = Pin {
            anchor: a,
            exp: Some(now + 3600),
            heads: vec![(3, [4; 32]), (7, [5; 32]), (9, [6; 32])],
            frozen: true,
        };
        write_anchor_pins(&path, "test", std::slice::from_ref(&window), None).unwrap();
        assert_eq!(read_anchor_pins(&path).unwrap(), vec![window]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
