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
use kuipa_enroll::merkle::Hash;
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

    /// `/etc/ipa/ku-witnesses.json`: the transparency-log witnesses this
    /// host trusts, and how many of them must cosign a head
    /// (`kuipa tlog witnesses`); world-readable, like the anchors.
    #[must_use]
    pub fn witnesses(&self) -> PathBuf {
        self.at("etc/ipa/ku-witnesses.json")
    }

    fn state_dir(&self) -> PathBuf {
        self.at("var/lib/ipa-client/ku")
    }

    /// The host's own kuipa data directory for `kuipa escrow`: the vault
    /// descriptors it seals deposits with, root-only.
    #[must_use]
    pub fn escrow_dir(&self) -> PathBuf {
        self.state_dir().join("escrow")
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
    ///
    /// # Panics
    ///
    /// Never: the state holds only strings and plain JSON types.
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

/// Every pin of an anchors file that has not expired (§4.4), the whole
/// pin rather than only its thumbprint: its head window
/// (DESIGN-claim-logs.md §1) and its frozen marker (§2) travel with it.
///
/// # Errors
///
/// I/O errors or a malformed line.
pub fn live_pins(path: &Path) -> Result<Vec<Pin>, Error> {
    let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
    Ok(read_anchor_pins(path)?
        .into_iter()
        .filter(|p| p.exp.is_none_or(|e| now <= e.saturating_add(CLOCK_SKEW)))
        .collect())
}

/// Whether a pin-read error is only "no pin file here yet".
#[must_use]
pub(crate) fn is_missing(e: &Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// What a pin file hands to verification: the live anchors, every head
/// of their windows oldest first, and the anchors that are frozen
/// (DESIGN-claim-logs.md §1.2).
pub type Windows = (
    Vec<tang_pqc::Thumbprint>,
    Vec<kuipa_enroll::delegation::HeadPin>,
    Vec<Hash>,
    Vec<tang_pqc::Thumbprint>,
);

/// What a pin file says this host trusts: the live anchors, every head of
/// their windows oldest first (§1.4: the whole window travels so the
/// server can try each pinned head in turn), and which of those anchors
/// are frozen (§2).  Expired pins are out, as in [`read_anchors_from`].
///
/// A missing file is nothing pinned.  A malformed one is an error: pins
/// are trust, and a corrupt pin file must fail closed rather than read as
/// "nothing pinned".
///
/// # Errors
///
/// I/O errors or a malformed line.
pub fn pinned_windows(path: &Path) -> Result<Windows, Error> {
    let pins = match live_pins(path) {
        Ok(pins) => pins,
        Err(e) if is_missing(&e) => return Ok((Vec::new(), Vec::new(), Vec::new(), Vec::new())),
        Err(e) => return Err(e),
    };
    let anchors = pins.iter().map(|p| p.anchor).collect();
    let heads = pins
        .iter()
        .flat_map(|p| {
            p.heads
                .iter()
                .map(move |(size, root)| kuipa_enroll::delegation::HeadPin {
                    anchor: p.anchor,
                    size: *size,
                    root: *root,
                })
        })
        .collect();
    let mut retired: Vec<Hash> = pins
        .iter()
        .flat_map(|p| p.retired.iter().copied())
        .collect();
    retired.sort_unstable();
    retired.dedup();
    let frozen = pins.iter().filter(|p| p.frozen).map(|p| p.anchor).collect();
    Ok((anchors, heads, retired, frozen))
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
    pub heads: Vec<(u64, Hash)>,
    /// The pin never falls back to a signature proof
    /// (DESIGN-claim-logs.md §2): what the heads cover is all it
    /// accepts, for the host's lifetime, moved only by an operator.
    pub frozen: bool,
    /// The claims (leaf hashes) the anchor's log retired, as far as the
    /// host has read it (`DESIGN-tlog.md` §8): still in every later
    /// tree, they prove nothing head-wise.  Written as a `retired
    /// <anchor> <leaf>…` line.
    pub retired: Vec<Hash>,
}

/// Most heads kept in one pin's window (DESIGN-claim-logs.md §1.2):
/// enough to cover a month of daily re-vouching with room for
/// refreshes in between, small enough that a pin line stays a line.
pub const MAX_HEAD_WINDOW: usize = 4;

/// Merge a verified advertisement's heads into the host's pins
/// (DESIGN-claim-logs.md §1.2–§1.3, `DESIGN-tlog.md` §8): a head that
/// extends a pin's window is appended (the window trimmed to
/// [`MAX_HEAD_WINDOW`], the oldest dropped first), with the claims its
/// log retired; a head already in the window keeps it.  A head whose
/// size is lower is a log that no longer extends what the host pinned —
/// claim logs only grow — and is not pinned: the window keeps what it
/// had, and the fork is reported.  A pin with no head yet starts its
/// window at the new one.  Frozen pins keep exactly what they had.  The
/// consistency check, and learning the retired claims, are the
/// caller's; this only merges what verified.
///
/// `retired` holds, per anchor, the claims the log at its new head
/// retired; they join the pin's own.  Returns the merged pins and
/// whether any anchor's log shrank, for the caller to report.
#[must_use]
pub fn merge_windows(
    pins: &[Pin],
    heads: &[AnchorHead],
    retired: &[(tang_pqc::Thumbprint, Vec<Hash>)],
) -> (Vec<Pin>, bool) {
    let mut forked = false;
    let mut out = pins.to_vec();
    let learned = |anchor: &tang_pqc::Thumbprint| {
        retired
            .iter()
            .find(|(a, _)| a == anchor)
            .map(|(_, r)| r.clone())
            .unwrap_or_default()
    };
    for (anchor, head) in heads {
        let Some(pin) = out.iter_mut().find(|p| &p.anchor == anchor) else {
            // A new anchor: its pin starts at the new head.
            out.push(Pin {
                anchor: *anchor,
                exp: None,
                heads: head.map_or_else(Vec::new, |h| vec![h]),
                frozen: false,
                retired: head.map_or_else(Vec::new, |_| learned(anchor)),
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
            Some((newest, _)) if *newest > *size => {
                // Lower than the window's newest: the log no longer
                // extends what was pinned.
                forked = true;
                continue;
            }
            Some(_) => {
                pin.heads.push((*size, *root));
                let cut = pin.heads.len().saturating_sub(MAX_HEAD_WINDOW);
                pin.heads.drain(..cut);
            }
            None => pin.heads = vec![(*size, *root)],
        }
        for leaf in learned(anchor) {
            if !pin.retired.contains(&leaf) {
                pin.retired.push(leaf);
            }
        }
    }
    (out, forked)
}

/// The anchor epoch watermark stored in an anchors file (§4.8): the
/// `(seq, head)` of the last entry of the anchor log this host has
/// verified, from the `epoch <seq> <hash>` line, if it has one.
///
/// # Errors
///
/// I/O errors or a malformed line.
pub fn read_epoch_from(
    path: &Path,
) -> Result<Option<(u64, kuipa_enroll::epoch::EpochHead)>, Error> {
    Ok(read_anchors_file(path)?.1)
}

/// What an anchors file holds: pins with optional expiries, and the
/// optional epoch watermark (§4.8).
type AnchorsFile = (Vec<Pin>, Option<(u64, kuipa_enroll::epoch::EpochHead)>);

fn read_anchors_file(path: &Path) -> Result<AnchorsFile, Error> {
    let text = fs::read_to_string(path)?;
    let mut pins = Vec::new();
    let mut epoch = None;
    let mut retired: Vec<(tang_pqc::Thumbprint, Vec<Hash>)> = Vec::new();
    for l in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let mut fields = l.split_whitespace();
        let first = fields.next().unwrap_or_default();
        if first == "retired" {
            let (anchor, leaves) = parse_retired(fields, l, path)?;
            if retired.iter().any(|(a, _)| *a == anchor) {
                return Err(format!("{}: duplicate retired line {l:?}", path.display()).into());
            }
            retired.push((anchor, leaves));
            continue;
        }
        if first == "epoch" {
            let seq = fields
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("{}: bad epoch sequence in {l:?}", path.display()))?;
            let head: kuipa_enroll::epoch::EpochHead = fields
                .next()
                .and_then(|f| tang_pqc::b64::decode(f).ok())
                .and_then(|h| h.try_into().ok())
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
        let anchor: tang_pqc::Thumbprint = first
            .parse()
            .map_err(|_| format!("{}: malformed anchor thumbprint in {l:?}", path.display()))?;
        // One line per anchor: two lines for one anchor would say two
        // different things about it, and the file is an administrator's
        // assertion that must round-trip.
        if pins.iter().any(|p: &Pin| p.anchor == anchor) {
            return Err(format!("{}: duplicate anchor in {l:?}", path.display()).into());
        }
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
            retired: Vec::new(),
        });
    }
    for (anchor, leaves) in retired {
        let pin = pins
            .iter_mut()
            .find(|p| p.anchor == anchor)
            .ok_or_else(|| format!("{}: retired claims for unpinned {anchor}", path.display()))?;
        pin.retired = leaves;
    }
    Ok((pins, epoch))
}

/// A `retired <anchor> <leaf>…` line's anchor and claim leaves
/// (`DESIGN-tlog.md` §8).
///
/// # Errors
///
/// A malformed anchor or leaf, or no leaf.
fn parse_retired<'a>(
    mut fields: impl Iterator<Item = &'a str>,
    line: &str,
    path: &Path,
) -> Result<(tang_pqc::Thumbprint, Vec<Hash>), Error> {
    let anchor: tang_pqc::Thumbprint = fields
        .next()
        .and_then(|a| a.parse().ok())
        .ok_or_else(|| format!("{}: bad retired anchor in {line:?}", path.display()))?;
    let leaves: Vec<Hash> = fields
        .map(|f| parse_root(f, line, path))
        .collect::<Result<_, _>>()?;
    if leaves.is_empty() {
        return Err(format!("{}: no retired claims in {line:?}", path.display()).into());
    }
    Ok((anchor, leaves))
}

fn parse_expiry(field: &str, line: &str, path: &Path) -> Result<u64, Error> {
    if !is_number(field) {
        return Err(format!("{}: bad expiry in {line:?}", path.display()).into());
    }
    field
        .parse()
        .map_err(|_| format!("{}: bad expiry in {line:?}", path.display()).into())
}

fn parse_size(field: &str, line: &str, path: &Path) -> Result<u64, Error> {
    if !is_number(field) {
        return Err(format!("{}: bad head size in {line:?}", path.display()).into());
    }
    let size = field
        .parse()
        .map_err(|_| format!("{}: bad head size in {line:?}", path.display()))?;
    if size == 0 {
        return Err(format!("{}: zero head size in {line:?}", path.display()).into());
    }
    Ok(size)
}

/// A number field of a pin line: ASCII digits only, as an enrollment
/// string's fields are (§4.4).  `u64::from_str` also accepts a leading
/// `+` (and whitespace is already gone), which a pin file must not carry:
/// `+5` is not an expiry anyone provisioned on purpose.
fn is_number(field: &str) -> bool {
    !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `size`-then-`root` reads as a head pair whose first field
/// is a size, not an expiry followed by one: the second field parses
/// as a thumbprint either way, so the first is the size when what
/// follows the pair is another pair or the line's end — in practice,
/// an expiry is never followed by a number that is itself followed by
/// a thumbprint.
fn looks_like_head(first: &str, second: &str) -> bool {
    is_number(first) && decode_hash(second).is_some()
}

/// Parse `<size> <root>` pairs, oldest first.
///
/// # Errors
///
/// A malformed size or root.
fn parse_pairs(fields: &[&str], line: &str, path: &Path) -> Result<Vec<(u64, Hash)>, Error> {
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
fn check_window(heads: &[(u64, Hash)], line: &str, path: &Path) -> Result<(), Error> {
    for pair in heads.windows(2) {
        if pair[1].0 <= pair[0].0 {
            return Err(format!("{}: head sizes must grow in {line:?}", path.display()).into());
        }
    }
    Ok(())
}

/// A tree hash in base64url: 32 bytes (SHA-256) or 48 (SHA-384).
fn decode_hash(field: &str) -> Option<Hash> {
    tang_pqc::b64::decode(field)
        .ok()
        .and_then(|b| Hash::from_slice(&b).ok())
}

fn parse_root(field: &str, line: &str, path: &Path) -> Result<Hash, Error> {
    decode_hash(field)
        .ok_or_else(|| format!("{}: bad head root in {line:?}", path.display()).into())
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
    epoch: Option<(u64, kuipa_enroll::epoch::EpochHead)>,
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
    epoch: Option<(u64, kuipa_enroll::epoch::EpochHead)>,
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
                retired: Vec::new(),
            })
            .collect::<Vec<_>>(),
        epoch,
    )
}

/// An anchor with its current vouch head (§4.9), as server responses
/// deliver them: `None` where the server knew no head.
pub type AnchorHead = (tang_pqc::Thumbprint, Option<(u64, Hash)>);

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
    epoch: Option<(u64, kuipa_enroll::epoch::EpochHead)>,
) -> Result<(), Error> {
    use std::fmt::Write as _; // appending to a String cannot fail
    let mut text = format!("# {comment}\n");
    if let Some((seq, head)) = epoch {
        writeln!(text, "epoch {seq} {}", tang_pqc::b64::encode(&head))
            .expect("a String sink never fails");
    }
    for pin in pins {
        text.push_str(&pin.anchor.to_string());
        if let Some(e) = pin.exp {
            write!(text, " {e}").expect("a String sink never fails");
        }
        for (size, root) in &pin.heads {
            write!(text, " {size} {}", tang_pqc::b64::encode(root))
                .expect("a String sink never fails");
        }
        if pin.frozen {
            text.push_str(" frozen");
        }
        text.push('\n');
    }
    for pin in pins.iter().filter(|p| !p.retired.is_empty()) {
        write!(text, "retired {}", pin.anchor).expect("a String sink never fails");
        for leaf in &pin.retired {
            write!(text, " {}", tang_pqc::b64::encode(leaf)).expect("a String sink never fails");
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
    epoch: Option<(u64, kuipa_enroll::epoch::EpochHead)>,
) -> Result<(), Error> {
    use std::fmt::Write as _; // appending to a String cannot fail
    let mut text = format!("# {comment}\n");
    if let Some((seq, head)) = epoch {
        writeln!(text, "epoch {seq} {}", tang_pqc::b64::encode(&head))
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

    /// A SHA-256-sized tree hash of `byte`s.
    fn test_hash(byte: u8) -> Hash {
        Hash::from_slice(&[byte; 32]).unwrap()
    }

    /// A scratch directory for one test, and the anchors file in it.
    fn scratch_anchors(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("kuipa-paths-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pq-anchors");
        (dir, path)
    }

    #[test]
    fn anchors_file_with_expiry() {
        let (dir, path) = scratch_anchors("expiry");
        let (a, b, c) = (
            tang_pqc::Thumbprint::from_bytes([1; 32]),
            tang_pqc::Thumbprint::from_bytes([2; 32]),
            tang_pqc::Thumbprint::from_bytes([3; 32]),
        );
        let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
        let head = tang_pqc::b64::encode(&[9; 48]);
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
                    frozen: false,
                    retired: Vec::new(),
                },
                Pin {
                    anchor: b,
                    exp: Some(now + 3600),
                    heads: Vec::new(),
                    frozen: false,
                    retired: Vec::new(),
                },
                Pin {
                    anchor: c,
                    exp: Some(now - CLOCK_SKEW - 1),
                    heads: Vec::new(),
                    frozen: false,
                    retired: Vec::new(),
                },
            ]
        );
        assert_eq!(
            read_epoch_from(&path).unwrap(),
            Some((7, [9; 48])),
            "the watermark rides with the pins"
        );
        assert_eq!(
            read_anchors_from(&path).unwrap(),
            vec![a, b],
            "expired pin left out"
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn malformed_anchor_lines_are_refused() {
        let (dir, path) = scratch_anchors("malformed");
        let a = tang_pqc::Thumbprint::from_bytes([1; 32]);
        let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
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
            // A number is digits only: `u64::from_str` accepts a leading
            // `+`, a pin file does not (§4.4).
            format!("{a} +5\n"),
            format!("{a} {} +3 {}\n", now + 3600, root(9)),
            format!("{a} +1 {}\n", root(9)),
            "short\n".into(),
            "epoch nope xx\n".into(),
            "epoch 7 notahash\n".into(),
        ] {
            fs::write(&path, bad).unwrap();
            assert!(read_anchor_pins(&path).is_err());
        }
        // One line per anchor: a duplicate is a contradiction, not a
        // pin to average.
        fs::write(&path, format!("{a}\n{a} {}\n", now + 3600)).unwrap();
        assert!(read_anchor_pins(&path).is_err());
        fs::write(&path, format!("{a} 5 {}\n{a} 6 {}\n", root(9), root(9))).unwrap();
        assert!(read_anchor_pins(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn written_pins_read_back() {
        let (dir, path) = scratch_anchors("written");
        let a = tang_pqc::Thumbprint::from_bytes([1; 32]);
        let b = tang_pqc::Thumbprint::from_bytes([2; 32]);
        let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
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
                heads: vec![(5, test_hash(8))],
                frozen: false,
                retired: Vec::new(),
            }],
            None,
        )
        .unwrap();
        assert_eq!(
            read_anchor_pins(&path).unwrap(),
            vec![Pin {
                anchor: a,
                exp: None,
                heads: vec![(5, test_hash(8))],
                frozen: false,
                retired: Vec::new(),
            }]
        );
        write_anchor_pins(
            &path,
            "test",
            &[Pin {
                anchor: a,
                exp: Some(now + 3600),
                heads: vec![(3, test_hash(4))],
                frozen: false,
                retired: Vec::new(),
            }],
            Some((3, [4; 48])),
        )
        .unwrap();
        assert_eq!(
            read_anchor_pins(&path).unwrap(),
            vec![Pin {
                anchor: a,
                exp: Some(now + 3600),
                heads: vec![(3, test_hash(4))],
                frozen: false,
                retired: Vec::new(),
            }]
        );
        assert_eq!(read_epoch_from(&path).unwrap(), Some((3, [4; 48])));
        // An epoch head is SHA-384: a head of any other length is
        // malformed, a SHA-256-sized one included.
        let text = fs::read_to_string(&path).unwrap();
        for len in [tang_pqc::primitives::SHA256_LEN, 40] {
            let odd = format!("epoch 10 {}\n", tang_pqc::b64::encode(&vec![1; len]));
            fs::write(&path, format!("{text}{odd}")).unwrap();
            assert!(read_epoch_from(&path).is_err(), "{len}");
        }

        // A window round-trips: several heads, oldest first, and the
        // frozen marker (DESIGN-claim-logs.md §1.2, §2).
        let window = Pin {
            anchor: a,
            exp: Some(now + 3600),
            heads: vec![(3, test_hash(4)), (7, test_hash(5)), (9, test_hash(6))],
            frozen: true,
            retired: Vec::new(),
        };
        write_anchor_pins(&path, "test", std::slice::from_ref(&window), None).unwrap();
        assert_eq!(read_anchor_pins(&path).unwrap(), vec![window]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn live_pins_drops_expired_pins_with_their_heads() {
        let dir = std::env::temp_dir().join(format!("kuipa-paths-live-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pq-anchors");
        let live = tang_pqc::Thumbprint::from_bytes([1; 32]);
        let expired = tang_pqc::Thumbprint::from_bytes([2; 32]);
        let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
        let pins = [
            Pin {
                anchor: live,
                exp: Some(now + 3600),
                heads: vec![(3, test_hash(4)), (7, test_hash(5))],
                frozen: true,
                retired: Vec::new(),
            },
            Pin {
                anchor: expired,
                exp: Some(now - CLOCK_SKEW - 1),
                heads: vec![(9, test_hash(6))],
                frozen: true,
                retired: Vec::new(),
            },
        ];
        write_anchor_pins(&path, "test", &pins, None).unwrap();
        assert_eq!(live_pins(&path).unwrap(), vec![pins[0].clone()]);
        let (anchors, heads, _, frozen) = pinned_windows(&path).unwrap();
        assert_eq!(anchors, vec![live]);
        assert_eq!(
            heads,
            vec![
                kuipa_enroll::delegation::HeadPin {
                    anchor: live,
                    size: 3,
                    root: test_hash(4)
                },
                kuipa_enroll::delegation::HeadPin {
                    anchor: live,
                    size: 7,
                    root: test_hash(5)
                },
            ],
            "the whole window of a live pin, oldest first (§1.4)"
        );
        assert_eq!(frozen, vec![live], "an expired frozen pin is no freeze");
        // No file at all is nothing pinned; a malformed one is an error.
        fs::remove_file(&path).unwrap();
        assert_eq!(
            pinned_windows(&path).unwrap(),
            (Vec::new(), Vec::new(), Vec::new(), Vec::new())
        );
        fs::write(&path, format!("{live} +5\n")).unwrap();
        assert!(
            pinned_windows(&path).is_err(),
            "a corrupt pin file fails closed"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retired_claims_round_trip_and_forks_are_not_pinned() {
        let dir = std::env::temp_dir().join(format!("kuipa-retired-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("anchors");
        let a = tang_pqc::Thumbprint::from_bytes([1; 32]);
        let pin = Pin {
            anchor: a,
            exp: None,
            heads: vec![(3, test_hash(7))],
            frozen: false,
            retired: vec![test_hash(5), test_hash(6)],
        };
        write_anchor_pins(&path, "test", std::slice::from_ref(&pin), None).unwrap();
        assert_eq!(read_anchor_pins(&path).unwrap(), vec![pin.clone()]);
        let (_, _, retired, _) = pinned_windows(&path).unwrap();
        assert_eq!(retired, vec![test_hash(5), test_hash(6)]);
        // A retired line needs a pinned anchor and at least one claim, once.
        let leaf = tang_pqc::Thumbprint::from_bytes([5; 32]);
        let other = tang_pqc::Thumbprint::from_bytes([2; 32]);
        for bad in [
            format!("{a}\nretired {a}\n"),
            format!("{a}\nretired {other} {leaf}\n"),
            format!("{a}\nretired {a} {leaf}\nretired {a} {leaf}\n"),
            format!("{a}\nretired {a} nonsense\n"),
        ] {
            fs::write(&path, &bad).unwrap();
            assert!(read_anchor_pins(&path).is_err(), "{bad:?}");
        }

        // A head that extends joins the window with what it retired; a
        // shorter one is a fork, reported, and the window keeps its heads.
        let learned = vec![(a, vec![test_hash(6), test_hash(8)])];
        let (grown, forked) = merge_windows(
            std::slice::from_ref(&pin),
            &[(a, Some((5, test_hash(9))))],
            &learned,
        );
        assert!(!forked);
        assert_eq!(grown[0].heads, vec![(3, test_hash(7)), (5, test_hash(9))]);
        assert_eq!(
            grown[0].retired,
            vec![test_hash(5), test_hash(6), test_hash(8)]
        );
        let (kept, forked) = merge_windows(&grown, &[(a, Some((2, test_hash(4))))], &[]);
        assert!(forked);
        assert_eq!(kept[0].heads, grown[0].heads);
        // A new anchor starts its pin with what its first head retired.
        let (fresh, _) = merge_windows(
            &[],
            &[(other, Some((1, test_hash(3))))],
            &[(other, vec![test_hash(1)])],
        );
        assert_eq!(fresh[0].retired, vec![test_hash(1)]);
        let _ = fs::remove_dir_all(&dir);
    }
}
