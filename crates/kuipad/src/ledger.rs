//! The server's transparency log store (`DESIGN-tlog.md` §5), under the
//! key directory:
//!
//! ```text
//! tlog/<log id>/leaves             the public leaves in order, each a u32 length ‖ IPLF
//! tlog/<log id>/openings/YYYY-MM   the openings of the leaves logged that month,
//!                                  each a u32 length ‖ position (u64) ‖ IPLO, 0600
//! ```
//!
//! The leaves are what the log publishes: for a committed kind, the kind,
//! the day and a commitment.  The openings say what each commits to and
//! never leave the server except in a lookup, to their subject.  A
//! month's openings are deleted once it is older than the retention
//! ([`RETENTION_MONTHS`] by default): its leaves stay in the log and keep
//! verifying, but nobody, the server included, can say any more what they
//! were or whom they were about.
//!
//! An opening is written and synced before its leaf, and a leaf before it
//! joins the in-memory log, so an append the server acknowledged survives
//! a crash.  A record cut short by a crash was never acknowledged and is
//! dropped when the store is opened, and so is an opening whose leaf was
//! never written.
//!
//! Heads are published on a schedule ([`with_head_interval`](FileLedger::with_head_interval),
//! hourly by default): a head covers the leaves appended before the start
//! of the period it is published in, and the public routes serve nothing
//! past it, so watching the head grow says no more than how many events a
//! period had.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use kuipa_enroll::merkle::{self, Hash, TreeHash};
use kuipa_enroll::server::{Appended, DirectoryError, Ledger};
use kuipa_enroll::tlog::{self, Entry, Head, Leaf, Log, LogId, Opening, SignedHead};
use tang_pqc::{Policy, SigningKey, VerifyingKey};

use crate::keystore::write_private;

/// Errors from the store.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// How long a signed head is served before it is signed again, even when
/// nothing was appended: heads carry their time, and monitors want a
/// recent one.  Also the default publication period
/// ([`FileLedger::with_head_interval`]).
pub const HEAD_INTERVAL: Duration = Duration::from_secs(3600);

/// How many months of openings a server keeps by default: a year and a
/// month, so a yearly review still finds the whole year.
pub const RETENTION_MONTHS: u32 = 13;

/// Largest leaf record accepted when reading the store.
const MAX_RECORD: usize = tlog::MAX_BODY + 128;

/// Largest opening record: the event, its subject and the fixed fields.
const MAX_OPENING: usize = 2 * tlog::MAX_BODY + 128;

/// A server's log on disk.
#[derive(Debug)]
pub struct FileLedger {
    id: LogId,
    path: PathBuf,
    openings_dir: PathBuf,
    witnesses: Vec<VerifyingKey>,
    head_interval: Duration,
    retention_months: u32,
    inner: Mutex<Inner>,
}

/// What [`FileLedger::cosign`] made of a witness's submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cosigned {
    /// This many trusted cosignatures are now on the served head.
    Accepted(usize),
    /// The submission is not for the head being served: fetch it again.
    Stale,
    /// No cosignature on it is by a trusted witness, or verifies.
    Untrusted,
}

#[derive(Debug)]
struct Inner {
    log: Log,
    leaves: Vec<Leaf>,
    /// The kept openings, by leaf position.
    openings: BTreeMap<u64, Opening>,
    file: File,
    /// The head being published, and the period it was published in.
    head: Option<(SignedHead, u64)>,
    /// The month whose expired predecessors were last deleted.
    expired_before: Option<u32>,
}

impl FileLedger {
    /// Open, or create, the log of `server` in `realm` under `key_dir`,
    /// hashed with `alg` — the server key's ([`TreeHash::for_signer`]).
    /// The hash is part of the log's identity: a server whose key moves
    /// to another category (a crypto policy change) starts a new log, in
    /// its own directory, and the old one stays on disk for auditors.
    ///
    /// # Errors
    ///
    /// I/O, a store whose leaves do not form a valid log, or an opening
    /// that does not open the leaf at its position.
    pub fn open(key_dir: &Path, realm: &str, server: &str, alg: TreeHash) -> Result<Self, Error> {
        let id = LogId::of(realm, server, alg)?;
        let log_dir = key_dir.join("tlog").join(id.to_string());
        let openings_dir = log_dir.join("openings");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&openings_dir)?;
        let path = log_dir.join("leaves");
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path)?;
        let (leaves, complete) = read_leaves(&fs::read(&path)?)?;
        if complete < file.metadata()?.len() {
            eprintln!(
                "kuipad: {}: dropping an incomplete record at byte {complete}",
                path.display()
            );
            file.set_len(complete)?;
            file.sync_all()?;
        }
        let log = Log::replay(id, &leaves)?;
        let openings = read_openings(&openings_dir, &leaves)?;
        let ledger = Self {
            id,
            path,
            openings_dir,
            witnesses: Vec::new(),
            head_interval: HEAD_INTERVAL,
            retention_months: RETENTION_MONTHS,
            inner: Mutex::new(Inner {
                log,
                leaves,
                openings,
                file,
                head: None,
                expired_before: None,
            }),
        };
        Ok(ledger)
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publish a head once per `interval`: a head covers what was appended
    /// before the start of its period.  Zero publishes every append at
    /// once, for tests and the playground; a real server should not.
    #[must_use]
    pub fn with_head_interval(mut self, interval: Duration) -> Self {
        self.head_interval = interval;
        self
    }

    /// Keep `months` months of openings (at least one, the current); the
    /// default is [`RETENTION_MONTHS`].  Older months are deleted by
    /// [`expire`](Self::expire), which the first append of each month
    /// runs.
    #[must_use]
    pub fn with_retention(mut self, months: u32) -> Self {
        self.retention_months = months.max(1);
        self.inner().expired_before = None;
        self
    }

    /// The log's identity.
    #[must_use]
    pub fn id(&self) -> LogId {
        self.id
    }

    /// How many leaves it holds, published or not.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.inner().log.size()
    }

    /// How many leaves the public routes show: those under the head being
    /// published.
    fn published(&self, inner: &Inner) -> u64 {
        if self.head_interval.is_zero() {
            inner.log.size()
        } else {
            inner.head.as_ref().map_or(0, |(h, _)| h.head.size)
        }
    }

    /// Up to `max` published leaves from index `from`, oldest first.
    #[must_use]
    pub fn leaves(&self, from: u64, max: usize) -> Vec<Leaf> {
        let inner = self.inner();
        let published = usize::try_from(self.published(&inner)).unwrap_or(usize::MAX);
        usize::try_from(from)
            .ok()
            .and_then(|from| inner.leaves.get(from..published.min(inner.leaves.len())))
            .map(|rest| rest.iter().take(max).cloned().collect())
            .unwrap_or_default()
    }

    /// The inclusion path of leaf `index` in the tree of the first `size`
    /// leaves: the size of a head the client holds, at most the published
    /// one.
    ///
    /// # Errors
    ///
    /// For an index or size outside the published log.
    pub fn inclusion(&self, index: u64, size: u64) -> Result<Vec<Hash>, Error> {
        let inner = self.inner();
        let hashes = prefix(inner.log.hashes(), size.min(self.published(&inner)), size)?;
        let index = usize::try_from(index)?;
        Ok(merkle::path(hashes, index)?)
    }

    /// The proof that the tree of the first `old` leaves is a prefix of
    /// the tree of the first `size`, at most the published size.
    ///
    /// # Errors
    ///
    /// For sizes outside the published log.
    pub fn consistency(&self, old: u64, size: u64) -> Result<Vec<Hash>, Error> {
        let inner = self.inner();
        let hashes = prefix(inner.log.hashes(), size.min(self.published(&inner)), size)?;
        Ok(merkle::consistency(hashes, old)?)
    }

    /// The head being published, signed with `key`; none while nothing
    /// has been published.
    ///
    /// Every period of [`with_head_interval`](Self::with_head_interval)
    /// gets one head, signed when it is first asked for, over the leaves
    /// appended before the period began: the leaves of the period itself
    /// wait for the next.  With an interval of zero, the head covers
    /// every leaf and is re-signed when the log grows or the signature is
    /// older than [`HEAD_INTERVAL`].
    ///
    /// # Errors
    ///
    /// An OpenSSL error, or a key of another category than the log's.
    pub fn signed_head(&self, key: &SigningKey, now: u64) -> Result<Option<SignedHead>, Error> {
        if TreeHash::for_signer(key.public().alg()) != self.id.alg() {
            return Err(format!(
                "log {} is not hashed as a {} key signs",
                self.id,
                key.public().alg().jose_name()
            )
            .into());
        }
        let mut inner = self.inner();
        let interval = self.head_interval.as_secs();
        // The period to publish a new head for, if the one being published
        // is not this period's, and the size it covers.
        let (period, size) = if let Some(period) = now.checked_div(interval) {
            let current = inner.head.as_ref().is_some_and(|(_, p)| *p == period);
            (
                (!current).then_some(period),
                size_before(&inner, period * interval),
            )
        } else {
            // No schedule: every append, and an hourly re-signing.
            let fresh = inner.head.as_ref().is_some_and(|(h, _)| {
                h.head.size == inner.log.size()
                    && now.saturating_sub(h.head.time) < HEAD_INTERVAL.as_secs()
            });
            ((!fresh).then_some(0), inner.log.size())
        };
        if let Some(period) = period {
            inner.head = match usize::try_from(size)? {
                0 => None,
                n => {
                    let head = Head {
                        log: self.id,
                        size,
                        root: merkle::root(&inner.log.hashes()[..n])?,
                        time: now,
                    };
                    Some((SignedHead::issue(key, head)?, period))
                }
            };
        }
        Ok(inner.head.as_ref().map(|(h, _)| h.clone()))
    }

    /// Accept cosignatures by `witnesses` only (none by default).
    #[must_use]
    pub fn with_witnesses(mut self, witnesses: Vec<VerifyingKey>) -> Self {
        self.witnesses = witnesses;
        self
    }

    /// Add the trusted witnesses' cosignatures on `submitted` to the head
    /// being served, when `submitted` is that head: served heads then
    /// carry them until the next re-signing, and a witness cosigns again.
    #[must_use]
    pub fn cosign(&self, submitted: &SignedHead, policy: &Policy) -> Cosigned {
        let trusted = submitted.witnesses(&self.witnesses, policy);
        let mut inner = self.inner();
        let Some((head, _)) = inner.head.as_mut() else {
            return Cosigned::Stale;
        };
        if head.head != submitted.head || head.signature != submitted.signature {
            return Cosigned::Stale;
        }
        // A submission repeats the cosignatures it was served with: only
        // a trusted one the served head does not carry yet is new.
        let new: Vec<_> = submitted
            .cosignatures
            .iter()
            .filter(|c| trusted.contains(&c.witness) && !head.cosignatures.contains(c))
            .cloned()
            .collect();
        if new.is_empty() {
            return Cosigned::Untrusted;
        }
        for c in new {
            head.cosignatures.retain(|o| o.witness != c.witness);
            head.cosignatures.push(c);
        }
        Cosigned::Accepted(head.witnesses(&self.witnesses, policy).len())
    }

    /// The file the leaves are kept in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the months of openings older than the retention, as of
    /// `now`, and forget them; once a month, and at start-up.
    ///
    /// # Errors
    ///
    /// I/O deleting a month, or a time out of range.
    pub fn expire(&self, now: u64) -> Result<(), Error> {
        let current = month(now)?;
        if self.inner().expired_before.replace(current) == Some(current) {
            return Ok(());
        }
        let mut expired = Vec::new();
        for entry in fs::read_dir(&self.openings_dir)? {
            let name = entry?.file_name();
            let Some(m) = name.to_str().and_then(parse_month) else {
                continue;
            };
            if current.saturating_sub(m) >= self.retention_months {
                expired.push(m);
                fs::remove_file(self.openings_dir.join(&name))?;
            }
        }
        if !expired.is_empty() {
            let mut inner = self.inner();
            inner
                .openings
                .retain(|_, o| month(o.time).is_ok_and(|m| !expired.contains(&m)));
        }
        Ok(())
    }
}

impl Ledger for FileLedger {
    fn append(&self, opening: Opening) -> Result<Option<Appended>, DirectoryError> {
        let leaf = opening.leaf(self.id.alg())?;
        let bytes = leaf.to_bytes();
        let len = u32::try_from(bytes.len())?;
        let month_of = month(opening.time)?;
        let appended = {
            let mut inner = self.inner();
            inner.log.check(&leaf)?;
            let position = inner.log.size();
            // The opening first: a leaf on disk always has its opening,
            // until its month expires.
            let o = opening.to_bytes();
            let mut record = Vec::with_capacity(12 + o.len());
            record.extend_from_slice(&u32::try_from(o.len() + 8)?.to_be_bytes());
            record.extend_from_slice(&position.to_be_bytes());
            record.extend_from_slice(&o);
            let mut month_file = OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(self.openings_dir.join(month_name(month_of)))?;
            month_file.write_all(&record)?;
            month_file.sync_data()?;

            let mut record = Vec::with_capacity(4 + bytes.len());
            record.extend_from_slice(&len.to_be_bytes());
            record.extend_from_slice(&bytes);
            inner.file.write_all(&record)?;
            inner.file.sync_data()?;
            let index = inner.log.append(&leaf)?;
            let appended = Appended {
                log: self.id,
                index,
                leaf: leaf.hash()?,
                time: opening.time,
            };
            inner.leaves.push(leaf);
            inner.openings.insert(index, opening);
            appended
        };
        self.expire(appended.time)?;
        Ok(Some(appended))
    }

    fn signed_head(
        &self,
        key: &SigningKey,
        now: u64,
    ) -> Result<Option<SignedHead>, DirectoryError> {
        FileLedger::signed_head(self, key, now)
    }

    fn find(
        &self,
        subject: &[u8],
        from: u64,
        size: u64,
        max: usize,
    ) -> Result<Vec<Entry>, DirectoryError> {
        let inner = self.inner();
        let hashes = prefix(inner.log.hashes(), size, size)?;
        let mut found = Vec::new();
        for (&i, opening) in inner.openings.range(from..size) {
            if found.len() == max {
                break;
            }
            if opening.subject == subject {
                let at = usize::try_from(i)?;
                found.push(Entry {
                    index: i,
                    leaf: inner.leaves[at].clone(),
                    path: merkle::path(hashes, at)?,
                    opening: Some(opening.clone()),
                });
            }
        }
        Ok(found)
    }
}

/// The first `size` of `hashes`, when `size` is within `limit`.
fn prefix(hashes: &[Hash], limit: u64, size: u64) -> Result<&[Hash], Error> {
    usize::try_from(size)
        .ok()
        .filter(|s| *s > 0 && size <= limit)
        .and_then(|s| hashes.get(..s))
        .ok_or_else(|| "size outside the log".into())
}

/// The month of a Unix time, counted from year 0: `year × 12 + month − 1`.
fn month(time: u64) -> Result<u32, Error> {
    let t = synta::GeneralizedTime::from_unix(i64::try_from(time)?).ok_or("time out of range")?;
    Ok(u32::from(t.year) * 12 + u32::from(t.month) - 1)
}

/// `YYYY-MM`, the name of a month's openings file.
fn month_name(m: u32) -> String {
    format!("{:04}-{:02}", m / 12, m % 12 + 1)
}

/// The month a `YYYY-MM` file name names.
fn parse_month(name: &str) -> Option<u32> {
    let (y, m) = name.split_once('-')?;
    let (y, m): (u32, u32) = (y.parse().ok()?, m.parse().ok()?);
    (y.to_string().len() == 4 && (1..=12).contains(&m) && name.len() == 7).then(|| y * 12 + m - 1)
}

/// Parse the store's records, and how many bytes of complete records
/// there are: a trailing partial record is left out, a malformed complete
/// one is an error.
fn read_leaves(bytes: &[u8]) -> Result<(Vec<Leaf>, u64), Error> {
    let (records, complete) = records(bytes, MAX_RECORD)?;
    let leaves = records
        .into_iter()
        .map(Leaf::from_bytes)
        .collect::<Result<_, _>>()?;
    Ok((leaves, complete))
}

/// How many leaves were appended before `boundary`, by their openings'
/// times: the leaves of a publication period are the last ones.  A leaf
/// whose opening expired is months old.
fn size_before(inner: &Inner, boundary: u64) -> u64 {
    let mut n = inner.leaves.len();
    while let Some(last) = n.checked_sub(1) {
        let time = inner
            .openings
            .get(&(last as u64))
            .map_or(inner.leaves[last].time, |o| o.time);
        if time < boundary {
            break;
        }
        n = last;
    }
    n as u64
}

/// The complete length-prefixed records in `bytes`, and how many bytes
/// they span.
fn records(bytes: &[u8], max: usize) -> Result<(Vec<&[u8]>, u64), Error> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(len) = bytes.get(at..at + 4) {
        let len = u32::from_be_bytes(len.try_into()?) as usize;
        if len > max {
            return Err(format!("log record at byte {at} is too long").into());
        }
        let Some(record) = bytes.get(at + 4..at + 4 + len) else {
            break;
        };
        out.push(record);
        at += 4 + len;
    }
    Ok((out, at as u64))
}

/// Read every month's openings, keeping those whose leaf was written and
/// rewriting a file that holds any other: an opening synced before a crash
/// kept its leaf from the disk.
fn read_openings(dir: &Path, leaves: &[Leaf]) -> Result<BTreeMap<u64, Opening>, Error> {
    let mut openings = BTreeMap::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(parse_month)
            .is_none()
        {
            continue;
        }
        let bytes = fs::read(&path)?;
        let (records, complete) = records(&bytes, MAX_OPENING)?;
        let mut kept = Vec::with_capacity(bytes.len());
        let mut dropped = complete < bytes.len() as u64;
        for record in records {
            let (position, opening) = record
                .split_first_chunk::<8>()
                .ok_or_else(|| format!("{}: a short opening record", path.display()))?;
            let position = u64::from_be_bytes(*position);
            let Some(leaf) = usize::try_from(position).ok().and_then(|p| leaves.get(p)) else {
                dropped = true;
                continue;
            };
            let opening = Opening::from_bytes(opening)?;
            if !opening.opens(leaf)? {
                return Err(format!(
                    "{}: the opening of leaf {position} does not open it",
                    path.display()
                )
                .into());
            }
            kept.extend_from_slice(&u32::try_from(record.len())?.to_be_bytes());
            kept.extend_from_slice(record);
            openings.insert(position, opening);
        }
        if dropped {
            eprintln!(
                "kuipad: {}: dropping openings of leaves never written",
                path.display()
            );
            write_private(&path, &kept)?;
        }
    }
    Ok(openings)
}

#[cfg(test)]
mod tests {
    use kuipa_enroll::tlog::Kind;
    use tang_pqc::{Policy, SignatureAlg};

    use super::*;

    /// 2026-10-26 12:00:00 UTC.
    const T: u64 = 1_793_016_000;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kuipad-ledger-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn open(dir: &Path) -> FileLedger {
        FileLedger::open(dir, "EXAMPLE.TEST", "ipa1.example.test", TreeHash::Sha256).unwrap()
    }

    /// A ledger that publishes every append at once, as the tests and the
    /// playground run it.
    fn eager(dir: &Path) -> FileLedger {
        open(dir).with_head_interval(Duration::ZERO)
    }

    fn event(kind: Kind, time: u64, subject: &[u8], body: &[u8]) -> Opening {
        Opening::new(kind, time, subject, body.to_vec()).unwrap()
    }

    #[test]
    fn appends_survive_a_reopen_and_a_torn_write() {
        let dir = temp("reopen");
        let ledger = eager(&dir);
        for i in 0..3u8 {
            let a = ledger
                .append(event(Kind::SEAL_DEVICE, T, b"seal", &[i]))
                .unwrap()
                .unwrap();
            assert_eq!(a.index, u64::from(i));
            assert_eq!(a.time, T, "the receipt has the exact time");
        }
        let path = ledger.path().to_owned();
        drop(ledger);

        // A crash during a write leaves a partial record: it is dropped.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0, 0, 0, 40, 1, 2]).unwrap();
        drop(f);
        let reopened = eager(&dir);
        assert_eq!(reopened.size(), 3);
        let a = reopened
            .append(event(Kind::KEYS_FETCH, T, b"host", b"x"))
            .unwrap()
            .unwrap();
        assert_eq!(a.index, 3);
        drop(reopened);
        let again = eager(&dir);
        let leaves = again.leaves(0, 10);
        assert_eq!(leaves.len(), 4);
        assert_eq!(leaves[3].kind, Kind::KEYS_FETCH);
        // The public leaves say nothing of the subject; the openings kept
        // beside them do, after a reopen too.
        assert!(
            leaves
                .iter()
                .all(|l| l.index == Hash::zero(TreeHash::Sha256))
        );
        let found = Ledger::find(&again, b"seal", 0, 4, 10).unwrap();
        assert_eq!(found.len(), 3);
        assert!(found.iter().all(|e| {
            e.opening
                .as_ref()
                .is_some_and(|o| o.opens(&e.leaf).unwrap())
        }));
        assert_eq!(again.leaves(2, 1).len(), 1);
        assert_eq!(again.leaves(9, 1), [] as [Leaf; 0]);

        // A corrupted complete record is refused, not skipped.
        let mut bytes = fs::read(&path).unwrap();
        bytes[4] = b'X';
        fs::write(&path, bytes).unwrap();
        assert!(
            FileLedger::open(&dir, "EXAMPLE.TEST", "ipa1.example.test", TreeHash::Sha256).is_err()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_opening_whose_leaf_was_never_written_is_dropped() {
        let dir = temp("torn-opening");
        let ledger = eager(&dir);
        ledger
            .append(event(Kind::SEAL_POLICY, T, b"v", b"a"))
            .unwrap();
        let path = ledger.path().to_owned();
        let month_file = ledger.openings_dir.join(month_name(month(T).unwrap()));
        drop(ledger);
        // A crash between the opening and its leaf: an opening for
        // position 1, and no leaf 1.
        let o = event(Kind::SEAL_POLICY, T, b"v", b"b").to_bytes();
        let mut record = u32::try_from(o.len() + 8).unwrap().to_be_bytes().to_vec();
        record.extend_from_slice(&1u64.to_be_bytes());
        record.extend_from_slice(&o);
        OpenOptions::new()
            .append(true)
            .open(&month_file)
            .unwrap()
            .write_all(&record)
            .unwrap();
        let reopened = eager(&dir);
        assert_eq!(reopened.size(), 1);
        // The next append takes position 1 with its own opening.
        reopened
            .append(event(Kind::SEAL_POLICY, T, b"w", b"c"))
            .unwrap();
        drop(reopened);
        let again = eager(&dir);
        let found = Ledger::find(&again, b"w", 0, 2, 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].opening.as_ref().unwrap().event, b"c");
        assert_eq!(Ledger::find(&again, b"v", 0, 2, 10).unwrap().len(), 1);

        // An opening that does not open its leaf: the store is refused.
        let mut leaves = fs::read(&path).unwrap();
        let last = leaves.len() - 1;
        leaves[last] ^= 1;
        fs::write(&path, leaves).unwrap();
        assert!(
            FileLedger::open(&dir, "EXAMPLE.TEST", "ipa1.example.test", TreeHash::Sha256).is_err()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn heads_and_proofs_at_any_served_size() {
        let dir = temp("heads");
        let ledger = eager(&dir);
        let key = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        assert!(ledger.signed_head(&key, 100).unwrap().is_none());
        ledger
            .append(event(Kind::SEAL_POLICY, T, b"v", b"a"))
            .unwrap();
        ledger
            .append(event(Kind::SEAL_DEVICE, T, b"v", b"b"))
            .unwrap();
        let old = ledger.signed_head(&key, 100).unwrap().unwrap();
        old.verify(key.public(), &Policy::default()).unwrap();
        // Cached while nothing changes and it is recent.
        assert_eq!(ledger.signed_head(&key, 200).unwrap(), Some(old.clone()));
        let later = ledger
            .signed_head(&key, 100 + HEAD_INTERVAL.as_secs())
            .unwrap()
            .unwrap();
        assert_eq!(later.head.size, 2);
        assert_ne!(later.head.time, old.head.time);

        for i in 0..5u8 {
            ledger
                .append(event(Kind::ESCROW_RELEASE, T, b"v", &[i]))
                .unwrap();
        }
        let new = ledger
            .signed_head(&key, 300 + HEAD_INTERVAL.as_secs())
            .unwrap()
            .unwrap();
        assert_eq!(new.head.size, 7);
        let proof = ledger.consistency(old.head.size, new.head.size).unwrap();
        assert!(new.head.extends(&old.head, &proof).unwrap());
        // Proofs against the old, smaller head still verify.
        let leaves = ledger.leaves(0, 10);
        let path = ledger.inclusion(1, old.head.size).unwrap();
        assert!(old.head.includes(&leaves[1], 1, &path).unwrap());
        assert!(ledger.inclusion(5, 2).is_err());
        assert!(ledger.inclusion(0, 0).is_err());
        assert!(ledger.consistency(2, 99).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn heads_are_published_once_a_period_over_what_came_before_it() {
        let dir = temp("schedule");
        let ledger = open(&dir);
        let key = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let hour = HEAD_INTERVAL.as_secs();
        let start = T - T % hour;
        // Two events in the first hour; nothing is published within it.
        ledger
            .append(event(Kind::SEAL_DEVICE, start + 10, b"v", b"a"))
            .unwrap();
        assert!(ledger.signed_head(&key, start + 20).unwrap().is_none());
        ledger
            .append(event(Kind::SEAL_DEVICE, start + 30, b"v", b"b"))
            .unwrap();
        assert_eq!(ledger.leaves(0, 10), [] as [Leaf; 0]);
        assert!(ledger.inclusion(0, 1).is_err());

        // The next hour's head covers both, and stays the same all hour:
        // a third event within it waits for the hour after.
        let h1 = ledger.signed_head(&key, start + hour + 5).unwrap().unwrap();
        assert_eq!(h1.head.size, 2);
        ledger
            .append(event(Kind::SEAL_DEVICE, start + hour + 6, b"v", b"c"))
            .unwrap();
        assert_eq!(
            ledger.signed_head(&key, start + 2 * hour - 1).unwrap(),
            Some(h1.clone())
        );
        assert_eq!(ledger.leaves(0, 10).len(), 2);
        assert!(ledger.consistency(1, 3).is_err());

        let h2 = ledger.signed_head(&key, start + 2 * hour).unwrap().unwrap();
        assert_eq!(h2.head.size, 3);
        assert_eq!(ledger.leaves(0, 10).len(), 3);
        let proof = ledger.consistency(2, 3).unwrap();
        assert!(h2.head.extends(&h1.head, &proof).unwrap());
        // A quiet hour is signed again, over the same leaves.
        let h3 = ledger.signed_head(&key, start + 3 * hour).unwrap().unwrap();
        assert_eq!((h3.head.size, h3.head.root), (h2.head.size, h2.head.root));
        assert!(h3.head.time > h2.head.time);

        // After a restart, the period's own events still wait.
        ledger
            .append(event(Kind::SEAL_DEVICE, start + 3 * hour + 1, b"v", b"d"))
            .unwrap();
        drop(ledger);
        let reopened = open(&dir);
        let h4 = reopened
            .signed_head(&key, start + 3 * hour + 2)
            .unwrap()
            .unwrap();
        assert_eq!(h4.head.size, 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn finds_a_subjects_leaves_up_to_a_head() {
        let dir = temp("find");
        let ledger = eager(&dir);
        for (i, subject) in [b"a", b"b", b"a", b"a"].iter().enumerate() {
            let body = [u8::try_from(i).unwrap()];
            ledger
                .append(event(Kind::SEAL_DEVICE, T, *subject, &body))
                .unwrap();
        }
        let key = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let head = ledger.signed_head(&key, 100).unwrap().unwrap().head;
        let found = Ledger::find(&ledger, b"a", 0, head.size, 10).unwrap();
        assert_eq!(found.iter().map(|e| e.index).collect::<Vec<_>>(), [0, 2, 3]);
        for e in &found {
            assert!(head.includes(&e.leaf, e.index, &e.path).unwrap());
            assert_eq!(e.opening.as_ref().unwrap().subject, b"a");
        }
        // From an index, at most `max`, only up to the head's size.
        assert_eq!(Ledger::find(&ledger, b"a", 1, 4, 1).unwrap()[0].index, 2);
        assert_eq!(Ledger::find(&ledger, b"a", 0, 2, 10).unwrap().len(), 1);
        assert_eq!(
            Ledger::find(&ledger, b"c", 0, 4, 10).unwrap(),
            [] as [Entry; 0]
        );
        assert!(Ledger::find(&ledger, b"a", 0, 9, 10).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn openings_expire_after_the_retention_and_their_leaves_stay() {
        let dir = temp("retention");
        let ledger = eager(&dir);
        let month = 31 * 86_400;
        // One event a month for fifteen months.
        let first = T - 15 * month;
        for i in 0..15u64 {
            ledger
                .append(event(Kind::ESCROW_RELEASE, first + i * month, b"v", &[0]))
                .unwrap();
        }
        // Each new month's first append deletes what is older than
        // thirteen months.
        let files = |l: &FileLedger| fs::read_dir(&l.openings_dir).unwrap().count();
        assert_eq!(files(&ledger), 13);
        let found = Ledger::find(&ledger, b"v", 0, 15, 20).unwrap();
        assert_eq!(found.first().unwrap().index, 2);
        assert_eq!(ledger.leaves(0, 20).len(), 15);
        drop(ledger);
        // Reopened with a shorter retention, as of the last event's month:
        // the expired leaves still verify and have no opening.
        let ledger = eager(&dir).with_retention(3);
        ledger.expire(first + 14 * month).unwrap();
        assert_eq!(files(&ledger), 3);
        let key = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let head = ledger.signed_head(&key, T).unwrap().unwrap();
        assert_eq!(head.head.size, 15);
        assert_eq!(Ledger::find(&ledger, b"v", 0, 15, 20).unwrap().len(), 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn months_are_named_and_parsed() {
        assert_eq!(month_name(month(T).unwrap()), "2026-10");
        assert_eq!(month_name(month(0).unwrap()), "1970-01");
        assert_eq!(parse_month("2026-10"), month(T).ok());
        for bad in ["2026-13", "2026-00", "26-10", "2026-1", "2026-10.tmp", "x"] {
            assert_eq!(parse_month(bad), None, "{bad}");
        }
    }

    #[test]
    fn cosignatures_land_only_on_the_served_head() {
        let dir = temp("cosign");
        let witness = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
        let stranger = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
        let ledger = eager(&dir).with_witnesses(vec![witness.public().clone()]);
        let key = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let policy = Policy::default();
        ledger
            .append(event(Kind::SEAL_DEVICE, T, b"v", b"a"))
            .unwrap();
        let served = ledger.signed_head(&key, 100).unwrap().unwrap();

        let mut by_stranger = served.clone();
        by_stranger.cosign(&stranger, 101).unwrap();
        assert_eq!(ledger.cosign(&by_stranger, &policy), Cosigned::Untrusted);
        let mut by_witness = served.clone();
        by_witness.cosign(&witness, 101).unwrap();
        by_witness.cosign(&stranger, 101).unwrap();
        assert_eq!(ledger.cosign(&by_witness, &policy), Cosigned::Accepted(1));
        // The served head carries the trusted cosignature, not the other.
        let now = ledger.signed_head(&key, 102).unwrap().unwrap();
        assert_eq!(now.cosignatures.len(), 1);
        assert_eq!(now.witnesses(&[witness.public().clone()], &policy).len(), 1);
        // A stranger resubmitting the served head, with the trusted
        // cosignature it was served, adds nothing.
        let mut replayed = now.clone();
        replayed.cosign(&stranger, 102).unwrap();
        assert_eq!(ledger.cosign(&replayed, &policy), Cosigned::Untrusted);

        // Once the log grows the head is re-signed: an old cosignature is
        // for a head no longer served.
        ledger
            .append(event(Kind::SEAL_DEVICE, T, b"v", b"b"))
            .unwrap();
        let next = ledger.signed_head(&key, 103).unwrap().unwrap();
        assert_eq!(
            next.cosignatures,
            [] as [kuipa_enroll::tlog::Cosignature; 0]
        );
        assert_eq!(ledger.cosign(&by_witness, &policy), Cosigned::Stale);
        let _ = fs::remove_dir_all(&dir);
    }
}
