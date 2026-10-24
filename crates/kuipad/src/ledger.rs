//! The server's transparency log store (`DESIGN-tlog.md` §5), under the
//! key directory:
//!
//! ```text
//! tlog/index.key          this server's index key: 32 random bytes, 0600
//! tlog/<log id>/leaves    the leaves in order, each a u32 length ‖ IPLF
//! ```
//!
//! Each server indexes its own events under its own key, so an auditor
//! reading two servers' logs cannot tell that two leaves concern the same
//! vault; only the server that logged a leaf can map a subject to it.
//!
//! A leaf is checked, written and synced before it joins the in-memory
//! log, so an append the server acknowledged survives a crash.  A record
//! cut short by a crash during the write was never acknowledged and is
//! dropped when the store is opened.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use kuipa_enroll::merkle::{self, Hash};
use kuipa_enroll::server::{Appended, DirectoryError, Ledger};
use kuipa_enroll::tlog::{self, Kind, Leaf, Log, LogId, SignedHead};
use native_ossl::rand::Rand;
use tang_pqc::{SigningKey, unix_seconds};

use crate::keystore::write_private;

/// Errors from the store.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// How long a signed head is served before it is signed again, even when
/// nothing was appended: heads carry their time, and monitors want a
/// recent one.
pub const HEAD_INTERVAL: Duration = Duration::from_secs(3600);

/// Largest leaf record accepted when reading the store.
const MAX_RECORD: usize = tlog::MAX_BODY + 128;

/// A server's log on disk.
#[derive(Debug)]
pub struct FileLedger {
    id: LogId,
    key: [u8; 32],
    path: PathBuf,
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    log: Log,
    leaves: Vec<Leaf>,
    file: File,
    head: Option<SignedHead>,
}

impl FileLedger {
    /// Open, or create, the log of `server` in `realm` under `key_dir`.
    ///
    /// # Errors
    ///
    /// I/O, or a store whose leaves do not form a valid log.
    pub fn open(key_dir: &Path, realm: &str, server: &str) -> Result<Self, Error> {
        let dir = key_dir.join("tlog");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        let key = index_key(&dir.join("index.key"))?;
        let id = LogId::of(realm, server)?;
        let log_dir = dir.join(id.to_string());
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&log_dir)?;
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
        Ok(Self {
            id,
            key,
            path,
            inner: Mutex::new(Inner {
                log,
                leaves,
                file,
                head: None,
            }),
        })
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The log's identity.
    #[must_use]
    pub fn id(&self) -> LogId {
        self.id
    }

    /// How many leaves it holds.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.inner().log.size()
    }

    /// Up to `max` leaves from index `from`, oldest first.
    #[must_use]
    pub fn leaves(&self, from: u64, max: usize) -> Vec<Leaf> {
        let inner = self.inner();
        usize::try_from(from)
            .ok()
            .and_then(|from| inner.leaves.get(from..))
            .map(|rest| rest.iter().take(max).cloned().collect())
            .unwrap_or_default()
    }

    /// The inclusion path of leaf `index` in the tree of the first `size`
    /// leaves: the size of a head the client holds.
    ///
    /// # Errors
    ///
    /// For an index or size outside the log.
    pub fn inclusion(&self, index: u64, size: u64) -> Result<Vec<Hash>, Error> {
        let inner = self.inner();
        let hashes = prefix(inner.log.hashes(), size)?;
        let index = usize::try_from(index)?;
        Ok(merkle::path(hashes, index)?)
    }

    /// The proof that the tree of the first `old` leaves is a prefix of
    /// the tree of the first `size`.
    ///
    /// # Errors
    ///
    /// For sizes outside the log.
    pub fn consistency(&self, old: u64, size: u64) -> Result<Vec<Hash>, Error> {
        let inner = self.inner();
        let hashes = prefix(inner.log.hashes(), size)?;
        Ok(merkle::consistency(hashes, old)?)
    }

    /// The current head signed with `key`, re-signed when the log grew or
    /// the last signature is older than [`HEAD_INTERVAL`]; none for an
    /// empty log.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn signed_head(&self, key: &SigningKey, now: u64) -> Result<Option<SignedHead>, Error> {
        let mut inner = self.inner();
        if inner.log.size() == 0 {
            return Ok(None);
        }
        let fresh = inner.head.as_ref().is_some_and(|h| {
            h.head.size == inner.log.size()
                && now.saturating_sub(h.head.time) < HEAD_INTERVAL.as_secs()
        });
        if !fresh {
            let head = SignedHead::issue(key, inner.log.head(now)?)?;
            inner.head = Some(head);
        }
        Ok(inner.head.clone())
    }

    /// The file the leaves are kept in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Ledger for FileLedger {
    fn append(
        &self,
        kind: Kind,
        subject: &[u8],
        body: &[u8],
    ) -> Result<Option<Appended>, DirectoryError> {
        let leaf = Leaf {
            kind,
            time: unix_seconds(SystemTime::now()),
            index: tlog::index(&self.key, subject)?,
            body: body.to_vec(),
        };
        let bytes = leaf.to_bytes();
        let len = u32::try_from(bytes.len())?;
        let mut inner = self.inner();
        inner.log.check(&leaf)?;
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
            time: leaf.time,
        };
        inner.leaves.push(leaf);
        Ok(Some(appended))
    }
}

/// The first `size` of `hashes`.
fn prefix(hashes: &[Hash], size: u64) -> Result<&[Hash], Error> {
    usize::try_from(size)
        .ok()
        .filter(|s| *s > 0)
        .and_then(|s| hashes.get(..s))
        .ok_or_else(|| "size outside the log".into())
}

/// Read the index key at `path`, creating it on first use.
fn index_key(path: &Path) -> Result<[u8; 32], Error> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes
            .try_into()
            .map_err(|_| format!("{}: not a 32-byte key", path.display()))?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            Rand::fill_private(&mut key)?;
            write_private(path, &key)?;
            Ok(key)
        }
        Err(e) => Err(e.into()),
    }
}

/// Parse the store's records, and how many bytes of complete records
/// there are: a trailing partial record is left out, a malformed complete
/// one is an error.
fn read_leaves(bytes: &[u8]) -> Result<(Vec<Leaf>, u64), Error> {
    let mut leaves = Vec::new();
    let mut at = 0usize;
    while let Some(len) = bytes.get(at..at + 4) {
        let len = u32::from_be_bytes(len.try_into()?) as usize;
        if len > MAX_RECORD {
            return Err(format!("log record at byte {at} is too long").into());
        }
        let Some(record) = bytes.get(at + 4..at + 4 + len) else {
            break;
        };
        leaves.push(Leaf::from_bytes(record)?);
        at += 4 + len;
    }
    Ok((leaves, at as u64))
}

#[cfg(test)]
mod tests {
    use tang_pqc::{Policy, SignatureAlg};

    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kuipad-ledger-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn appends_survive_a_reopen_and_a_torn_write() {
        let dir = temp("reopen");
        let ledger = FileLedger::open(&dir, "EXAMPLE.TEST", "ipa1.example.test").unwrap();
        for i in 0..3u8 {
            let a = ledger
                .append(Kind::VAULT_DEVICE, b"vault", &[i])
                .unwrap()
                .unwrap();
            assert_eq!(a.index, u64::from(i));
        }
        let path = ledger.path().to_owned();
        drop(ledger);

        // A crash during a write leaves a partial record: it is dropped.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0, 0, 0, 40, 1, 2]).unwrap();
        drop(f);
        let reopened = FileLedger::open(&dir, "EXAMPLE.TEST", "ipa1.example.test").unwrap();
        assert_eq!(reopened.size(), 3);
        let a = reopened
            .append(Kind::KEYS_FETCH, b"host", b"x")
            .unwrap()
            .unwrap();
        assert_eq!(a.index, 3);
        drop(reopened);
        let again = FileLedger::open(&dir, "EXAMPLE.TEST", "ipa1.example.test").unwrap();
        let leaves = again.leaves(0, 10);
        assert_eq!(leaves.len(), 4);
        assert_eq!(leaves[3].kind, Kind::KEYS_FETCH);
        // The index key is kept, so subjects keep their index.
        assert_eq!(leaves[0].index, leaves[1].index);
        assert_eq!(again.leaves(2, 1).len(), 1);
        assert!(again.leaves(9, 1).is_empty());

        // A corrupted complete record is refused, not skipped.
        let mut bytes = fs::read(&path).unwrap();
        bytes[4] = b'X';
        fs::write(&path, bytes).unwrap();
        assert!(FileLedger::open(&dir, "EXAMPLE.TEST", "ipa1.example.test").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn heads_and_proofs_at_any_served_size() {
        let dir = temp("heads");
        let ledger = FileLedger::open(&dir, "EXAMPLE.TEST", "ipa1.example.test").unwrap();
        let key = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        assert!(ledger.signed_head(&key, 100).unwrap().is_none());
        ledger.append(Kind::VAULT_POLICY, b"v", b"a").unwrap();
        ledger.append(Kind::VAULT_DEVICE, b"v", b"b").unwrap();
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
            ledger.append(Kind::ESCROW_RELEASE, b"v", &[i]).unwrap();
        }
        let new = ledger.signed_head(&key, 300).unwrap().unwrap();
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
}
