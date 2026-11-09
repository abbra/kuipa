//! Sealed backups (`docs/DESIGN-backup.md`): the realm's recovery key and its
//! papers, and sealing and opening a backup stream with them.
//!
//! Nothing here talks to a server: a recovery must work with the realm gone.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use kuipa_enroll::backup::{self, Recipient};
use kuipa_enroll::shards::{self, Share};
use native_ossl::rand::Rand;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tang_pqc::{ExchangeKey, ExchangeKeyPair, KemAlg, Policy};

use crate::paths::{Error, write_file};
use crate::seal::SealClient;

/// What a host needs to seal backups: public data only.  `kuipa backup key
/// create` writes it; `ipa-backup` reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientFile {
    /// The realm the backups are of.
    pub realm: String,
    /// The recovery key's id: the thumbprint of `key`.
    pub key_id: String,
    /// The set id every paper carries.
    pub set: u32,
    /// The recovery public key, its JWK.
    pub key: String,
}

impl RecipientFile {
    /// Read and check a recipient file: its key must have the id it names.
    ///
    /// # Errors
    ///
    /// I/O, a file that is not one, or a key that is not the one named.
    pub fn read(path: &Path) -> Result<Self, Error> {
        let file: Self = serde_json::from_slice(&fs::read(path)?)
            .map_err(|e| format!("{}: not a recipient file: {e}", path.display()))?;
        file.recipient()?;
        Ok(file)
    }

    /// Write it, mode 0644 (nothing in it is secret).
    ///
    /// # Errors
    ///
    /// I/O errors.
    pub fn write(&self, path: &Path) -> Result<(), Error> {
        write_file(path, &serde_json::to_vec_pretty(self)?, 0o644)
    }

    /// The recipient it names.
    ///
    /// # Errors
    ///
    /// A key that does not parse, or is not the one `key_id` names.
    pub fn recipient(&self) -> Result<Recipient, Error> {
        let key = ExchangeKey::from_jwk_json(self.key.as_bytes())?;
        if key.kid().to_string() != self.key_id {
            return Err("the recipient file's key is not the one it names".into());
        }
        Ok(Recipient { key, set: self.set })
    }
}

/// A new recovery key: the public file and the papers to print.
pub struct NewSet {
    /// What the backup hosts keep.
    pub file: RecipientFile,
    /// The papers, one page each.
    pub pages: Vec<String>,
}

/// Make a recovery key for `realm`, hidden under `recovery` and split into
/// `shares` papers of which `threshold` recover it.  The key is ML-KEM-1024
/// when the system crypto policy allows no ML-KEM-768.
///
/// # Errors
///
/// Parameters outside their ranges, or a crypto error.
pub fn create_key(
    realm: &str,
    recovery: &[u8],
    threshold: u8,
    shares: u8,
) -> Result<NewSet, Error> {
    let kem_1024 = !Policy::from_system()?.allows_kem(KemAlg::MlKem768);
    let mut seed = [0u8; 32];
    Rand::fill_private(&mut seed)?;
    let params = shards::SetParams::new(threshold, shares, kem_1024);
    let salt = shards::new_salt().map_err(|e| e.to_string())?;
    let hidden = shards::mask(
        &seed,
        &String::from_utf8_lossy(recovery),
        &salt,
        params.iterations,
    )
    .map_err(|e| e.to_string())?;
    let made = shards::make_shares(&hidden, salt, params).map_err(|e| e.to_string())?;
    let pair = shards::recovery_key(&seed, kem_1024).map_err(|e| e.to_string())?;
    let file = RecipientFile {
        realm: realm.to_owned(),
        key_id: pair.public().kid().to_string(),
        set: made[0].header.set_id,
        key: pair.public().to_jwk_json(),
    };
    let pages = made.iter().map(|s| page(&file, s, shares)).collect();
    Ok(NewSet { file, pages })
}

/// One paper: the words, and what a reader years later needs to know.
fn page(file: &RecipientFile, share: &Share, shares: u8) -> String {
    let h = &share.header;
    let mut out = format!(
        "kuipa backup recovery shard {} of {} (any {} are needed)  set {:05X}\n\
         for realm {} backups, recovery key id {}\n\
         the passphrase you chose is also needed\n",
        h.index, shares, h.threshold, h.set_id, file.realm, file.key_id
    );
    for line in shards::format_lines(&share.symbols()) {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// The recovery key the papers' words and `recovery` make, with what was
/// repaired on each paper.
///
/// # Errors
///
/// Unreadable or mixed papers, or too few.
pub fn recover_key(
    words: &[String],
    recovery: &[u8],
) -> Result<(ExchangeKeyPair, Vec<Value>), Error> {
    let (read, report) = SealClient::gather_shares(words)?;
    let combined = shards::combine(&read).map_err(|e| e.to_string())?;
    let seed = shards::mask(
        &combined.hidden,
        &String::from_utf8_lossy(recovery),
        &combined.salt,
        combined.iterations,
    )
    .map_err(|e| e.to_string())?;
    let pair = shards::recovery_key(&seed, combined.kem_1024).map_err(|e| e.to_string())?;
    Ok((pair, report))
}

/// Whether the papers would recover the key `file` names.
///
/// # Errors
///
/// Unreadable papers, or a key that is not the one named (a wrong paper or
/// passphrase).
pub fn check(words: &[String], recovery: &[u8], file: &RecipientFile) -> Result<Value, Error> {
    let (pair, report) = recover_key(words, recovery)?;
    if pair.public().kid().to_string() != file.key_id {
        return Err(
            "the passphrase or a paper is wrong: the key they make is not the one named".into(),
        );
    }
    Ok(json!({ "recovery_key": file.key_id, "repaired": report }))
}

/// A sibling of `path` the stream is written to before it replaces `path`.
fn part(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".part");
    PathBuf::from(name)
}

/// Write what `fill` produces to `path`, mode 0600, atomically: the file
/// appears whole or not at all.
fn atomic(path: &Path, fill: impl FnOnce(&mut fs::File) -> Result<(), Error>) -> Result<(), Error> {
    let tmp = part(path);
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let done = fill(&mut f).and_then(|()| Ok(f.sync_all()?));
    if let Err(e) = done {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Seal `input` to the recipients into the file `out`.
///
/// # Errors
///
/// No recipients, I/O or a crypto error; `out` is not left behind.
pub fn seal_file(recipients: &[Recipient], input: impl Read, out: &Path) -> Result<(), Error> {
    atomic(out, |f| {
        backup::seal_stream(recipients, backup::DEFAULT_CHUNK_LOG2, input, f).map_err(Into::into)
    })
}

/// What a failed opening means to a person: the key the papers make is not
/// one the file was sealed to, or the file is damaged.
fn opened(e: kuipa_enroll::Error) -> Error {
    match e {
        kuipa_enroll::Error::WrongRecipient => {
            "the passphrase or a paper is wrong, or this backup was sealed to another recovery key"
                .into()
        }
        kuipa_enroll::Error::BadResponse => {
            "the backup is damaged or has been altered: a part of it does not authenticate".into()
        }
        e => e.into(),
    }
}

/// Open a sealed backup with the recovery key into the file `out`.
///
/// # Errors
///
/// A container that is not one, one the key is not a recipient of, or one
/// that does not authenticate; `out` is not left behind.
pub fn open_file(key: &ExchangeKeyPair, input: impl Read, out: &Path) -> Result<(), Error> {
    atomic(out, |f| backup::open_stream(key, input, f).map_err(opened))
}

/// Open a sealed backup into `out`, which cannot be taken back (a pipe):
/// what was written before a failure is the caller's to discard.
///
/// # Errors
///
/// As [`open_file`].
pub fn open_stream(key: &ExchangeKeyPair, input: impl Read, out: impl Write) -> Result<(), Error> {
    backup::open_stream(key, input, out).map_err(opened)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(set: &NewSet, which: &[usize]) -> Vec<String> {
        which.iter().map(|&i| set.pages[i].clone()).collect()
    }

    #[test]
    fn papers_recover_the_key_and_seal_opens_with_it() {
        let set = create_key("EXAMPLE.TEST", b"six honest words to open the papers", 2, 3).unwrap();
        let file = RecipientFile::read_back(&set.file);
        let dir = std::env::temp_dir().join(format!("kuipa-backup-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let sealed = dir.join("b.kuipa");
        let data = vec![7u8; 200_000];
        seal_file(&[file.recipient().unwrap()], &data[..], &sealed).unwrap();
        assert!(!part(&sealed).exists());

        let phrase = b"six honest words to open the papers";
        assert!(check(&words(&set, &[0, 2]), phrase, &file).is_ok());
        assert!(
            check(
                &words(&set, &[0, 2]),
                b"five dishonest words, honest",
                &file
            )
            .is_err()
        );
        let (pair, _) = recover_key(&words(&set, &[1, 2]), phrase).unwrap();
        let out = dir.join("b.tar");
        open_file(&pair, fs::File::open(&sealed).unwrap(), &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), data);

        // A damaged container leaves no output file.
        let mut bad = fs::read(&sealed).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        fs::write(&sealed, bad).unwrap();
        let out2 = dir.join("c.tar");
        assert!(open_file(&pair, fs::File::open(&sealed).unwrap(), &out2).is_err());
        assert!(!out2.exists() && !part(&out2).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    impl RecipientFile {
        /// Through the JSON a host keeps, as `ipa-backup` reads it.
        fn read_back(file: &Self) -> Self {
            serde_json::from_slice(&serde_json::to_vec(file).unwrap()).unwrap()
        }
    }
}
