//! Voucher issuing (§9), with `ml-dsa-blind`:
//!
//! * the **issuer** holds the voucher key and a quota, and signs blinded
//!   requests ([`sign`]): it never sees realm, host or host group, and the
//!   quota counts exactly the vouchers that can exist (one-more
//!   unforgeability);
//! * the **provisioner** knows what the voucher allows, blinds it
//!   ([`request`]), keeps the [`State`], and unblinds the issuer's answer
//!   into the voucher ([`finish`]);
//! * the **host** joins with the voucher (`kuipa enroll --voucher-file`),
//!   with the ephemeral key it is bound to if it is bound ([`ephemeral`]).
//!
//! Requests and responses travel as base64url text, so any channel will do.

use std::fs::OpenOptions;
use std::io::Seek;
use std::path::Path;

use kuipa_enroll::voucher::{self, Claims, SIGN_CONTEXT, Voucher};
use ml_dsa_blind::{BlindRequest, BlindResponse, Context, ParameterSet, Requester};
use native_ossl::util::SecretBuf;
use serde::{Deserialize, Serialize};
use tang_pqc::{ExchangeKeyPair, SignatureAlg, VerifyingKey, b64};

use crate::paths::{Error, write_file};

fn parameter_set(alg: SignatureAlg) -> ParameterSet {
    match alg {
        SignatureAlg::MlDsa44 => ParameterSet::MlDsa44,
        SignatureAlg::MlDsa65 => ParameterSet::MlDsa65,
        SignatureAlg::MlDsa87 => ParameterSet::MlDsa87,
    }
}

fn requester(public: &VerifyingKey) -> Result<Requester, Error> {
    let key =
        ml_dsa_blind::VerifyingKey::from_bytes(parameter_set(public.alg()), public.as_bytes())?;
    Ok(Requester::with_context(key, Context::new(SIGN_CONTEXT)?))
}

/// Generate a voucher key: write the private key (PKCS#8 PEM, mode 0600)
/// to `key` and return the public JWK for `kuipad add-voucher-key`.
///
/// # Errors
///
/// An existing `key`, a parameter set the system policy disables, or I/O.
pub fn keygen(key: &Path, alg: SignatureAlg) -> Result<String, Error> {
    if key.exists() {
        return Err(format!("{} exists", key.display()).into());
    }
    let sk = ml_dsa_blind::SigningKey::generate(parameter_set(alg))?;
    write_file(key, &sk.to_pem()?, 0o600)?;
    Ok(VerifyingKey::from_bytes(alg, sk.verifying_key().as_bytes())?.to_jwk_json())
}

/// The issuer's count.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quota {
    /// Vouchers that may be issued in all.
    pub limit: u64,
    /// Vouchers issued so far.
    pub issued: u64,
}

/// Set the quota in `path` to `limit`, keeping the count.
///
/// # Errors
///
/// I/O or a malformed file.
pub fn set_quota(path: &Path, limit: u64) -> Result<Quota, Error> {
    let mut guard = quota_lock(path)?;
    let quota = Quota {
        limit,
        ..read_quota(&mut guard)?
    };
    guard.store(&quota)?;
    Ok(quota)
}

/// The issuer's exclusive lock on the quota file, held across a
/// read-modify-write: two `sign` processes running at once must not both
/// pass the quota check on the same count.  The count is written back
/// through the locked file itself, in place — replacing the file (an
/// atomic rename) would put a new, unlocked inode at the path and free
/// the lock for a second signer.
#[derive(Debug)]
struct QuotaGuard {
    file: std::fs::File,
}

impl QuotaGuard {
    /// Write `quota` back through the locked file.
    ///
    /// # Errors
    ///
    /// Serialisation or I/O.
    fn store(&mut self, quota: &Quota) -> Result<(), Error> {
        use std::io::Write as _;
        self.file.set_len(0)?;
        self.file.seek(std::io::SeekFrom::Start(0))?;
        self.file
            .write_all(serde_json::to_string(quota)?.as_bytes())?;
        self.file.sync_all()?;
        Ok(())
    }
}

impl Drop for QuotaGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Take the issuer's exclusive lock on the quota file at `path`.  The
/// lock is held until the returned guard drops.
///
/// # Errors
///
/// I/O, or the quota file cannot be created or locked.
fn quota_lock(path: &Path) -> Result<QuotaGuard, Error> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock()
        .map_err(|e| format!("cannot lock {}: {e}", path.display()))?;
    Ok(QuotaGuard { file })
}

/// Sign one blinded `request` (base64url) with the voucher key in `key`,
/// counting it against the quota in `quota` first.  Returns the response
/// (base64url).
///
/// # Errors
///
/// An exhausted quota, a malformed request, or I/O.
pub fn sign(key: &Path, quota: &Path, request: &str) -> Result<String, Error> {
    let mut guard = quota_lock(quota)?;
    let request = BlindRequest::from_bytes(&b64::decode(request.trim())?)?;
    let sk = ml_dsa_blind::SigningKey::from_pem(&std::fs::read(key)?)?;
    let mut q = read_quota(&mut guard)?;
    if q.issued >= q.limit {
        return Err(format!("quota exhausted ({} of {} issued)", q.issued, q.limit).into());
    }
    // Counted before signing: a crash loses a voucher, never the count.
    q.issued += 1;
    guard.store(&q)?;
    let response = sk.blind_sign(&request)?;
    tracing::info!("signed voucher {} of {}", q.issued, q.limit);
    Ok(b64::encode(response.as_bytes()))
}

/// Read the quota through the locked file.  An empty file (freshly
/// created, or a crash between creation and the first store) counts as
/// nothing issued.
///
/// # Errors
///
/// I/O or a malformed file.
fn read_quota(guard: &mut QuotaGuard) -> Result<Quota, Error> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    guard.file.seek(std::io::SeekFrom::Start(0))?;
    guard.file.read_to_end(&mut buf)?;
    if buf.is_empty() {
        return Ok(Quota {
            limit: 0,
            issued: 0,
        });
    }
    Ok(serde_json::from_slice(&buf)?)
}

/// What the provisioner keeps between [`request`] and [`finish`]: the
/// claims, the voucher key and the secret blinding salt.
#[derive(Serialize, Deserialize)]
pub struct State {
    key: String,
    realm: String,
    fqdn: String,
    hostgroup: String,
    not_before: u64,
    not_after: u64,
    lease: u64,
    binding: String,
    salt: String,
}

impl State {
    fn claims(&self) -> Result<Claims, Error> {
        let binding = b64::decode(&self.binding)?;
        if !binding.is_empty() && !voucher::is_binding_len(binding.len()) {
            return Err("bad binding in the voucher state".into());
        }
        Ok(Claims {
            realm: self.realm.clone(),
            fqdn: self.fqdn.clone(),
            hostgroup: self.hostgroup.clone(),
            not_before: self.not_before,
            not_after: self.not_after,
            lease: self.lease,
            binding,
        })
    }
}

/// Blind `claims` for the voucher key `public` (its JWK): write the state
/// to `state` (mode 0600) and return the request (base64url) for the
/// issuer.
///
/// # Errors
///
/// A bad key, or I/O.
pub fn request(public: &[u8], claims: &Claims, state: &Path) -> Result<String, Error> {
    let key = VerifyingKey::from_jwk_json(public)?;
    let (request, pending) = requester(&key)?.blind(&claims.message())?;
    let s = State {
        key: key.to_jwk_json(),
        realm: claims.realm.clone(),
        fqdn: claims.fqdn.clone(),
        hostgroup: claims.hostgroup.clone(),
        not_before: claims.not_before,
        not_after: claims.not_after,
        lease: claims.lease,
        binding: b64::encode(&claims.binding),
        salt: b64::encode(pending.salt()),
    };
    let json = SecretBuf::new(serde_json::to_vec(&s)?);
    write_file(state, json.as_ref(), 0o600)?;
    Ok(b64::encode(request.as_bytes()))
}

/// Unblind the issuer's `response` (base64url) for the request saved in
/// `state` into the voucher.  The response is checked first.
///
/// # Errors
///
/// A response that is not a valid signature on the request, or I/O.
pub fn finish(state: &Path, response: &str) -> Result<Voucher, Error> {
    let s: State = serde_json::from_slice(SecretBuf::new(std::fs::read(state)?).as_ref())?;
    let key = VerifyingKey::from_jwk_json(s.key.as_bytes())?;
    let claims = s.claims()?;
    let salt = SecretBuf::new(b64::decode(&s.salt)?);
    let pending = requester(&key)?.resume(&claims.message(), salt.as_ref())?;
    let signature = pending.finalize(&BlindResponse::from(b64::decode(response.trim())?))?;
    Ok(Voucher::new(
        key.thumbprint(),
        claims,
        &signature.to_bytes(),
    )?)
}

/// Make the ephemeral key a host will join with: write it (mode 0600) to
/// `path` and return its binding, for a voucher bound to it.
///
/// # Errors
///
/// An existing `path`, or I/O.
pub fn ephemeral(path: &Path) -> Result<Vec<u8>, Error> {
    if path.exists() {
        return Err(format!("{} exists", path.display()).into());
    }
    let key = ExchangeKeyPair::generate_preferred()?;
    write_file(path, key.to_jwk()?.as_ref(), 0o600)?;
    Ok(voucher::binding(key.public().as_bytes())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_signs_cannot_exceed_the_quota() {
        // The issuer's count must be exactly the vouchers that can exist
        // (one-more unforgeability): two signers racing on the same quota
        // file must serialise, not both pass the check on one count.
        let dir = std::env::temp_dir().join(format!("kuipa-quota-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let quota = dir.join("quota.json");
        set_quota(&quota, 4).unwrap();

        let key = dir.join("key.pem");
        let sk = ml_dsa_blind::SigningKey::generate(ParameterSet::MlDsa44).unwrap();
        std::fs::write(&key, sk.to_pem().unwrap()).unwrap();
        let public = VerifyingKey::from_bytes(SignatureAlg::MlDsa44, sk.verifying_key().as_bytes())
            .unwrap()
            .to_jwk_json();
        // One blinded request every signer uses.
        let claims = Claims {
            realm: "EXAMPLE.TEST".into(),
            fqdn: "web.example.test".into(),
            hostgroup: String::new(),
            not_before: 0,
            not_after: 1,
            lease: 0,
            binding: Vec::new(),
        };
        let request = request(public.as_bytes(), &claims, &dir.join("state.json")).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        for _ in 0..8 {
            let (tx, request, quota, key) =
                (tx.clone(), request.clone(), quota.clone(), key.clone());
            std::thread::spawn(move || {
                let signed = sign(&key, &quota, &request).is_ok();
                tx.send(signed).unwrap();
            });
        }
        drop(tx);
        let ok: usize = rx.into_iter().filter(|s| *s).count();
        assert_eq!(ok, 4, "exactly the quota's worth of vouchers");
        let final_ = read_quota(&mut quota_lock(&quota).unwrap()).unwrap();
        assert_eq!(final_.issued, 4, "the count agrees with reality");
    }
}
