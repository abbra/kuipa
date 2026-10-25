//! An in-memory [`Directory`] standing in for FreeIPA, sized by a profile.
//!
//! GSS tokens are modelled as `principal ‖ 0 ‖ channel binding`, so a token
//! only verifies against the binding it was made for, exactly as the
//! end-to-end tests fake it.  No LDAP, no GSS-API: this runs on macOS, where
//! neither is available.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use kuipa_enroll::escrow::{BindingHash, Kind, RegisterParams};
use kuipa_enroll::join::KerberosBinding;
use kuipa_enroll::keytab::{Enctype, Keytab, KeytabEntry, Principal};
use kuipa_enroll::server::{Directory, DirectoryError, Staged};
use native_ossl::util::SecretBuf;

use crate::prng::SplitMix64;

/// The realm fixture principals live in.
pub const REALM: &str = "EXAMPLE.TEST";
/// The host a bench enrolls.
pub const HOST: &str = "web1.example.test";
/// The administrator whose ticket authorizes joins.
pub const ADMIN: &str = "admin@EXAMPLE.TEST";

/// A stand-in for the GSS-API pseudo-random output both ends share.
///
/// # Panics
///
/// Never: the derived buffer is always 32 bytes.
#[must_use]
pub fn fake_binding(principal: &str, cb: &[u8; 32]) -> KerberosBinding {
    let mut b = *cb;
    for (i, c) in principal.bytes().enumerate() {
        b[i % 32] ^= c;
    }
    KerberosBinding::new(&b).expect("32-byte binding")
}

/// A fake GSS token for `principal`, bound to `cb`.
#[must_use]
pub fn gss_token(principal: &str, cb: &[u8; 32]) -> Vec<u8> {
    let mut t = principal.as_bytes().to_vec();
    t.push(0);
    t.extend_from_slice(cb);
    t
}

/// A directory that answers from memory: OTPs, tickets, escrow bindings, CA
/// certificates.
pub struct BenchDirectory {
    /// OTPs by host, consumed on first use.
    otps: RefCell<HashMap<String, Vec<u8>>>,
    kvno: RefCell<HashMap<String, u32>>,
    admins: HashSet<String>,
    escrow: RefCell<HashMap<String, Vec<BindingHash>>>,
    disabled: RefCell<HashSet<String>>,
    staged: RefCell<HashMap<String, Staged>>,
    cas: Vec<Vec<u8>>,
    servers: Vec<String>,
    /// Keytab entries per issued principal.
    entries: usize,
    /// Deterministic source for keytab keys.
    rng: RefCell<SplitMix64>,
}

impl Default for BenchDirectory {
    fn default() -> Self {
        Self::new(1, vec![Vec::new()], Vec::new())
    }
}

impl BenchDirectory {
    /// A directory issuing `entries`-entry keytabs, answering with `cas` and
    /// listing `servers`.
    #[must_use]
    pub fn new(entries: usize, cas: Vec<Vec<u8>>, servers: Vec<String>) -> Self {
        Self {
            otps: RefCell::new(HashMap::new()),
            kvno: RefCell::new(HashMap::new()),
            admins: HashSet::from([ADMIN.to_string()]),
            escrow: RefCell::new(HashMap::new()),
            disabled: RefCell::new(HashSet::new()),
            staged: RefCell::new(HashMap::new()),
            cas,
            servers,
            entries: entries.max(1),
            rng: RefCell::new(SplitMix64::new(0xb0c4)),
        }
    }

    /// Publish `otp` for `fqdn`, usable once.
    pub fn set_otp(&self, fqdn: &str, otp: &[u8]) {
        self.otps.borrow_mut().insert(fqdn.to_owned(), otp.to_vec());
    }

    /// Stop `principal` from unsealing anything.
    pub fn disable(&self, principal: &Principal) {
        self.disabled.borrow_mut().insert(principal.to_string());
    }

    fn accept(token: &[u8], cb: &[u8; 32]) -> Result<String, DirectoryError> {
        let (name, rest) = token.split_at(token.iter().position(|&b| b == 0).ok_or("bad token")?);
        if rest[1..] != *cb {
            return Err("channel binding mismatch".into());
        }
        Ok(String::from_utf8(name.to_vec())?)
    }

    fn new_keys(&self, fqdn: &str) -> Keytab {
        let kvno = {
            let mut k = self.kvno.borrow_mut();
            let v = k.entry(fqdn.to_owned()).or_insert(0);
            *v += 1;
            *v
        };
        let entries = (0..self.entries)
            .map(|i| KeytabEntry {
                kvno,
                enctype: Enctype::DEFAULT[i % Enctype::DEFAULT.len()],
                key: SecretBuf::from_slice(&self.rng.borrow_mut().bytes(32)),
                timestamp: 1,
            })
            .collect();
        Keytab::new(Principal::host(fqdn, REALM), entries)
    }
}

impl Directory for BenchDirectory {
    fn join_with_otp(
        &self,
        fqdn: &str,
        otp: &[u8],
        _: &[Enctype],
    ) -> Result<Keytab, DirectoryError> {
        let stored = self.otps.borrow_mut().remove(fqdn);
        match stored {
            Some(expected) if expected == otp => Ok(self.new_keys(fqdn)),
            Some(expected) => {
                self.otps.borrow_mut().insert(fqdn.to_owned(), expected);
                Err("wrong OTP".into())
            }
            None => Err("no OTP".into()),
        }
    }

    fn join_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        _: &[Enctype],
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let who = Self::accept(token, cb)?;
        if !self.admins.contains(&who) {
            return Err("not allowed to enroll".into());
        }
        Ok((self.new_keys(fqdn), fake_binding(&who, cb)))
    }

    fn rekey_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        _: &[Enctype],
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let who = Self::accept(token, cb)?;
        if who != Principal::host(fqdn, REALM).to_string() {
            return Err("only the host may rekey itself".into());
        }
        self.staged.borrow_mut().remove(fqdn);
        Ok((self.new_keys(fqdn), fake_binding(&who, cb)))
    }

    fn stage_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        _: &[Enctype],
        staged: &Staged,
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let who = Self::accept(token, cb)?;
        if !self.admins.contains(&who) {
            return Err("not allowed to stage".into());
        }
        self.staged
            .borrow_mut()
            .insert(fqdn.to_owned(), staged.clone());
        Ok((self.new_keys(fqdn), fake_binding(&who, cb)))
    }

    fn register_escrow(
        &self,
        principal: &Principal,
        bindings: &[BindingHash],
    ) -> Result<(), DirectoryError> {
        self.escrow
            .borrow_mut()
            .insert(principal.to_string(), bindings.to_vec());
        Ok(())
    }

    fn escrow_allowed(
        &self,
        principal: &Principal,
        kind: Kind,
        binding: &BindingHash,
    ) -> Result<bool, DirectoryError> {
        let p = principal.to_string();
        Ok(!self.disabled.borrow().contains(&p)
            && kind == Kind::Keytab
            && self
                .escrow
                .borrow()
                .get(&p)
                .is_some_and(|b| b.contains(binding)))
    }

    fn register_with_gss(
        &self,
        params: &RegisterParams,
        bindings: &[BindingHash],
        token: &[u8],
        cb: &[u8; 32],
    ) -> Result<KerberosBinding, DirectoryError> {
        let who = Self::accept(token, cb)?;
        if who != params.principal.to_string() {
            return Err("only a principal may register for itself".into());
        }
        self.escrow
            .borrow_mut()
            .insert(who.clone(), bindings.to_vec());
        Ok(fake_binding(&who, cb))
    }

    fn ca_certificates(&self) -> Result<Vec<Vec<u8>>, DirectoryError> {
        Ok(self.cas.clone())
    }

    fn servers(&self) -> Result<Vec<String>, DirectoryError> {
        Ok(self.servers.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{BenchDirectory, BindingHash, REALM, gss_token};
    use kuipa_enroll::keytab::Principal;
    use kuipa_enroll::server::Directory;

    #[test]
    fn otp_is_one_time() {
        let dir = BenchDirectory::new(1, vec![Vec::new()], Vec::new());
        dir.set_otp("web1.example.test", b"otp");
        assert!(dir.join_with_otp("web1.example.test", b"otp", &[]).is_ok());
        assert!(dir.join_with_otp("web1.example.test", b"otp", &[]).is_err());
    }

    #[test]
    fn gss_token_needs_its_binding() {
        let dir = BenchDirectory::new(1, vec![Vec::new()], Vec::new());
        let cb = [3u8; 32];
        let token = gss_token(super::ADMIN, &cb);
        assert!(
            dir.join_with_gss("h.example.test", &token, &cb, &[])
                .is_ok()
        );
        assert!(
            dir.join_with_gss("h.example.test", &token, &[9u8; 32], &[])
                .is_err()
        );
    }

    #[test]
    fn keytab_has_profile_entries() {
        let dir = BenchDirectory::new(4, vec![Vec::new()], Vec::new());
        dir.set_otp("web1.example.test", b"otp");
        let kt = dir.join_with_otp("web1.example.test", b"otp", &[]).unwrap();
        assert_eq!(kt.entries().len(), 4);
        assert_eq!(kt.principal(), &Principal::host("web1.example.test", REALM));
    }

    #[test]
    fn escrow_needs_registration() {
        let dir = BenchDirectory::new(1, vec![Vec::new()], Vec::new());
        let p = Principal::host("web1.example.test", REALM);
        let mut b = [1u8; 32];
        for (i, c) in p.to_string().bytes().enumerate() {
            b[i % 32] ^= c;
        }
        let binding = BindingHash::from_slice(&b).expect("binding");
        assert!(
            !dir.escrow_allowed(&p, kuipa_enroll::escrow::Kind::Keytab, &binding)
                .unwrap()
        );
        dir.register_escrow(&p, &[binding]).unwrap();
        assert!(
            dir.escrow_allowed(&p, kuipa_enroll::escrow::Kind::Keytab, &binding)
                .unwrap()
        );
        dir.disable(&p);
        assert!(
            !dir.escrow_allowed(&p, kuipa_enroll::escrow::Kind::Keytab, &binding)
                .unwrap()
        );
    }
}
