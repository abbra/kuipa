//! A [`Directory`] that authenticates for real against a test [`Realm`]:
//! GSS-API tokens are accepted with the daemon's keytab, passwords are
//! checked by `kinit`, and keys come from the KDC (`kadmin.local ktadd`,
//! standing in for `KEYTAB_GET`).  Only the LDAP-side state (OTPs, escrow
//! registrations, staging) is kept in memory.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use kuipa_enroll::escrow::{Kind, RegisterParams, VaultId};
use kuipa_enroll::join::{KERBEROS_BINDING_LEN, KerberosBinding, kerberos_prf_input};
use kuipa_enroll::keytab::{Enctype, Keytab, Principal};
use kuipa_enroll::realm::TrustedRealm;
use kuipa_enroll::server::{Accepted, Directory, DirectoryError, Staged};
use kuipa_enroll::vault::Vault;
use kuipa_gssapi::{AcceptStep, GssServerCred};

use super::kdc::Realm;

/// The realm's directory, shared by all its servers.
pub struct KdcDirectory {
    pub realm: Arc<Realm>,
    /// Who may enroll and stage hosts with a ticket or a password.
    pub admins: HashSet<String>,
    pub otps: Mutex<HashMap<String, Vec<u8>>>,
    pub escrow: Mutex<HashMap<String, Vec<kuipa_enroll::escrow::BindingHash>>>,
    /// Escrow bindings of sealed files, by principal (§7.5).
    pub escrow_files: Mutex<HashMap<String, Vec<kuipa_enroll::escrow::BindingHash>>>,
    pub staged: Mutex<HashSet<String>>,
    pub servers: Vec<String>,
    /// Spent voucher salts.
    pub spent: Mutex<HashSet<[u8; 32]>>,
    /// Host groups and their members, as voucher joins add them.
    pub hostgroups: Mutex<HashMap<String, Vec<String>>>,
    /// Trust invitations (secret hash → not after).
    pub invitations: Mutex<HashMap<[u8; 48], u64>>,
    /// Recorded trusted realms.
    pub trusts: Mutex<Vec<TrustedRealm>>,
    /// User vaults.
    pub vaults: Mutex<HashMap<VaultId, Vault>>,
    /// Locked principals (`nsAccountLock`).
    pub locked: Mutex<HashSet<String>>,
    /// Releases per vault and server.
    pub unlocks: Mutex<HashMap<(VaultId, String), u64>>,
    /// Servers' published escrow keys.
    pub escrow_keys: Mutex<Vec<(String, tang_pqc::ExchangeKey)>>,
    /// The server list (`cn=masters`) for the keys operation's policy.
    pub masters: Mutex<Vec<String>>,
    /// The masters with the CA role (`cn=CA` under their entry).
    pub ca_masters: Mutex<Vec<String>>,
    /// The `keys` operation's secrets, by `namespace/nickname` (§18.2):
    /// the playground stands in for the handler executables.
    pub key_secrets: Mutex<std::collections::BTreeMap<(u8, String), Vec<u8>>>,
    /// The realm's vault limits.
    pub limits: Mutex<kuipa_enroll::vault::Limits>,
    /// The realm's signing policy (`DESIGN-sign.md`).
    pub sign_policy: Mutex<kuipa_enroll::sign::SignPolicy>,
    /// User groups by principal, as `memberOf` lists them (host groups
    /// come from `hostgroups`).
    pub groups: Mutex<HashMap<String, Vec<String>>>,
    /// Acceptor credentials, one per server (`ipa-ku@<server>`).
    creds: Vec<GssServerCred>,
}

impl KdcDirectory {
    /// Create the `ipa-ku/<server>` principals and their acceptor
    /// credentials.
    pub fn new(realm: Arc<Realm>, servers: &[&str], admins: &[&str]) -> Self {
        let creds = servers
            .iter()
            .map(|s| {
                let kt = realm.dir.join(format!("kuipa-{s}.keytab"));
                std::fs::write(&kt, realm.new_keys(&format!("ipa-ku/{s}@{}", realm.realm)))
                    .unwrap();
                GssServerCred::acquire(&format!("ipa-ku@{s}"), kt.to_str().unwrap()).unwrap()
            })
            .collect();
        Self {
            realm,
            admins: admins.iter().map(|a| (*a).to_owned()).collect(),
            otps: Mutex::new(HashMap::new()),
            escrow: Mutex::new(HashMap::new()),
            escrow_files: Mutex::new(HashMap::new()),
            staged: Mutex::new(HashSet::new()),
            servers: servers.iter().map(|s| (*s).to_owned()).collect(),
            spent: Mutex::new(HashSet::new()),
            hostgroups: Mutex::new(HashMap::new()),
            invitations: Mutex::new(HashMap::new()),
            trusts: Mutex::new(Vec::new()),
            vaults: Mutex::new(HashMap::new()),
            locked: Mutex::new(HashSet::new()),
            unlocks: Mutex::new(HashMap::new()),
            escrow_keys: Mutex::new(Vec::new()),
            masters: Mutex::new(servers.iter().map(|s| (*s).to_owned()).collect()),
            ca_masters: Mutex::new(Vec::new()),
            key_secrets: Mutex::new(std::collections::BTreeMap::new()),
            limits: Mutex::new(kuipa_enroll::vault::Limits::default()),
            sign_policy: Mutex::new(kuipa_enroll::sign::SignPolicy::default()),
            groups: Mutex::new(HashMap::new()),
            creds,
        }
    }

    /// Accept a token for any of the servers (the request does not say
    /// which one it was made for; a real daemon has a single credential).
    fn accept(&self, token: &[u8], cb: &[u8; 32]) -> Result<String, DirectoryError> {
        let mut last = None;
        for cred in &self.creds {
            match kuipa_gssapi::accept_token(cred, token, Some(cb)) {
                Ok(AcceptStep::Complete { principal, .. }) => return Ok(principal),
                Ok(AcceptStep::Continue { .. }) => return Err("more than one token".into()),
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(|| "no acceptor".into(), Into::into))
    }

    /// As [`Self::accept`], with the binding the client derives too.
    fn accept_bound(
        &self,
        token: &[u8],
        cb: &[u8; 32],
    ) -> Result<(String, KerberosBinding), DirectoryError> {
        let mut last = None;
        for cred in &self.creds {
            match kuipa_gssapi::accept_bound(
                cred,
                token,
                cb,
                &kerberos_prf_input(cb),
                KERBEROS_BINDING_LEN,
            ) {
                Ok((principal, derived)) => {
                    return Ok((principal, KerberosBinding::new(&derived)?));
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.map_or_else(|| "no acceptor".into(), Into::into))
    }

    fn total(&self, id: &VaultId) -> u64 {
        self.unlocks
            .lock()
            .unwrap()
            .iter()
            .filter(|((v, _), _)| v == id)
            .map(|(_, n)| n)
            .sum()
    }

    fn keys(&self, fqdn: &str) -> Result<Keytab, DirectoryError> {
        let principal = Principal::host(fqdn, &self.realm.realm).to_string();
        Ok(Keytab::from_mit(&self.realm.new_keys(&principal))?)
    }

    fn admin(&self, principal: &str) -> Result<(), DirectoryError> {
        if self.admins.contains(principal) {
            Ok(())
        } else {
            Err(format!("{principal} may not enroll or stage hosts").into())
        }
    }
}

impl Directory for KdcDirectory {
    fn join_with_otp(
        &self,
        fqdn: &str,
        otp: &[u8],
        _: &[Enctype],
    ) -> Result<Keytab, DirectoryError> {
        let ok = self
            .otps
            .lock()
            .unwrap()
            .remove(fqdn)
            .is_some_and(|o| o == otp);
        if !ok {
            return Err("bad or used OTP".into());
        }
        self.keys(fqdn)
    }

    fn join_with_voucher(
        &self,
        fqdn: &str,
        hostgroup: &str,
        salt: &[u8; 32],
        _: &[Enctype],
    ) -> Result<Keytab, DirectoryError> {
        if self.realm.has(&format!("host/{fqdn}@{}", self.realm.realm)) {
            return Err("the host exists".into());
        }
        if !self.spent.lock().unwrap().insert(*salt) {
            return Err("spent voucher".into());
        }
        if !hostgroup.is_empty() {
            self.hostgroups
                .lock()
                .unwrap()
                .entry(hostgroup.to_owned())
                .or_default()
                .push(fqdn.to_owned());
        }
        self.keys(fqdn)
    }

    fn join_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        _: &[Enctype],
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let (caller, binding) = self.accept_bound(token, cb)?;
        self.admin(&caller)?;
        Ok((self.keys(fqdn)?, binding))
    }

    fn rekey_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        _: &[Enctype],
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let host = Principal::host(fqdn, &self.realm.realm).to_string();
        let (caller, binding) = self.accept_bound(token, cb)?;
        if caller != host {
            return Err("only the host may rekey itself".into());
        }
        if self.staged.lock().unwrap().remove(fqdn) {
            eprintln!("kuipad: first contact: {host} unstaged");
        }
        Ok((self.keys(fqdn)?, binding))
    }

    fn stage_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        _: &[Enctype],
        _: &Staged,
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let (caller, binding) = self.accept_bound(token, cb)?;
        self.admin(&caller)?;
        self.staged.lock().unwrap().insert(fqdn.into());
        Ok((self.keys(fqdn)?, binding))
    }

    fn register_escrow(
        &self,
        principal: &Principal,
        bindings: &[kuipa_enroll::escrow::BindingHash],
    ) -> Result<(), DirectoryError> {
        self.escrow
            .lock()
            .unwrap()
            .insert(principal.to_string(), bindings.to_vec());
        Ok(())
    }

    fn escrow_allowed(
        &self,
        principal: &Principal,
        kind: Kind,
        binding: &kuipa_enroll::escrow::BindingHash,
    ) -> Result<bool, DirectoryError> {
        let set = match kind {
            Kind::Keytab => &self.escrow,
            Kind::File => &self.escrow_files,
        };
        Ok(set
            .lock()
            .unwrap()
            .get(&principal.to_string())
            .is_some_and(|b| b.contains(binding)))
    }

    fn register_with_gss(
        &self,
        params: &RegisterParams,
        bindings: &[kuipa_enroll::escrow::BindingHash],
        token: &[u8],
        cb: &[u8; 32],
    ) -> Result<KerberosBinding, DirectoryError> {
        let (caller, binding) = self.accept_bound(token, cb)?;
        let principal = params.principal.to_string();
        if caller != principal {
            return Err(format!("{caller} may not register for {principal}").into());
        }
        match params.kind {
            Kind::Keytab => {
                self.escrow
                    .lock()
                    .unwrap()
                    .insert(principal, bindings.to_vec());
            }
            Kind::File => {
                let mut files = self.escrow_files.lock().unwrap();
                let set = files.entry(principal).or_default();
                set.retain(|b| !params.retire.contains(b));
                set.extend_from_slice(bindings);
            }
        }
        Ok(binding)
    }

    fn ca_certificates(&self) -> Result<Vec<Vec<u8>>, DirectoryError> {
        Ok(vec![self.realm.chain.ca_der.clone()])
    }

    fn servers(&self) -> Result<Vec<String>, DirectoryError> {
        Ok(self.servers.clone())
    }

    fn accept_peer(&self, token: &[u8], cb: &[u8; 32]) -> Result<String, DirectoryError> {
        self.accept(token, cb)
    }

    fn accept_user(&self, token: &[u8], cb: &[u8; 32]) -> Result<Accepted, DirectoryError> {
        let (principal, binding) = self.accept_bound(token, cb)?;
        Ok(Accepted {
            principal,
            binding,
            // The PAC's delegation info is not read yet.
            transited: None,
        })
    }

    fn fetch_key(
        &self,
        principal: &kuipa_enroll::keytab::Principal,
        fetch: &kuipa_enroll::keys::KeysFetch,
    ) -> Result<Vec<u8>, DirectoryError> {
        // The policy of §18.2, against the modelled cn=masters lists.
        let policy = kuipa_enroll::keys::KeysPolicy {
            servers: self.masters.lock().unwrap().clone(),
            ca_servers: self.ca_masters.lock().unwrap().clone(),
        };
        if let Some(reason) = policy.check(principal, fetch.namespace) {
            eprintln!("playground keys: DENIED {principal}: {reason}");
            return Err(reason.into());
        }
        self.key_secrets
            .lock()
            .unwrap()
            .get(&(fetch.namespace.id(), fetch.nickname.clone()))
            .cloned()
            .ok_or_else(|| {
                format!(
                    "no such key: {}/{}",
                    fetch.namespace.label(),
                    fetch.nickname
                )
                .into()
            })
    }

    fn vault_add(&self, vault: &Vault) -> Result<(), DirectoryError> {
        self.vaults.lock().unwrap().insert(vault.id, vault.clone());
        Ok(())
    }

    fn vault_get(&self, id: &VaultId) -> Result<Option<Vault>, DirectoryError> {
        Ok(self.vaults.lock().unwrap().get(id).cloned().map(|mut v| {
            v.unlocks = self.total(id);
            v
        }))
    }

    fn vault_limits(&self) -> Result<kuipa_enroll::vault::Limits, DirectoryError> {
        Ok(self.limits.lock().unwrap().clone())
    }

    fn sign_policy(&self) -> Result<kuipa_enroll::sign::SignPolicy, DirectoryError> {
        Ok(self.sign_policy.lock().unwrap().clone())
    }

    fn principal_groups(&self, principal: &Principal) -> Result<Vec<String>, DirectoryError> {
        let name = principal.to_string();
        let mut groups = self
            .groups
            .lock()
            .unwrap()
            .get(&name)
            .cloned()
            .unwrap_or_default();
        if let [service, fqdn] = principal.components()
            && service == "host"
        {
            groups.extend(
                self.hostgroups
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(_, members)| members.iter().any(|m| m == fqdn))
                    .map(|(g, _)| g.clone()),
            );
        }
        Ok(groups)
    }

    fn escrow_servers(&self) -> Result<Vec<(String, tang_pqc::ExchangeKey)>, DirectoryError> {
        Ok(self.escrow_keys.lock().unwrap().clone())
    }

    fn publish_escrow_key(
        &self,
        server: &str,
        key: &tang_pqc::ExchangeKey,
    ) -> Result<(), DirectoryError> {
        let mut keys = self.escrow_keys.lock().unwrap();
        keys.retain(|(s, _)| s != server);
        keys.push((server.to_owned(), key.clone()));
        Ok(())
    }

    fn vault_unlock(
        &self,
        id: &VaultId,
        server: &str,
        limit: Option<u64>,
    ) -> Result<bool, DirectoryError> {
        if limit.is_some_and(|l| self.total(id) >= l) {
            return Ok(false);
        }
        *self
            .unlocks
            .lock()
            .unwrap()
            .entry((*id, server.to_owned()))
            .or_default() += 1;
        Ok(true)
    }

    fn vault_update(&self, vault: &Vault) -> Result<(), DirectoryError> {
        self.vaults.lock().unwrap().insert(vault.id, vault.clone());
        Ok(())
    }

    fn vaults_of(&self, owner: &Principal) -> Result<Vec<Vault>, DirectoryError> {
        let owner = owner.to_string();
        let vaults: Vec<Vault> = self
            .vaults
            .lock()
            .unwrap()
            .values()
            .filter(|v| v.owner == owner)
            .cloned()
            .collect();
        Ok(vaults
            .into_iter()
            .map(|mut v| {
                v.unlocks = self.total(&v.id);
                v
            })
            .collect())
    }

    fn vaults_shared_with(
        &self,
        principal: &Principal,
        groups: &[String],
    ) -> Result<Vec<Vault>, DirectoryError> {
        let wanted = kuipa_enroll::vault::Members::matching_entries(principal, groups);
        let vaults: Vec<Vault> = self
            .vaults
            .lock()
            .unwrap()
            .values()
            .filter(|v| {
                v.managers
                    .entries()
                    .iter()
                    .chain(&v.members.entries())
                    .any(|e| wanted.contains(e))
            })
            .cloned()
            .collect();
        Ok(vaults
            .into_iter()
            .map(|mut v| {
                v.unlocks = self.total(&v.id);
                v
            })
            .collect())
    }

    fn principal_locked(&self, principal: &Principal) -> Result<bool, DirectoryError> {
        Ok(self.locked.lock().unwrap().contains(&principal.to_string()))
    }

    fn add_trust_invitation(&self, hash: &[u8; 48], not_after: u64) -> Result<(), DirectoryError> {
        self.invitations.lock().unwrap().insert(*hash, not_after);
        Ok(())
    }

    fn consume_trust_invitation(&self, hash: &[u8; 48]) -> Result<(), DirectoryError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match self.invitations.lock().unwrap().remove(hash) {
            Some(not_after) if not_after > now => Ok(()),
            _ => Err("unknown, used or expired trust invitation".into()),
        }
    }

    /// The cross-realm keys in this KDC, from the secret's text form, as
    /// `trust-add --trust_secret` would create them.
    fn record_trust(&self, partner: &TrustedRealm, secret: &[u8]) -> Result<(), DirectoryError> {
        let text =
            kuipa_enroll::trust::secret_text(&native_ossl::util::SecretBuf::from_slice(secret));
        self.realm
            .cross_realm(&partner.realm, std::str::from_utf8(text.as_ref())?);
        let mut trusts = self.trusts.lock().unwrap();
        trusts.retain(|t| t.realm != partner.realm);
        trusts.push(partner.clone());
        Ok(())
    }

    fn update_trust(&self, partner: &TrustedRealm) -> Result<(), DirectoryError> {
        let mut trusts = self.trusts.lock().unwrap();
        let t = trusts
            .iter_mut()
            .find(|t| t.realm == partner.realm)
            .ok_or("unknown trusted realm")?;
        *t = partner.clone();
        Ok(())
    }

    fn trusted_realms(&self) -> Result<Vec<TrustedRealm>, DirectoryError> {
        Ok(self.trusts.lock().unwrap().clone())
    }
}
