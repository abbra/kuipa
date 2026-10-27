//! A [`Directory`] that authenticates for real against a test [`Realm`]:
//! GSS-API tokens are accepted with the daemon's keytab, passwords are
//! checked by `kinit`, and keys come from the KDC (`kadmin.local ktadd`,
//! standing in for `KEYTAB_GET`).  Only the LDAP-side state (OTPs, escrow
//! registrations, staging) is kept in memory.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use kuipa_enroll::escrow::{Kind, RegisterParams, SealId};
use kuipa_enroll::join::{KERBEROS_BINDING_LEN, KerberosBinding, kerberos_prf_input};
use kuipa_enroll::keytab::{Enctype, Keytab, Principal};
use kuipa_enroll::realm::TrustedRealm;
use kuipa_enroll::seal::{Approval, ReleaseRequest, Seal};
use kuipa_enroll::server::{Accepted, Directory, DirectoryError, Staged};
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
    /// When each leased host's lease ends (`DESIGN-ci.md` §1), by FQDN.
    pub leases: Mutex<HashMap<String, u64>>,
    /// Host groups and their members, as voucher joins add them.
    pub hostgroups: Mutex<HashMap<String, Vec<String>>>,
    /// Trust invitations (secret hash → not after).
    pub invitations: Mutex<HashMap<[u8; 48], u64>>,
    /// Recorded trusted realms.
    pub trusts: Mutex<Vec<TrustedRealm>>,
    /// User seals.
    pub seals: Mutex<HashMap<SealId, Seal>>,
    /// Locked principals (`nsAccountLock`).
    pub locked: Mutex<HashSet<String>>,
    /// Releases per seal and server.
    pub unlocks: Mutex<HashMap<(SealId, String), u64>>,
    /// Servers' published escrow keys.
    pub escrow_keys: Mutex<Vec<(String, tang_pqc::ExchangeKey)>>,
    /// The server list (`cn=masters`) for the keys operation's policy.
    pub masters: Mutex<Vec<String>>,
    /// The masters with the CA role (`cn=CA` under their entry).
    pub ca_masters: Mutex<Vec<String>>,
    /// The `keys` operation's secrets, by `namespace/nickname` (§18.2):
    /// the playground stands in for the handler executables.
    pub key_secrets: Mutex<std::collections::BTreeMap<(u8, String), Vec<u8>>>,
    /// The realm's seal limits.
    pub limits: Mutex<kuipa_enroll::seal::Limits>,
    /// The realm's signing policy (`DESIGN-sign.md`).
    pub sign_policy: Mutex<kuipa_enroll::sign::SignPolicy>,
    /// User groups by principal, as `memberOf` lists them (host groups
    /// come from `hostgroups`).
    pub groups: Mutex<HashMap<String, Vec<String>>>,
    /// Release requests by seal and id (`DESIGN-approvals.md`).
    pub releases: Mutex<HashMap<(SealId, String), ReleaseRequest>>,
    /// Their uses, by seal, id and server.
    release_uses: Mutex<HashMap<(SealId, String, String), u64>>,
    /// Device keys kept under recovery codes, by holder.
    pub escrows: Mutex<HashMap<String, Vec<kuipa_enroll::seal::DeviceEscrow>>>,
    /// Deposits by seal and id (`DESIGN-recovery.md` §3).
    pub deposits: Mutex<HashMap<(SealId, String), kuipa_enroll::seal::Deposit>>,
    /// The realm's device-key recovery settings (`DESIGN-recovery.md` §4).
    pub recovery: Mutex<Option<kuipa_enroll::seal::RecoverySettings>>,
    /// IPA passkeys (`ipaPassKey` values) by principal.
    pub passkeys: Mutex<HashMap<String, Vec<String>>>,
    /// Whether the realm requires user verification (`ipa passkeyconfig`).
    pub passkey_uv: Mutex<bool>,
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
                std::fs::write(&kt, realm.new_keys(&format!("ipa-ku/{s}@{}", realm.name))).unwrap();
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
            leases: Mutex::new(HashMap::new()),
            hostgroups: Mutex::new(HashMap::new()),
            invitations: Mutex::new(HashMap::new()),
            trusts: Mutex::new(Vec::new()),
            seals: Mutex::new(HashMap::new()),
            locked: Mutex::new(HashSet::new()),
            unlocks: Mutex::new(HashMap::new()),
            escrow_keys: Mutex::new(Vec::new()),
            masters: Mutex::new(servers.iter().map(|s| (*s).to_owned()).collect()),
            ca_masters: Mutex::new(Vec::new()),
            key_secrets: Mutex::new(std::collections::BTreeMap::new()),
            limits: Mutex::new(kuipa_enroll::seal::Limits::default()),
            sign_policy: Mutex::new(kuipa_enroll::sign::SignPolicy::default()),
            groups: Mutex::new(HashMap::new()),
            releases: Mutex::new(HashMap::new()),
            release_uses: Mutex::new(HashMap::new()),
            escrows: Mutex::new(HashMap::new()),
            deposits: Mutex::new(HashMap::new()),
            recovery: Mutex::new(None),
            passkeys: Mutex::new(HashMap::new()),
            passkey_uv: Mutex::new(true),
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

    fn total(&self, id: &SealId) -> u64 {
        self.unlocks
            .lock()
            .unwrap()
            .iter()
            .filter(|((v, _), _)| v == id)
            .map(|(_, n)| n)
            .sum()
    }

    fn keys(&self, fqdn: &str) -> Result<Keytab, DirectoryError> {
        let principal = Principal::host(fqdn, &self.realm.name).to_string();
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
        lease: Option<u64>,
    ) -> Result<Keytab, DirectoryError> {
        if self.realm.has(&format!("host/{fqdn}@{}", self.realm.name)) {
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
        let keytab = self.keys(fqdn)?;
        if let Some(end) = lease {
            // As krbPrincipalExpiration does: no ticket after the lease.
            self.realm.kadmin(&[
                "modprinc",
                "-expire",
                &format!("\"{}\"", kuipa_tools::text::date(end).unwrap()),
                &format!("host/{fqdn}@{}", self.realm.name),
            ]);
            self.leases.lock().unwrap().insert(fqdn.to_owned(), end);
        }
        Ok(keytab)
    }

    fn principal_lease(&self, principal: &Principal) -> Result<Option<u64>, DirectoryError> {
        Ok(match principal.components() {
            [service, fqdn] if service == "host" => self.leases.lock().unwrap().get(fqdn).copied(),
            _ => None,
        })
    }

    fn purge_leases(&self, before: u64) -> Result<Vec<String>, DirectoryError> {
        let mut leases = self.leases.lock().unwrap();
        let gone: Vec<String> = leases
            .iter()
            .filter(|(_, end)| **end < before)
            .map(|(fqdn, _)| fqdn.clone())
            .collect();
        for fqdn in &gone {
            leases.remove(fqdn);
            self.realm.kadmin(&[
                "delprinc",
                "-force",
                &format!("host/{fqdn}@{}", self.realm.name),
            ]);
            for members in self.hostgroups.lock().unwrap().values_mut() {
                members.retain(|m| m != fqdn);
            }
        }
        Ok(gone)
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
        let host = Principal::host(fqdn, &self.realm.name).to_string();
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

    fn seal_add(&self, seal: &Seal) -> Result<(), DirectoryError> {
        self.seals.lock().unwrap().insert(seal.id, seal.clone());
        Ok(())
    }

    fn seal_get(&self, id: &SealId) -> Result<Option<Seal>, DirectoryError> {
        Ok(self.seals.lock().unwrap().get(id).cloned().map(|mut v| {
            v.unlocks = self.total(id);
            v
        }))
    }

    fn seal_limits(&self) -> Result<kuipa_enroll::seal::Limits, DirectoryError> {
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

    fn seal_unlock(
        &self,
        id: &SealId,
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

    fn seal_update(&self, seal: &Seal) -> Result<(), DirectoryError> {
        self.seals.lock().unwrap().insert(seal.id, seal.clone());
        Ok(())
    }

    fn seals_of(&self, owner: &Principal) -> Result<Vec<Seal>, DirectoryError> {
        let owner = owner.to_string();
        let seals: Vec<Seal> = self
            .seals
            .lock()
            .unwrap()
            .values()
            .filter(|v| v.owner == owner)
            .cloned()
            .collect();
        Ok(seals
            .into_iter()
            .map(|mut v| {
                v.unlocks = self.total(&v.id);
                v
            })
            .collect())
    }

    fn seals_shared_with(
        &self,
        principal: &Principal,
        groups: &[String],
    ) -> Result<Vec<Seal>, DirectoryError> {
        let wanted = kuipa_enroll::seal::Members::matching_entries(principal, groups);
        let seals: Vec<Seal> = self
            .seals
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
        Ok(seals
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

    fn passkeys(
        &self,
        principal: &Principal,
    ) -> Result<kuipa_enroll::passkey::UserPasskeys, DirectoryError> {
        Ok(kuipa_enroll::passkey::UserPasskeys {
            values: self
                .passkeys
                .lock()
                .unwrap()
                .get(&principal.to_string())
                .cloned()
                .unwrap_or_default(),
            user_verification: *self.passkey_uv.lock().unwrap(),
        })
    }

    fn seals_approved_by(
        &self,
        principal: &Principal,
        groups: &[String],
    ) -> Result<Vec<Seal>, DirectoryError> {
        let wanted = kuipa_enroll::seal::Members::matching_entries(principal, groups);
        Ok(self
            .seals
            .lock()
            .unwrap()
            .values()
            .filter(|v| {
                v.policy
                    .approvals
                    .as_ref()
                    .is_some_and(|a| a.from.entries().iter().any(|e| wanted.contains(e)))
            })
            .cloned()
            .collect())
    }

    fn recovery_settings(
        &self,
    ) -> Result<Option<kuipa_enroll::seal::RecoverySettings>, DirectoryError> {
        Ok(self.recovery.lock().unwrap().clone())
    }

    fn deposit_add(&self, deposit: &kuipa_enroll::seal::Deposit) -> Result<(), DirectoryError> {
        self.deposits
            .lock()
            .unwrap()
            .insert((deposit.seal, deposit.id.clone()), deposit.clone());
        Ok(())
    }

    fn deposits(&self, id: &SealId) -> Result<Vec<kuipa_enroll::seal::Deposit>, DirectoryError> {
        Ok(self
            .deposits
            .lock()
            .unwrap()
            .values()
            .filter(|d| d.seal == *id)
            .cloned()
            .collect())
    }

    fn deposit_remove(&self, id: &SealId, deposit: &str) -> Result<(), DirectoryError> {
        self.deposits
            .lock()
            .unwrap()
            .remove(&(*id, deposit.to_owned()));
        Ok(())
    }

    fn device_escrow_set(
        &self,
        principal: &Principal,
        escrow: &kuipa_enroll::seal::DeviceEscrow,
    ) -> Result<(), DirectoryError> {
        let mut all = self.escrows.lock().unwrap();
        let mine = all.entry(principal.to_string()).or_default();
        mine.retain(|e| e.device != escrow.device);
        mine.push(escrow.clone());
        Ok(())
    }

    fn device_escrows(
        &self,
        principal: &Principal,
    ) -> Result<Vec<kuipa_enroll::seal::DeviceEscrow>, DirectoryError> {
        Ok(self
            .escrows
            .lock()
            .unwrap()
            .get(&principal.to_string())
            .cloned()
            .unwrap_or_default())
    }

    fn release_add(&self, request: &ReleaseRequest) -> Result<(), DirectoryError> {
        self.releases
            .lock()
            .unwrap()
            .insert((request.seal, request.id.clone()), request.clone());
        Ok(())
    }

    fn releases(&self, id: &SealId) -> Result<Vec<ReleaseRequest>, DirectoryError> {
        let uses = self.release_uses.lock().unwrap();
        Ok(self
            .releases
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.seal == *id)
            .cloned()
            .map(|mut r| {
                r.uses = uses
                    .iter()
                    .filter(|((v, rid, _), _)| v == id && *rid == r.id)
                    .map(|(_, n)| n)
                    .sum();
                r
            })
            .collect())
    }

    fn release_mark(
        &self,
        id: &SealId,
        request: &str,
        approval: &Approval,
        deny: bool,
    ) -> Result<(), DirectoryError> {
        let mut releases = self.releases.lock().unwrap();
        let r = releases
            .get_mut(&(*id, request.to_owned()))
            .ok_or("no such request")?;
        if deny {
            r.denied = Some(approval.clone());
        } else {
            r.approvals.push(approval.clone());
        }
        Ok(())
    }

    fn release_use(
        &self,
        id: &SealId,
        request: &str,
        server: &str,
        limit: u64,
    ) -> Result<bool, DirectoryError> {
        let mut uses = self.release_uses.lock().unwrap();
        let total: u64 = uses
            .iter()
            .filter(|((v, r, _), _)| v == id && r == request)
            .map(|(_, n)| n)
            .sum();
        if total >= limit {
            return Ok(false);
        }
        *uses
            .entry((*id, request.to_owned(), server.to_owned()))
            .or_default() += 1;
        Ok(true)
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
