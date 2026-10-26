//! Every protocol flow, client and server, against an in-memory directory.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use agirru_crdt::GenerationClock;
use kuipa_enroll::anchors::{AnchorState, Entry, Trust};
use kuipa_enroll::bundle::{Bundle, Mode, Opener, StageParams};
use kuipa_enroll::delegation::{Claim, Delegation, SignedVouch, VOUCH_VALIDITY};
use kuipa_enroll::escrow::{EscrowRequest, Kind, RegisterParams, Sealed, Sealer, VaultId};
use kuipa_enroll::join::{
    AuthType, KerberosBinding, Operation, PendingJoin, Prepared, Request, Response,
};
use kuipa_enroll::keytab::{Enctype, Keytab, KeytabEntry, Principal};
use kuipa_enroll::merkle::TreeHash;
use kuipa_enroll::passkey::soft::SoftAuthenticator;
use kuipa_enroll::passkey::{Algorithm, UserPasskeys};
use kuipa_enroll::realm::{Deployment, RealmInfo, ServerKeys, VerifiedRealm};
use kuipa_enroll::server::{
    Accepted, Appended, Directory, DirectoryError, Ledger, Staged, parse_stage_result,
};
use kuipa_enroll::tlog::{self, Head, Leaf, Log, LogId, SignedHead, VaultAction, VaultEvent};
use kuipa_enroll::vault::{
    self, Descriptor, DeviceType, Factors, Level, Recovered, SealedVaultFile, TicketDelegation,
    Unlock, Vault, VaultOp, VerifiedDescriptor,
};
use kuipa_enroll::{EnrollServer, Error};
use native_ossl::util::SecretBuf;
use tang_pqc::{
    ExchangeKeyPair, KemAlg, Policy, SignatureAlg, SignedAdvertisement, SigningKey, Thumbprint,
    unix_seconds,
};

const REALM: &str = "EXAMPLE.TEST";
const HOST: &str = "web1.example.test";
const CA: &[u8] = include_bytes!("data/ipa-ca.der");

fn now() -> u64 {
    unix_seconds(SystemTime::now())
}

/// A fake directory.  GSS tokens are modelled as `principal ‖ cb`, so a
/// token only "verifies" with the channel binding it was made for, and the
/// context's Kerberos binding as [`fake_binding`].  An `impostor` (a server
/// whose anchor verifies but that cannot accept tickets for this realm)
/// derives another binding.
#[derive(Default)]
struct MemoryDirectory {
    impostor: std::cell::Cell<bool>,
    otps: RefCell<HashMap<String, Vec<u8>>>,
    kvno: RefCell<HashMap<String, u32>>,
    admins: HashSet<String>,
    escrow: RefCell<HashMap<String, Vec<kuipa_enroll::escrow::BindingHash>>>,
    escrow_files: RefCell<HashMap<String, Vec<kuipa_enroll::escrow::BindingHash>>>,
    disabled: RefCell<HashSet<String>>,
    /// When each leased principal's lease ends.
    leases: RefCell<HashMap<String, u64>>,
    staged: RefCell<HashMap<String, Staged>>,
    vaults: RefCell<HashMap<VaultId, Vault>>,
    unlocks: RefCell<HashMap<(VaultId, String), u64>>,
    escrow_keys: RefCell<Vec<(String, tang_pqc::ExchangeKey)>>,
    limits: RefCell<vault::Limits>,
    /// The server list for the keys operation's policy (§18.2).
    masters: RefCell<Vec<String>>,
    /// The masters with the CA role.
    ca_masters: RefCell<Vec<String>>,
    /// The keys operation's secrets, by `namespace id/nickname`.
    key_secrets: RefCell<HashMap<(u8, String), Vec<u8>>>,
    /// The signing policy (`DESIGN-sign.md`).
    sign_policy: RefCell<kuipa_enroll::sign::SignPolicy>,
    /// Groups by principal, as `memberOf` would list them.
    groups: RefCell<HashMap<String, Vec<String>>>,
    /// Release requests by vault and id (`DESIGN-approvals.md`).
    releases: RefCell<HashMap<(VaultId, String), vault::ReleaseRequest>>,
    /// Their uses, by vault, id and server.
    release_uses: RefCell<HashMap<(VaultId, String, String), u64>>,
    /// Device keys kept under recovery codes, by holder.
    escrows: RefCell<HashMap<String, Vec<vault::DeviceEscrow>>>,
    /// Deposits by vault and id (`DESIGN-recovery.md` §3).
    deposits: RefCell<HashMap<(VaultId, String), vault::Deposit>>,
    /// The realm's device-key recovery settings (§4).
    recovery: RefCell<Option<vault::RecoverySettings>>,
    /// IPA passkeys (`ipaPassKey` values) by principal.
    passkeys: RefCell<HashMap<String, Vec<String>>>,
    /// Whether the realm requires user verification.
    passkey_uv: std::cell::Cell<bool>,
}

/// A stand-in for the GSS-API pseudo-random output both ends of a context
/// share.
fn fake_binding(principal: &str, cb: &[u8; 32]) -> KerberosBinding {
    let mut b = *cb;
    for (i, c) in principal.bytes().enumerate() {
        b[i % 32] ^= c;
    }
    KerberosBinding::new(&b).unwrap()
}

fn gss_token(principal: &str, cb: &[u8; 32]) -> Vec<u8> {
    let mut t = principal.as_bytes().to_vec();
    t.push(0);
    t.extend_from_slice(cb);
    t
}

impl MemoryDirectory {
    fn accept(token: &[u8], cb: &[u8; 32]) -> Result<String, DirectoryError> {
        let (name, rest) = token.split_at(token.iter().position(|&b| b == 0).ok_or("bad token")?);
        if &rest[1..] != cb {
            return Err("channel binding mismatch".into());
        }
        Ok(String::from_utf8(name.to_vec())?)
    }

    fn binding(&self, who: &str, cb: &[u8; 32]) -> KerberosBinding {
        fake_binding(if self.impostor.get() { "impostor" } else { who }, cb)
    }

    fn new_keys(&self, fqdn: &str) -> Keytab {
        let mut kvno = self.kvno.borrow_mut();
        let v = kvno.entry(fqdn.into()).or_insert(0);
        *v += 1;
        Keytab::new(
            Principal::host(fqdn, REALM),
            vec![KeytabEntry {
                kvno: *v,
                enctype: Enctype::AES256_CTS_HMAC_SHA1_96,
                key: SecretBuf::from_slice(&[u8::try_from(*v).unwrap(); 32]),
                timestamp: 1,
            }],
        )
    }
}

impl Directory for MemoryDirectory {
    fn join_with_otp(
        &self,
        fqdn: &str,
        otp: &[u8],
        _: &[Enctype],
    ) -> Result<Keytab, DirectoryError> {
        // One-time: consumed by the first successful use.
        let stored = self.otps.borrow_mut().remove(fqdn);
        match stored {
            Some(expected) if expected == otp => Ok(self.new_keys(fqdn)),
            Some(expected) => {
                self.otps.borrow_mut().insert(fqdn.into(), expected);
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
        Ok((self.new_keys(fqdn), self.binding(&who, cb)))
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
        Ok((self.new_keys(fqdn), self.binding(&who, cb)))
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
        self.staged.borrow_mut().insert(fqdn.into(), staged.clone());
        Ok((self.new_keys(fqdn), self.binding(&who, cb)))
    }

    fn register_escrow(
        &self,
        principal: &Principal,
        bindings: &[kuipa_enroll::escrow::BindingHash],
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
        binding: &kuipa_enroll::escrow::BindingHash,
    ) -> Result<bool, DirectoryError> {
        let p = principal.to_string();
        let set = match kind {
            Kind::Keytab => &self.escrow,
            Kind::File => &self.escrow_files,
        };
        Ok(!self.disabled.borrow().contains(&p)
            && set.borrow().get(&p).is_some_and(|b| b.contains(binding)))
    }

    fn register_with_gss(
        &self,
        params: &RegisterParams,
        bindings: &[kuipa_enroll::escrow::BindingHash],
        token: &[u8],
        cb: &[u8; 32],
    ) -> Result<KerberosBinding, DirectoryError> {
        let who = Self::accept(token, cb)?;
        if who != params.principal.to_string() {
            return Err("only a principal may register for itself".into());
        }
        match params.kind {
            Kind::Keytab => {
                self.escrow
                    .borrow_mut()
                    .insert(who.clone(), bindings.to_vec());
            }
            Kind::File => {
                let mut files = self.escrow_files.borrow_mut();
                let set = files.entry(who.clone()).or_default();
                set.retain(|b| !params.retire.contains(b));
                set.extend_from_slice(bindings);
            }
        }
        Ok(self.binding(&who, cb))
    }

    /// A token's name may end in ` via svc1,svc2`: the services a
    /// delegated ticket passed through.
    fn accept_user(&self, token: &[u8], cb: &[u8; 32]) -> Result<Accepted, DirectoryError> {
        let who = Self::accept(token, cb)?;
        let (principal, transited) = match who.split_once(" via ") {
            Some((p, via)) => (p.to_owned(), via.split(',').map(str::to_owned).collect()),
            None => (who.clone(), Vec::new()),
        };
        Ok(Accepted {
            principal,
            binding: self.binding(&who, cb),
            transited: Some(transited),
        })
    }

    fn fetch_key(
        &self,
        principal: &Principal,
        fetch: &kuipa_enroll::keys::KeysFetch,
    ) -> Result<Vec<u8>, DirectoryError> {
        let policy = kuipa_enroll::keys::KeysPolicy {
            servers: self.masters.borrow().clone(),
            ca_servers: self.ca_masters.borrow().clone(),
        };
        if let Some(reason) = policy.check(principal, fetch.namespace) {
            return Err(reason.into());
        }
        self.key_secrets
            .borrow()
            .get(&(fetch.namespace.id(), fetch.nickname.clone()))
            .cloned()
            .ok_or_else(|| "no such key".into())
    }

    fn vault_add(&self, vault: &Vault) -> Result<(), DirectoryError> {
        self.vaults.borrow_mut().insert(vault.id, vault.clone());
        Ok(())
    }

    fn vault_get(&self, id: &VaultId) -> Result<Option<Vault>, DirectoryError> {
        Ok(self.vaults.borrow().get(id).cloned())
    }

    fn vault_update(&self, vault: &Vault) -> Result<(), DirectoryError> {
        self.vaults.borrow_mut().insert(vault.id, vault.clone());
        Ok(())
    }

    fn vaults_of(&self, owner: &Principal) -> Result<Vec<Vault>, DirectoryError> {
        let owner = owner.to_string();
        let unlocks = self.unlocks.borrow();
        Ok(self
            .vaults
            .borrow()
            .values()
            .filter(|v| v.owner == owner)
            .cloned()
            .map(|mut v| {
                v.unlocks = unlocks
                    .iter()
                    .filter(|((id, _), _)| *id == v.id)
                    .map(|(_, n)| n)
                    .sum();
                v
            })
            .collect())
    }

    fn vaults_shared_with(
        &self,
        principal: &Principal,
        groups: &[String],
    ) -> Result<Vec<Vault>, DirectoryError> {
        let wanted = vault::Members::matching_entries(principal, groups);
        Ok(self
            .vaults
            .borrow()
            .values()
            .filter(|v| {
                v.managers
                    .entries()
                    .iter()
                    .chain(&v.members.entries())
                    .any(|e| wanted.contains(e))
            })
            .cloned()
            .collect())
    }

    fn principal_locked(&self, principal: &Principal) -> Result<bool, DirectoryError> {
        Ok(self.disabled.borrow().contains(&principal.to_string()))
    }

    fn principal_lease(&self, principal: &Principal) -> Result<Option<u64>, DirectoryError> {
        Ok(self.leases.borrow().get(&principal.to_string()).copied())
    }

    fn vaults_approved_by(
        &self,
        principal: &Principal,
        groups: &[String],
    ) -> Result<Vec<Vault>, DirectoryError> {
        let wanted = vault::Members::matching_entries(principal, groups);
        Ok(self
            .vaults
            .borrow()
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

    fn recovery_settings(&self) -> Result<Option<vault::RecoverySettings>, DirectoryError> {
        Ok(self.recovery.borrow().clone())
    }

    fn deposit_add(&self, deposit: &vault::Deposit) -> Result<(), DirectoryError> {
        self.deposits
            .borrow_mut()
            .insert((deposit.vault, deposit.id.clone()), deposit.clone());
        Ok(())
    }

    fn deposits(&self, id: &VaultId) -> Result<Vec<vault::Deposit>, DirectoryError> {
        Ok(self
            .deposits
            .borrow()
            .values()
            .filter(|d| d.vault == *id)
            .cloned()
            .collect())
    }

    fn deposit_remove(&self, id: &VaultId, deposit: &str) -> Result<(), DirectoryError> {
        self.deposits
            .borrow_mut()
            .remove(&(*id, deposit.to_owned()));
        Ok(())
    }

    fn device_escrow_set(
        &self,
        principal: &Principal,
        escrow: &vault::DeviceEscrow,
    ) -> Result<(), DirectoryError> {
        let mut all = self.escrows.borrow_mut();
        let mine = all.entry(principal.to_string()).or_default();
        mine.retain(|e| e.device != escrow.device);
        mine.push(escrow.clone());
        Ok(())
    }

    fn device_escrows(
        &self,
        principal: &Principal,
    ) -> Result<Vec<vault::DeviceEscrow>, DirectoryError> {
        Ok(self
            .escrows
            .borrow()
            .get(&principal.to_string())
            .cloned()
            .unwrap_or_default())
    }

    fn release_add(&self, request: &vault::ReleaseRequest) -> Result<(), DirectoryError> {
        self.releases
            .borrow_mut()
            .insert((request.vault, request.id.clone()), request.clone());
        Ok(())
    }

    fn releases(&self, id: &VaultId) -> Result<Vec<vault::ReleaseRequest>, DirectoryError> {
        let uses = self.release_uses.borrow();
        Ok(self
            .releases
            .borrow()
            .values()
            .filter(|r| r.vault == *id)
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
        id: &VaultId,
        request: &str,
        approval: &vault::Approval,
        deny: bool,
    ) -> Result<(), DirectoryError> {
        let mut releases = self.releases.borrow_mut();
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
        id: &VaultId,
        request: &str,
        server: &str,
        limit: u64,
    ) -> Result<bool, DirectoryError> {
        let mut uses = self.release_uses.borrow_mut();
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

    fn vault_limits(&self) -> Result<vault::Limits, DirectoryError> {
        Ok(self.limits.borrow().clone())
    }

    fn passkeys(&self, principal: &Principal) -> Result<UserPasskeys, DirectoryError> {
        Ok(UserPasskeys {
            values: self
                .passkeys
                .borrow()
                .get(&principal.to_string())
                .cloned()
                .unwrap_or_default(),
            user_verification: self.passkey_uv.get(),
        })
    }

    fn sign_policy(&self) -> Result<kuipa_enroll::sign::SignPolicy, DirectoryError> {
        Ok(self.sign_policy.borrow().clone())
    }

    fn principal_groups(&self, principal: &Principal) -> Result<Vec<String>, DirectoryError> {
        Ok(self
            .groups
            .borrow()
            .get(&principal.to_string())
            .cloned()
            .unwrap_or_default())
    }

    fn escrow_servers(&self) -> Result<Vec<(String, tang_pqc::ExchangeKey)>, DirectoryError> {
        Ok(self.escrow_keys.borrow().clone())
    }

    fn publish_escrow_key(
        &self,
        server: &str,
        key: &tang_pqc::ExchangeKey,
    ) -> Result<(), DirectoryError> {
        let mut keys = self.escrow_keys.borrow_mut();
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
        let total: u64 = self
            .unlocks
            .borrow()
            .iter()
            .filter(|((v, _), _)| v == id)
            .map(|(_, n)| n)
            .sum();
        if limit.is_some_and(|l| total >= l) {
            return Ok(false);
        }
        *self
            .unlocks
            .borrow_mut()
            .entry((*id, server.to_owned()))
            .or_default() += 1;
        Ok(true)
    }

    fn ca_certificates(&self) -> Result<Vec<Vec<u8>>, DirectoryError> {
        Ok(vec![CA.to_vec()])
    }

    fn servers(&self) -> Result<Vec<String>, DirectoryError> {
        Ok(vec!["ipa1.example.test".into(), "ipa2.example.test".into()])
    }
}

struct Realm {
    /// Each server's own anchor.
    anchors: Vec<SigningKey>,
    servers: Vec<EnrollServer>,
    dir: MemoryDirectory,
}

const SERVERS: [&str; 2] = ["ipa1.example.test", "ipa2.example.test"];

fn server(anchor: &SigningKey, fqdn: &str) -> (EnrollServer, Delegation) {
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let own = Delegation::issue(
        anchor,
        REALM,
        fqdn,
        signing.public(),
        now() - 60,
        now() + 30 * 86400,
    )
    .unwrap();
    let server = EnrollServer::new(
        ServerKeys {
            signing,
            join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            trust: Vec::new(),
            vouchers: Vec::new(),
            retired: Vec::new(),
        },
        RealmInfo {
            realm: REALM.into(),
            domain: "example.test".into(),
            basedn: "dc=example,dc=test".into(),
            server: fqdn.into(),
            servers: SERVERS.map(String::from).to_vec(),
            ca_certs: vec![CA.to_vec()],
            pkinit_anchors: vec![CA.to_vec()],
            anchors: vec![*anchor.public().thumbprint()],
            heads: Vec::new(),
            trusts: Vec::new(),
        },
        own.clone(),
    );
    (server, own)
}

/// The anchor exchange between the servers, as the daemons run it: each
/// trusts the other after a Kerberos-authenticated sync, its anchor vouches
/// for both claims, and it publishes its claim with both anchors' proofs.
fn exchange(anchors: &[SigningKey], servers: &[EnrollServer], own: &[Delegation]) {
    let clock = GenerationClock::new();
    let policy = Policy::default();
    let members: BTreeSet<String> = SERVERS.map(String::from).into();
    let claims: Vec<Claim> = own.iter().map(|d| d.claim().unwrap()).collect();
    let mut state = AnchorState::default();
    for (anchor, claim) in anchors.iter().zip(&claims) {
        let key = Entry::Key(anchor.public().to_jwk_json());
        state.put(key, REALM, &policy, now(), &clock).unwrap();
        state
            .put(Entry::Claim(claim.clone()), REALM, &policy, now(), &clock)
            .unwrap();
    }
    let trust = |state: &AnchorState, i: usize| {
        let attested: Vec<_> = (0..own.len())
            .filter(|j| *j != i)
            .map(|j| own[j].clone())
            .collect();
        Trust::compute(state, &claims[i], &attested, &members, &policy, now()).unwrap()
    };
    for (i, anchor) in anchors.iter().enumerate() {
        let leaves = trust(&state, i)
            .leaves(TreeHash::for_signer(anchor.public().alg()))
            .unwrap();
        let vouch = SignedVouch::issue(
            anchor,
            REALM,
            leaves,
            now() - 60,
            now() + VOUCH_VALIDITY,
            None,
        )
        .unwrap();
        state
            .put(Entry::Vouch(vouch), REALM, &policy, now(), &clock)
            .unwrap();
    }
    for (i, server) in servers.iter().enumerate() {
        let t = trust(&state, i);
        let vouches: HashMap<_, _> = state
            .vouches()
            .map(|v| (v.vouch().anchor, v.clone()))
            .collect();
        server.publish(t.own_delegation(&state).unwrap(), t.anchors(), vouches);
    }
}

fn realm() -> Realm {
    let anchors: Vec<_> = SERVERS
        .iter()
        .map(|_| SigningKey::generate(SignatureAlg::MlDsa65).unwrap())
        .collect();
    let (servers, own): (Vec<_>, Vec<_>) = SERVERS
        .iter()
        .zip(&anchors)
        .map(|(fqdn, anchor)| server(anchor, fqdn))
        .unzip();
    exchange(&anchors, &servers, &own);
    let dir = MemoryDirectory {
        admins: HashSet::from(["admin@EXAMPLE.TEST".to_string()]),
        ..MemoryDirectory::default()
    };
    dir.otps
        .borrow_mut()
        .insert(HOST.into(), b"Secret123".to_vec());
    Realm {
        anchors,
        servers,
        dir,
    }
}

impl Realm {
    /// What the enrollment string pins: the first server's anchor, which
    /// every server's delegation carries after the exchange.
    fn anchors(&self) -> [Thumbprint; 1] {
        [*self.anchors[0].public().thumbprint()]
    }

    /// Every server's anchor.
    fn all_anchors(&self) -> Vec<Thumbprint> {
        self.anchors
            .iter()
            .map(|a| *a.public().thumbprint())
            .collect()
    }

    /// What a client does with `GET /adv`: parse JSON and verify.
    fn verify(&self, i: usize) -> VerifiedRealm {
        let json = self.servers[i]
            .advertisement(&self.anchors())
            .unwrap()
            .to_json();
        VerifiedRealm::verify(
            &SignedAdvertisement::from_json(json.as_bytes()).unwrap(),
            REALM,
            &self.anchors(),
            &Policy::default(),
            SystemTime::now(),
        )
        .unwrap()
    }

    /// Send over the "wire" to server `i` at the endpoint of `op`.
    fn send(&self, i: usize, op: Operation, request: &Request) -> Result<Response, ()> {
        let request = Request::from_bytes(op, &request.to_bytes()).map_err(|_| ())?;
        let response = self.servers[i]
            .handle(&request, &self.dir)
            .map_err(|_| ())?;
        Ok(Response::from_bytes(&response.to_bytes()).unwrap())
    }
}

fn otp_request(adv: &VerifiedRealm, otp: &[u8]) -> (Request, PendingJoin) {
    Prepared::new(adv, Operation::Join, HOST, AuthType::Otp, &Enctype::DEFAULT)
        .unwrap()
        .seal(otp, &[], &[])
        .unwrap()
}

#[test]
fn otp_join() {
    let r = realm();
    let adv = r.verify(0);
    let (request, pending) = otp_request(&adv, b"Secret123");
    let response = r.send(0, Operation::Join, &request).unwrap();
    let e = pending.finish(&response, &adv).unwrap();
    assert_eq!(e.keytab.principal(), &Principal::host(HOST, REALM));
    assert_eq!(e.keytab.kvno(), Some(1));
    assert_eq!(e.ca_certs, vec![CA.to_vec()]);
    assert_eq!(e.config.issuer, "ipa1.example.test");
    assert_eq!(
        e.anchors,
        r.all_anchors(),
        "both anchors, the issuer's first"
    );

    // The OTP is consumed: replaying the same request is refused.
    assert!(r.send(0, Operation::Join, &request).is_err());
}

/// A copy of `server` after its join key was rotated: a new join key is
/// advertised, the old one is retired.
fn rotated(server: &EnrollServer) -> EnrollServer {
    let copy =
        |k: &ExchangeKeyPair| ExchangeKeyPair::from_jwk(k.to_jwk().unwrap().as_ref()).unwrap();
    let keys = server.keys();
    let rotated = EnrollServer::new(
        ServerKeys {
            signing: SigningKey::from_jwk(keys.signing.to_jwk().unwrap().as_ref()).unwrap(),
            join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            escrow: keys.escrow.iter().map(copy).collect(),
            trust: Vec::new(),
            vouchers: Vec::new(),
            retired: keys.join.iter().map(copy).collect(),
        },
        server.info().clone(),
        server.delegation(),
    );
    rotated.publish(server.delegation(), server.anchors(), server.vouches());
    rotated
}

#[test]
fn retired_join_keys_are_still_answered() {
    let mut r = realm();
    // The client verified the advertisement before the rotation.
    let adv = r.verify(0);
    let old_kid = *adv.join_key().unwrap().kid();
    r.servers[0] = rotated(&r.servers[0]);
    let (request, pending) = otp_request(&adv, b"Secret123");
    let e = pending
        .finish(&r.send(0, Operation::Join, &request).unwrap(), &adv)
        .unwrap();
    assert_eq!(e.keytab.principal(), &Principal::host(HOST, REALM));
    // New clients see only the new join key.
    let fresh = r.verify(0);
    assert_ne!(fresh.join_key().unwrap().kid(), &old_kid);
}

#[test]
fn any_delegated_server_accepts_the_same_enrollment_string() {
    let r = realm();
    let adv = r.verify(1);
    assert_eq!(adv.server(), "ipa2.example.test");
    let (request, pending) = otp_request(&adv, b"Secret123");
    let e = pending
        .finish(&r.send(1, Operation::Join, &request).unwrap(), &adv)
        .unwrap();
    assert_eq!(e.config.issuer, "ipa2.example.test");
}

#[test]
fn wrong_otp_and_wrong_server_are_refused() {
    let r = realm();
    let adv = r.verify(0);
    let (request, _) = otp_request(&adv, b"guess");
    assert!(r.send(0, Operation::Join, &request).is_err());

    // A request encrypted to ipa1 cannot be answered by ipa2.
    let (request, _) = otp_request(&adv, b"Secret123");
    assert!(r.send(1, Operation::Join, &request).is_err());
    // ... and the OTP is still usable on ipa1.
    assert!(r.send(0, Operation::Join, &request).is_ok());
}

#[test]
fn requests_are_bound_to_their_endpoint() {
    let r = realm();
    let adv = r.verify(0);
    let (request, _) = otp_request(&adv, b"Secret123");
    // Same wire format, other endpoint: the transcript differs.
    assert!(r.send(0, Operation::Rekey, &request).is_err());
    assert!(
        r.send(0, Operation::Stage, &request).is_err(),
        "other magic"
    );
}

#[test]
fn responses_are_bound_to_their_request() {
    let r = realm();
    let adv = r.verify(0);
    let (request, _first) = otp_request(&adv, b"Secret123");
    let response = r.send(0, Operation::Join, &request).unwrap();
    let (_, second) = otp_request(&adv, b"Secret123");
    assert!(matches!(
        second.finish(&response, &adv),
        Err(Error::BadResponse)
    ));

    // Tampering with the response.
    let r = realm();
    let adv = r.verify(0);
    let (request, pending) = otp_request(&adv, b"Secret123");
    let mut bytes = r.send(0, Operation::Join, &request).unwrap().to_bytes();
    let n = bytes.len();
    bytes[n - 1] ^= 1;
    assert!(
        pending
            .finish(&Response::from_bytes(&bytes).unwrap(), &adv)
            .is_err()
    );
}

#[test]
fn tampered_request_fields_are_refused() {
    let r = realm();
    let adv = r.verify(0);
    let (request, _) = otp_request(&adv, b"Secret123");
    let good = request.to_bytes();
    // Flip one byte in the fqdn (after magic, version, alg, kid, realm).
    let pos = 4 + 1 + 1 + 32 + 4 + REALM.len() + 4;
    let mut bad = good.clone();
    bad[pos] ^= 0x20;
    let bad = Request::from_bytes(Operation::Join, &bad).unwrap();
    assert!(r.servers[0].handle(&bad, &r.dir).is_err());
}

fn join_binds_the_token(r: &Realm, adv: &VerifiedRealm) {
    let prepared = Prepared::new(
        adv,
        Operation::Join,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = prepared.channel_binding().unwrap();
    let (request, pending) = prepared
        .with_kerberos(fake_binding("admin@EXAMPLE.TEST", &cb))
        .seal(&gss_token("admin@EXAMPLE.TEST", &cb), &[], &[])
        .unwrap();
    let e = pending
        .finish(&r.send(0, Operation::Join, &request).unwrap(), adv)
        .unwrap();
    assert_eq!(e.keytab.kvno(), Some(1));

    // A token made for another exchange does not verify (channel binding).
    let p2 = Prepared::new(
        adv,
        Operation::Join,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let (request, _) = p2
        .with_kerberos(fake_binding("admin@EXAMPLE.TEST", &cb))
        .seal(&gss_token("admin@EXAMPLE.TEST", &cb), &[], &[])
        .unwrap();
    assert!(r.send(0, Operation::Join, &request).is_err());
}

fn rekey_by_the_host_only(r: &Realm, adv: &VerifiedRealm) {
    // Rekey by the host itself; not by someone else.
    let host = Principal::host(HOST, REALM).to_string();
    let p = Prepared::new(
        adv,
        Operation::Rekey,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding(&host, &cb))
        .seal(&gss_token(&host, &cb), &[], &[])
        .unwrap();
    let e = pending
        .finish(&r.send(0, Operation::Rekey, &request).unwrap(), adv)
        .unwrap();
    assert_eq!(e.keytab.kvno(), Some(2));

    // A server that cannot accept this realm's tickets derives another
    // binding: its response does not open, though its anchor verified.
    r.dir.impostor.set(true);
    let p = Prepared::new(
        adv,
        Operation::Rekey,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding(&host, &cb))
        .seal(&gss_token(&host, &cb), &[], &[])
        .unwrap();
    let response = r.send(0, Operation::Rekey, &request).unwrap();
    assert!(matches!(
        pending.finish(&response, adv),
        Err(Error::BadResponse)
    ));
    r.dir.impostor.set(false);
}

fn rekey_refusals(r: &Realm, adv: &VerifiedRealm) {
    let host = Principal::host(HOST, REALM).to_string();
    // A Kerberos request without the binding is not even sealed.
    let p = Prepared::new(
        adv,
        Operation::Rekey,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    assert!(p.seal(&gss_token(&host, &cb), &[], &[]).is_err());

    let p = Prepared::new(
        adv,
        Operation::Rekey,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, _) = p
        .with_kerberos(fake_binding("admin@EXAMPLE.TEST", &cb))
        .seal(&gss_token("admin@EXAMPLE.TEST", &cb), &[], &[])
        .unwrap();
    assert!(r.send(0, Operation::Rekey, &request).is_err());

    // OTP is not accepted for rekeying.
    let (request, _) = Prepared::new(
        adv,
        Operation::Rekey,
        HOST,
        AuthType::Otp,
        &Enctype::DEFAULT,
    )
    .unwrap()
    .seal(b"Secret123", &[], &[])
    .unwrap();
    assert!(r.send(0, Operation::Rekey, &request).is_err());
}

#[test]
fn kerberos_join_and_rekey() {
    let r = realm();
    let adv = r.verify(0);
    join_binds_the_token(&r, &adv);
    rekey_by_the_host_only(&r, &adv);
    rekey_refusals(&r, &adv);
}

fn stage(
    r: &Realm,
    adv: &VerifiedRealm,
    params: &StageParams,
) -> (Bundle, Option<kuipa_enroll::enrollment::Secret>) {
    let p = Prepared::new(
        adv,
        Operation::Stage,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding("admin@EXAMPLE.TEST", &cb))
        .seal(
            &gss_token("admin@EXAMPLE.TEST", &cb),
            &[],
            &params.to_bytes(),
        )
        .unwrap();
    let payload = pending
        .open(&r.send(0, Operation::Stage, &request).unwrap())
        .unwrap();
    parse_stage_result(payload.as_ref()).unwrap()
}

#[test]
fn offline_enrollment_modes_a_and_b() {
    let r = realm();
    let adv = r.verify(0);

    // Mode A: the target prepared a machine key.
    let machine = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let params = StageParams {
        mode: Mode::MachineKey,
        recipient: Some(machine.public().clone()),
        not_after: now() + 7 * 86400,
    };
    let (bundle, secret) = stage(&r, &adv, &params);
    assert!(secret.is_none());
    assert!(r.dir.staged.borrow().contains_key(HOST));
    // Offline: only the bundle and the anchor.
    let v = Bundle::from_bytes(&bundle.to_bytes())
        .unwrap()
        .verify(&r.anchors(), &Policy::default())
        .unwrap();
    let e = v.open(Opener::MachineKey(&machine)).unwrap();
    assert_eq!(e.keytab.principal(), &Principal::host(HOST, REALM));
    assert_eq!(e.ca_certs, vec![CA.to_vec()]);

    // Mode B: a secret for the enrollment string.
    let params = StageParams {
        mode: Mode::Secret,
        recipient: None,
        not_after: now() + 86400,
    };
    let (bundle, secret) = stage(&r, &adv, &params);
    let v = bundle.verify(&r.anchors(), &Policy::default()).unwrap();
    let e = v.open(Opener::Secret(secret.unwrap().as_bytes())).unwrap();
    assert_eq!(e.keytab.kvno(), Some(2), "staging again replaces the keys");

    // First contact: rekey with the staged keys clears the staged state.
    let host = Principal::host(HOST, REALM).to_string();
    let p = Prepared::new(
        &adv,
        Operation::Rekey,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding(&host, &cb))
        .seal(&gss_token(&host, &cb), &[], &[])
        .unwrap();
    pending
        .finish(&r.send(0, Operation::Rekey, &request).unwrap(), &adv)
        .unwrap();
    assert!(!r.dir.staged.borrow().contains_key(HOST));
}

#[test]
fn staging_needs_an_administrator() {
    let r = realm();
    let adv = r.verify(0);
    let p = Prepared::new(
        &adv,
        Operation::Stage,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let params = StageParams {
        mode: Mode::Secret,
        recipient: None,
        not_after: now() + 86400,
    };
    let (request, _) = p
        .with_kerberos(fake_binding("eve@EXAMPLE.TEST", &cb))
        .seal(&gss_token("eve@EXAMPLE.TEST", &cb), &[], &params.to_bytes())
        .unwrap();
    assert!(r.send(0, Operation::Stage, &request).is_err());
}

#[test]
fn sealed_keytab_with_registration_and_revocation() {
    let r = realm();
    let advs = [r.verify(0), r.verify(1)];

    // Join, registering bindings to both servers in the same request.
    let host_keys = {
        let (request, pending) = otp_request(&advs[0], b"Secret123");
        pending
            .finish(&r.send(0, Operation::Join, &request).unwrap(), &advs[0])
            .unwrap()
            .keytab
    };
    let (sealed, registrations) = Sealed::seal(&host_keys, &[&advs[0], &advs[1]]).unwrap();
    let hashes: Vec<_> = registrations.iter().map(|g| g.binding).collect();
    r.dir
        .register_escrow(&Principal::host(HOST, REALM), &hashes)
        .unwrap();
    let stored = sealed.to_bytes();

    let recover = |i: usize, req: &EscrowRequest| {
        let req = EscrowRequest::from_bytes(&req.to_bytes()).unwrap();
        r.servers[i]
            .recover(&req, &r.dir)
            .ok()
            .and_then(Recovered::into_plain)
    };
    let by_name = |name: &str| usize::from(name == "ipa2.example.test");

    // Any server can unseal.
    let sealed = Sealed::from_bytes(&stored).unwrap();
    let kt = sealed.unseal(|s, req| recover(by_name(s), req)).unwrap();
    assert_eq!(kt.kvno(), host_keys.kvno());
    // ipa1 down: ipa2 alone suffices.
    let kt = sealed
        .unseal(|s, req| {
            (s == "ipa2.example.test")
                .then(|| recover(1, req))
                .flatten()
        })
        .unwrap();
    assert_eq!(kt.principal(), host_keys.principal());

    // Disabling the host stops unsealing immediately.
    r.dir
        .disabled
        .borrow_mut()
        .insert(Principal::host(HOST, REALM).to_string());
    assert!(matches!(
        sealed.unseal(|s, req| recover(by_name(s), req)),
        Err(Error::Refused)
    ));
    r.dir.disabled.borrow_mut().clear();

    // A fresh seal (rebind) retires the old bindings once registered.
    let (resealed, registrations) = Sealed::seal(&kt, &[&advs[0], &advs[1]]).unwrap();
    let hashes: Vec<_> = registrations.iter().map(|g| g.binding).collect();
    r.dir
        .register_escrow(&Principal::host(HOST, REALM), &hashes)
        .unwrap();
    assert!(sealed.unseal(|s, req| recover(by_name(s), req)).is_err());
    resealed.unseal(|s, req| recover(by_name(s), req)).unwrap();
}

/// A registration (§7.5) made with `caller`'s ticket.
fn register_request(
    adv: &VerifiedRealm,
    caller: &str,
    params: &RegisterParams,
    bindings: &[kuipa_enroll::escrow::BindingHash],
) -> (Request, PendingJoin) {
    let p = Prepared::new(
        adv,
        Operation::Register,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    p.with_kerberos(fake_binding(caller, &cb))
        .seal(
            &gss_token(caller, &cb),
            bindings,
            &params.to_bytes().unwrap(),
        )
        .unwrap()
}

#[test]
fn sealed_file_registered_by_its_principal() {
    let r = realm();
    let advs = [r.verify(0), r.verify(1)];
    let service: Principal = format!("HTTP/{HOST}@{REALM}").parse().unwrap();
    let recover = |s: &str, req: &EscrowRequest| {
        let req = EscrowRequest::from_bytes(&req.to_bytes()).unwrap();
        r.servers[usize::from(s == "ipa2.example.test")]
            .recover(&req, &r.dir)
            .ok()
            .and_then(Recovered::into_plain)
    };
    let seal = |contents: &[u8], retire: Vec<kuipa_enroll::escrow::BindingHash>| {
        let (sealer, registrations) =
            Sealer::prepare(&service, Kind::File, &[&advs[0], &advs[1]]).unwrap();
        let bindings: Vec<_> = registrations.iter().map(|g| g.binding).collect();
        let params = RegisterParams {
            principal: service.clone(),
            kind: Kind::File,
            retire,
        };
        let (request, pending) =
            register_request(&advs[0], &service.to_string(), &params, &bindings);
        let response = r.send(0, Operation::Register, &request).unwrap();
        pending
            .finish_register(&response, &advs[0], &params)
            .unwrap();
        sealer.seal_file(contents).unwrap()
    };

    let first = Sealed::from_bytes(&seal(b"first", Vec::new()).to_bytes()).unwrap();
    assert_eq!(first.kind(), Kind::File);
    assert_eq!(first.unseal_contents(recover).unwrap().as_ref(), b"first");
    assert!(matches!(first.unseal(recover), Err(Error::Mismatch(_))));

    // A reseal retires the bindings it replaces; the keytab set is untouched.
    let second = seal(b"second", first.bindings().unwrap());
    assert!(first.unseal_contents(recover).is_err());
    assert_eq!(second.unseal_contents(recover).unwrap().as_ref(), b"second");
    assert!(!r.dir.escrow.borrow().contains_key(&service.to_string()));

    // Another principal's ticket cannot register for the service.
    let params = RegisterParams {
        principal: service.clone(),
        kind: Kind::File,
        retire: second.bindings().unwrap(),
    };
    let host = Principal::host(HOST, REALM).to_string();
    let (request, _) = register_request(&advs[0], &host, &params, &[]);
    assert!(r.send(0, Operation::Register, &request).is_err());
    second.unseal_contents(recover).unwrap();

    // Nor can a registration be sent to the rekey endpoint.
    let (request, _) = register_request(&advs[0], &service.to_string(), &params, &[]);
    assert!(r.send(0, Operation::Rekey, &request).is_err());
}

/// `req` presented under another principal and vault, with its own
/// commitment.
fn renamed(req: &EscrowRequest, principal: &Principal, vault: &VaultId) -> EscrowRequest {
    let bytes = tang_pqc::wire::Writer::new(*b"IPEQ")
        .str(&principal.to_string())
        .fixed(vault.as_bytes())
        .fixed(req.commitment())
        .bytes(&req.recovery().to_bytes())
        .bytes(req.device().map_or(&[][..], |d| d.as_bytes()))
        .bytes(req.session())
        .bytes(req.ticket())
        .finish();
    EscrowRequest::from_bytes(&bytes).unwrap()
}

#[test]
fn bindings_open_only_under_what_they_commit_to() {
    let r = realm();
    let advs = [r.verify(0), r.verify(1)];
    let host = Principal::host(HOST, REALM);
    let eve = Principal::host("evil.example.test", REALM);
    let keys = Keytab::new(
        host.clone(),
        vec![KeytabEntry {
            kvno: 1,
            enctype: Enctype::AES256_CTS_HMAC_SHA1_96,
            key: SecretBuf::from_slice(&[7; 32]),
            timestamp: 1,
        }],
    );
    let (sealed, registrations) = Sealed::seal(&keys, &[&advs[0], &advs[1]]).unwrap();
    let hashes: Vec<_> = registrations.iter().map(|g| g.binding).collect();
    // The same bindings registered on the host's entry and on Eve's, in
    // both sets: before commitments, only the binding context (mixed in on
    // the client) stood between Eve's claim and the host's key.
    for p in [&host, &eve] {
        r.dir.register_escrow(p, &hashes).unwrap();
        r.dir
            .escrow_files
            .borrow_mut()
            .insert(p.to_string(), hashes.clone());
    }
    let answer = |req: &EscrowRequest| {
        let req = EscrowRequest::from_bytes(&req.to_bytes()).unwrap();
        r.servers[0]
            .recover(&req, &r.dir)
            .map(|a| a.into_plain().unwrap())
    };

    let mut seen = Vec::new();
    sealed
        .unseal(|_, req| {
            seen.push(req.clone());
            answer(req).ok()
        })
        .unwrap();
    let req = &seen[0];
    assert_eq!(
        req.vault(),
        &VaultId::machine(&host, Kind::Keytab, KemAlg::MlKem768).unwrap()
    );
    // Opened by its own principal: rate limited by it before decapsulation.
    assert!(r.servers[0].is_machine_request(req));

    // Eve's own principal and machine vault, where the binding is registered.
    let eves = renamed(
        req,
        &eve,
        &VaultId::machine(&eve, Kind::Keytab, KemAlg::MlKem768).unwrap(),
    );
    assert!(answer(&eves).is_err());
    // The host's file vault, where the binding is registered too.
    let file = renamed(
        req,
        &host,
        &VaultId::machine(&host, Kind::File, KemAlg::MlKem768).unwrap(),
    );
    assert!(answer(&file).is_err());
    // A vault that does not exist.
    let none = renamed(req, &host, &VaultId::from_bytes([9; 16]));
    assert!(answer(&none).is_err());
}

const ALICE: &str = "alice@EXAMPLE.TEST";
const BOB: &str = "bob@EXAMPLE.TEST";
const CAROL: &str = "carol@EXAMPLE.TEST";

/// Run a vault operation as `caller` against server 0.
fn vault_op(
    r: &Realm,
    adv: &VerifiedRealm,
    caller: &str,
    op: &VaultOp,
) -> Result<Vec<Descriptor>, ()> {
    let p = Prepared::new(
        adv,
        Operation::Vault,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding(caller, &cb))
        .seal(&gss_token(caller, &cb), &[], &op.to_bytes())
        .unwrap();
    let response = r.send(0, Operation::Vault, &request)?;
    let payload = pending.open(&response).map_err(|_| ())?;
    vault::Reply::from_bytes(payload.as_ref())
        .map(|r| r.descriptors)
        .map_err(|_| ())
}

/// The operation that adds a device named `name`, with `key`.
fn add_device_op(name: &str, key: &ExchangeKeyPair) -> VaultOp {
    VaultOp::AddDevice {
        name: name.into(),
        label: "laptop".into(),
        kind: DeviceType::File,
        alg: key.public().alg().id(),
        key: tang_pqc::b64::encode(key.public().as_bytes()),
    }
}

/// Escrow recovery as the test's servers answer it; `s` names the server.
fn ask_server(r: &Realm, s: &str, req: &EscrowRequest) -> Option<Vec<u8>> {
    let req = EscrowRequest::from_bytes(&req.to_bytes()).unwrap();
    r.servers[usize::from(s == "ipa2.example.test")]
        .recover(&req, &r.dir)
        .ok()
        .map(|a| a.to_bytes())
}

/// The fixture of the vault test: the realm, Alice's device, her
/// policy and the file she sealed.
struct VaultCase {
    r: Realm,
    advs: [VerifiedRealm; 2],
    anchors: Vec<Thumbprint>,
    device: ExchangeKeyPair,
    other_device: ExchangeKeyPair,
    policy: vault::Policy,
    sealed: SealedVaultFile,
    id: VaultId,
}

impl VaultCase {
    /// The advertisement of the first server.
    fn adv(&self) -> &VerifiedRealm {
        &self.advs[0]
    }

    /// Open the file as `who` with `key`, against the test's servers.
    fn open(&self, who: &'static str, key: Option<&ExchangeKeyPair>) -> Result<SecretBuf, Error> {
        let mut ticket = move |_: &str, cb: &[u8; 32]| Some(gss_token(who, cb));
        self.sealed.open(
            Unlock {
                device: key.map(|k| k as &dyn vault::DeviceKey),
                session: None,
                ticket: Some(&mut ticket),
                release: None,
                passkey: None,
            },
            |s, req| ask_server(&self.r, s, req),
        )
    }
}

/// The vault test's fixture, with Alice's file sealed to her device.
fn vault_case() -> VaultCase {
    let r = realm();
    let advs = [r.verify(0), r.verify(1)];
    let adv = &advs[0];
    let anchors = r.all_anchors();
    let device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let other_device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let policy = vault::Policy {
        factors: Factors {
            device: Some(Level::Any),
            ticket: true,
            passkey: false,
        },
        ..vault::Policy::default()
    };

    // Policies the server refuses: no factor, unsupported features.
    for bad in [
        vault::Policy::default(),
        vault::Policy {
            sessions: vault::Sessions {
                reauth: None,
                offline: Some(600),
                epoch: None,
            },
            ..policy.clone()
        },
    ] {
        let op = VaultOp::Create {
            name: "bad".into(),
            policy: bad,
        };
        assert!(vault_op(&r, adv, ALICE, &op).is_err());
    }

    let created = vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::Create {
            name: "personal".into(),
            policy: policy.clone(),
        },
    )
    .unwrap();
    let v = created[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap();
    assert!(
        v.vault().policy.not_after.is_some(),
        "filled in from the limits"
    );
    // Sealing needs a registered device when the policy asks for one.
    assert!(SealedVaultFile::seal(&v, &[&advs[0], &advs[1]], b"x").is_err());

    let described = vault_op(&r, adv, ALICE, &add_device_op("personal", &device)).unwrap();
    let desc = Descriptor::from_bytes(&described[0].to_bytes()).unwrap();
    let v = desc.verify(REALM, &anchors, &Policy::default()).unwrap();
    assert_eq!(v.vault().devices.len(), 1);
    // A descriptor checked against unrelated anchors does not verify.
    let stranger = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    assert!(
        desc.verify(
            REALM,
            &[*stranger.public().thumbprint()],
            &Policy::default()
        )
        .is_err()
    );

    let sealed = SealedVaultFile::seal(&v, &[&advs[0], &advs[1]], b"token=secret\n").unwrap();
    let sealed = SealedVaultFile::from_bytes(&sealed.to_bytes()).unwrap();
    let id = *sealed.vault();
    VaultCase {
        r,
        advs,
        anchors,
        device,
        other_device,
        policy,
        sealed,
        id,
    }
}

/// Replace Alice's policy on the personal vault with `p`.
fn set_policy(c: &VaultCase, p: vault::Policy) {
    vault_op(
        &c.r,
        c.adv(),
        ALICE,
        &VaultOp::SetPolicy {
            name: "personal".into(),
            policy: p,
        },
    )
    .unwrap();
}

fn alice_opens_her_file(c: &VaultCase) {
    let device = &c.device;
    let other_device = &c.other_device;
    assert_eq!(
        c.open(ALICE, Some(device)).unwrap().as_ref(),
        b"token=secret\n"
    );
    // Without the device, or with one the file was not sealed to.
    assert!(c.open(ALICE, None).is_err());
    assert!(c.open(ALICE, Some(other_device)).is_err());
    // Bob's ticket is not the owner's.
    assert!(matches!(c.open(BOB, Some(device)), Err(Error::Refused)));
    // Without any ticket.
    let no_ticket = c.sealed.open(
        Unlock {
            device: Some(device),
            session: None,
            ticket: None,
            release: None,
            passkey: None,
        },
        |s, req| ask_server(&c.r, s, req),
    );
    assert!(matches!(no_ticket, Err(Error::Refused)));
}

fn delegated_tickets(c: &VaultCase) {
    let device = &c.device;
    let policy = &c.policy;
    // Delegated tickets: allowed by default, refused or limited by policy.
    let via = "alice@EXAMPLE.TEST via host/vm1.example.test@EXAMPLE.TEST";
    assert!(c.open(via, Some(device)).is_ok());
    set_policy(
        c,
        vault::Policy {
            ticket_delegation: TicketDelegation::Refuse,
            ..policy.clone()
        },
    );
    assert!(c.open(via, Some(device)).is_err());
    assert!(c.open(ALICE, Some(device)).is_ok());
    set_policy(
        c,
        vault::Policy {
            ticket_delegation: TicketDelegation::Via(vec![
                "host/vm1.example.test@EXAMPLE.TEST".into(),
            ]),
            ..policy.clone()
        },
    );
    assert!(c.open(via, Some(device)).is_ok());
    let elsewhere = "alice@EXAMPLE.TEST via host/vm2.example.test@EXAMPLE.TEST";
    assert!(c.open(elsewhere, Some(device)).is_err());
    // Only a principal whose lease is running, with ticket.leased.
    set_policy(
        c,
        vault::Policy {
            ticket_leased: true,
            ..policy.clone()
        },
    );
    assert!(c.open(ALICE, Some(device)).is_err(), "not leased");
    let now = tang_pqc::unix_seconds(std::time::SystemTime::now());
    c.r.dir.leases.borrow_mut().insert(ALICE.into(), now + 3600);
    assert!(c.open(ALICE, Some(device)).is_ok());
    c.r.dir.leases.borrow_mut().insert(ALICE.into(), now - 1);
    assert!(c.open(ALICE, Some(device)).is_err(), "the lease ended");
    c.r.dir.leases.borrow_mut().clear();
    // A level the device does not have.
    set_policy(
        c,
        vault::Policy {
            factors: Factors {
                device: Some(Level::HardwareBound),
                ..policy.factors.clone()
            },
            ..policy.clone()
        },
    );
    assert!(c.open(ALICE, Some(device)).is_err());
    set_policy(c, policy.clone());
}

fn bobs_vault_cannot_release(c: &VaultCase) {
    let r = &c.r;
    let adv = c.adv();
    let anchors = &c.anchors;
    let device = &c.device;
    let policy = &c.policy;
    let sealed = &c.sealed;
    let id = c.id;
    // Bob's vault cannot release Alice's binding, even under his policy.
    let bobs = vault_op(
        r,
        adv,
        BOB,
        &VaultOp::Create {
            name: "personal".into(),
            policy: policy.clone(),
        },
    )
    .unwrap();
    let bob_vault = bobs[0]
        .verify(REALM, anchors, &Policy::default())
        .unwrap()
        .vault()
        .id;
    let mut seen = Vec::new();
    sealed
        .open(
            Unlock {
                device: Some(device),
                session: None,
                ticket: Some(&mut |_: &str, cb: &[u8; 32]| Some(gss_token(ALICE, cb))),
                release: None,
                passkey: None,
            },
            |s, req| {
                seen.push(req.clone());
                ask_server(&c.r, s, req)
            },
        )
        .unwrap();
    let theirs = renamed(&seen[0], &BOB.parse().unwrap(), &bob_vault);
    assert!(r.servers[0].recover(&theirs, &r.dir).is_err());
    // "personal" names Bob's own vault when Bob asks: Alice's is not his.
    let shown = vault_op(
        r,
        adv,
        BOB,
        &VaultOp::Show {
            name: "personal".into(),
        },
    )
    .unwrap();
    let shown = shown[0].verify(REALM, anchors, &Policy::default()).unwrap();
    assert_ne!(shown.vault().id, id);
}

fn devices_and_revocation(c: &VaultCase) {
    let r = &c.r;
    let adv = c.adv();
    let device = &c.device;
    // Removing the device, locking the owner and revoking the vault each
    // stop unlocks.
    let device_id = device.public().kid().to_string();
    vault_op(
        r,
        adv,
        ALICE,
        &VaultOp::RemoveDevice {
            name: "personal".into(),
            id: device_id,
        },
    )
    .unwrap();
    assert!(c.open(ALICE, Some(device)).is_err());
    vault_op(r, adv, ALICE, &add_device_op("personal", device)).unwrap();
    assert!(c.open(ALICE, Some(device)).is_ok());
    r.dir.disabled.borrow_mut().insert(ALICE.into());
    assert!(c.open(ALICE, Some(device)).is_err());
    r.dir.disabled.borrow_mut().clear();
    vault_op(
        r,
        adv,
        ALICE,
        &VaultOp::Revoke {
            name: "personal".into(),
        },
    )
    .unwrap();
    assert!(c.open(ALICE, Some(device)).is_err());
    let listed = vault_op(r, adv, ALICE, &VaultOp::List).unwrap();
    assert_eq!(listed.len(), 1);
}

#[test]
fn user_vault_seals_and_opens_under_its_policy() {
    let c = vault_case();
    alice_opens_her_file(&c);
    delegated_tickets(&c);
    bobs_vault_cannot_release(&c);
    devices_and_revocation(&c);
}

/// Run a vault operation as `caller` and keep the whole reply.
/// A ledger over an in-memory log, as the daemon keeps one on disk.
#[derive(Debug)]
struct MemoryLedger {
    log: Mutex<(Log, Vec<Leaf>, Vec<tlog::Opening>)>,
}

impl MemoryLedger {
    /// The test servers sign with ML-DSA-65, so their logs are SHA-256.
    fn new(server: &str) -> Self {
        let id = LogId::of(REALM, server, TreeHash::Sha256).unwrap();
        Self {
            log: Mutex::new((Log::new(id), Vec::new(), Vec::new())),
        }
    }

    fn leaves(&self) -> Vec<Leaf> {
        self.log.lock().unwrap().1.clone()
    }

    /// The openings the server keeps beside the public leaves.
    fn openings(&self) -> Vec<tlog::Opening> {
        self.log.lock().unwrap().2.clone()
    }

    fn head(&self) -> (Head, Log) {
        let log = self.log.lock().unwrap().0.clone();
        (log.head(now()).unwrap(), log)
    }
}

impl Ledger for MemoryLedger {
    fn append(&self, opening: tlog::Opening) -> Result<Option<Appended>, DirectoryError> {
        let leaf = opening.leaf(TreeHash::Sha256)?;
        let mut log = self.log.lock().unwrap();
        let index = log.0.append(&leaf)?;
        log.1.push(leaf.clone());
        let time = opening.time;
        log.2.push(opening);
        Ok(Some(Appended {
            log: log.0.id(),
            index,
            leaf: leaf.hash()?,
            time,
        }))
    }

    fn signed_head(
        &self,
        key: &SigningKey,
        now: u64,
    ) -> Result<Option<SignedHead>, DirectoryError> {
        let log = self.log.lock().unwrap();
        if log.0.size() == 0 {
            return Ok(None);
        }
        Ok(Some(SignedHead::issue(key, log.0.head(now)?)?))
    }

    fn find(
        &self,
        subject: &[u8],
        from: u64,
        size: u64,
        max: usize,
    ) -> Result<Vec<tlog::Entry>, DirectoryError> {
        let log = self.log.lock().unwrap();
        let size = usize::try_from(size)?;
        let hashes = &log.0.hashes()[..size];
        Ok(log.2[..size]
            .iter()
            .enumerate()
            .skip(usize::try_from(from)?)
            .filter(|(_, o)| o.subject == subject)
            .take(max)
            .map(|(i, o)| tlog::Entry {
                index: i as u64,
                leaf: log.1[i].clone(),
                path: kuipa_enroll::merkle::path(hashes, i).unwrap(),
                opening: Some(o.clone()),
            })
            .collect())
    }
}

/// A `tlog` lookup by `caller` at server 0, checked by the client.
fn tlog_lookup(
    r: &Realm,
    adv: &VerifiedRealm,
    caller: &str,
    query: &tlog::Query,
) -> Result<tlog::Answer, ()> {
    let p = Prepared::new(
        adv,
        Operation::Tlog,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding(caller, &cb))
        .seal(&gss_token(caller, &cb), &[], &query.to_bytes())
        .unwrap();
    let response = r.send(0, Operation::Tlog, &request)?;
    pending
        .finish_tlog(&response, adv, &Policy::default())
        .map_err(|_| ())
}

/// A ledger whose store has failed.
#[derive(Debug)]
struct BrokenLedger;

impl Ledger for BrokenLedger {
    fn append(&self, _: tlog::Opening) -> Result<Option<Appended>, DirectoryError> {
        Err("disk full".into())
    }
}

/// Look `vault`'s entries up from `from` as `who`, with proofs.
fn lookup_entries(
    r: &Realm,
    adv: &VerifiedRealm,
    who: &str,
    vault: &str,
    from: u64,
) -> Result<tlog::Answer, ()> {
    tlog_lookup(
        r,
        adv,
        who,
        &tlog::Query {
            vault: vault.into(),
            from,
        },
    )
}

/// A server whose ledger fails refuses a change, and makes none: the vault
/// stays enabled.
fn ledger_failure_refuses_the_change(r: &mut Realm, adv: &VerifiedRealm, anchors: &[Thumbprint]) {
    // A server whose ledger fails refuses the change, and does not make
    // it: the vault is still enabled.
    let first = r.servers.remove(0).with_ledger(Arc::new(BrokenLedger));
    r.servers.insert(0, first);
    assert!(
        vault_op(
            r,
            adv,
            ALICE,
            &VaultOp::Revoke {
                name: "personal".into()
            }
        )
        .is_err()
    );
    let shown = vault_reply(
        r,
        adv,
        ALICE,
        &VaultOp::Show {
            name: "personal".into(),
        },
    );
    let v = shown.descriptors[0]
        .verify(REALM, anchors, &Policy::default())
        .unwrap();
    assert_eq!(v.vault().state, vault::State::Enabled);
}

/// Opening a sealed file logs the release on the server that answered.
fn opened_file_logs_release(
    r: &Realm,
    advs: &[VerifiedRealm; 2],
    ledger: &MemoryLedger,
    device: &ExchangeKeyPair,
    v: &kuipa_enroll::vault::VerifiedDescriptor,
) {
    // Opening a sealed file logs the release on the server that answered.
    let sealed = SealedVaultFile::seal(v, &[&advs[0], &advs[1]], b"x").unwrap();
    let ask = |s: &str, req: &EscrowRequest| {
        r.servers[usize::from(s == SERVERS[1])]
            .recover(req, &r.dir)
            .ok()
            .map(|a| a.to_bytes())
    };
    let mut ticket = |_: &str, cb: &[u8; 32]| Some(gss_token(ALICE, cb));
    sealed
        .open(
            Unlock {
                device: Some(device),
                session: None,
                ticket: Some(&mut ticket),
                release: None,
                passkey: None,
            },
            ask,
        )
        .unwrap();
    let (leaves, openings) = (ledger.leaves(), ledger.openings());
    let release = openings.last().unwrap();
    assert_eq!(release.kind, tlog::Kind::ESCROW_RELEASE);
    let event = VaultEvent::from_bytes(&release.event).unwrap();
    assert_eq!(event.action, VaultAction::Release);
    let device_id = v.vault().devices[0].id.as_str();
    assert_eq!(event.device.as_deref(), Some(device_id));

    // Every opening is about the vault and opens its leaf; no public leaf
    // names the vault, its owner, the device or the binding released, or
    // says more than the day it was logged.
    for (leaf, opening) in leaves.iter().zip(&openings) {
        assert_eq!(opening.subject, sealed.vault().as_bytes());
        assert!(opening.opens(leaf).unwrap());
        assert_eq!(leaf.time, tlog::public_time(opening.time));
        let bytes = leaf.to_bytes();
        for secret in [
            &b"personal"[..],
            b"alice",
            sealed.vault().as_bytes(),
            device_id.as_bytes(),
            &event.digest,
        ] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        }
    }
}

/// A realm whose first server keeps its log in `ledger`.
fn logged_realm() -> (Realm, Arc<MemoryLedger>) {
    let mut r = realm();
    let ledger = Arc::new(MemoryLedger::new(SERVERS[0]));
    let first = r.servers.remove(0).with_ledger(ledger.clone());
    r.servers.insert(0, first);
    (r, ledger)
}

#[test]
fn vault_events_are_logged_with_receipts() {
    let (mut r, ledger) = logged_realm();
    let advs = [r.verify(0), r.verify(1)];
    let adv = &advs[0];
    let anchors = r.all_anchors();
    let log_key = r.servers[0].keys().signing.public().clone();
    let policy = vault::Policy {
        factors: Factors {
            device: Some(Level::Any),
            ticket: true,
            passkey: false,
        },
        ..vault::Policy::default()
    };
    let device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();

    let created = vault_reply(
        &r,
        adv,
        ALICE,
        &VaultOp::Create {
            name: "personal".into(),
            policy,
        },
    );
    let added = vault_reply(
        &r,
        adv,
        ALICE,
        &VaultOp::AddDevice {
            name: "personal".into(),
            label: "laptop".into(),
            kind: DeviceType::File,
            alg: device.public().alg().id(),
            key: tang_pqc::b64::encode(device.public().as_bytes()),
        },
    );
    // Reads log nothing.
    let shown = vault_reply(
        &r,
        adv,
        ALICE,
        &VaultOp::Show {
            name: "personal".into(),
        },
    );
    assert_eq!(shown.receipts, [] as [kuipa_enroll::tlog::Receipt; 0]);

    // Each change has one receipt, signed by the server and proven by the
    // log's head.
    let (head, log) = ledger.head();
    for (reply, index) in [(&created, 0), (&added, 1)] {
        let [receipt] = reply.receipts.as_slice() else {
            panic!("one receipt per change");
        };
        receipt.verify(&log_key, &Policy::default()).unwrap();
        assert_eq!(receipt.index, index);
        assert!(
            receipt
                .proven_by(&head, &log.inclusion(index).unwrap())
                .unwrap()
        );
    }
    let v = added.descriptors[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap();
    let leaves = ledger.leaves();
    assert_eq!(leaves[0].kind, tlog::Kind::VAULT_POLICY);
    assert_eq!(leaves[1].kind, tlog::Kind::VAULT_DEVICE);
    let event = VaultEvent::from_bytes(&ledger.openings()[1].event).unwrap();
    assert_eq!(event.action, VaultAction::AddDevice);
    assert_eq!(
        event.device.as_deref(),
        Some(v.vault().devices[0].id.as_str())
    );

    opened_file_logs_release(&r, &advs, &ledger, &device, &v);
    owner_looks_up_and_checks_the_openings(&r, adv, &ledger, event);
    ledger_failure_refuses_the_change(&mut r, adv, &anchors);
}

/// The owner looks their vault's entries up, with proofs the client
/// checks against the head and the openings of their leaves; nobody else
/// can, and a lying answer does not verify.
fn owner_looks_up_and_checks_the_openings(
    r: &Realm,
    adv: &VerifiedRealm,
    ledger: &MemoryLedger,
    event: VaultEvent,
) {
    let leaves = ledger.leaves();
    // Pages on with `from`.
    let answer = lookup_entries(r, adv, ALICE, "personal", 0).unwrap();
    assert_eq!(answer.entries.len(), leaves.len());
    assert_eq!(answer.entries[1].leaf, leaves[1]);
    assert_eq!(
        answer.entries[1].opening.as_ref(),
        Some(&ledger.openings()[1])
    );
    assert_eq!(
        lookup_entries(r, adv, ALICE, "personal", 2)
            .unwrap()
            .entries
            .len(),
        1
    );
    // Nothing is about Alice's principal; Bob cannot look up her vault.
    assert_eq!(
        lookup_entries(r, adv, ALICE, "", 0).unwrap().entries,
        [] as [kuipa_enroll::tlog::Entry; 0]
    );
    assert!(lookup_entries(r, adv, BOB, "personal", 0).is_err());
    // A tampered answer does not verify, nor one whose opening says
    // another event happened.
    let mut forged = answer.clone();
    forged.entries[0].leaf.body.push(0);
    assert!(forged.verify(adv.signer(), &Policy::default()).is_err());
    let mut lying = answer.clone();
    if let Some(o) = lying.entries[1].opening.as_mut() {
        o.event = VaultEvent {
            action: VaultAction::RemoveDevice,
            ..event
        }
        .to_bytes();
    }
    assert!(lying.verify(adv.signer(), &Policy::default()).is_err());
}

fn vault_reply(r: &Realm, adv: &VerifiedRealm, caller: &str, op: &VaultOp) -> vault::Reply {
    let p = Prepared::new(
        adv,
        Operation::Vault,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding(caller, &cb))
        .seal(&gss_token(caller, &cb), &[], &op.to_bytes())
        .unwrap();
    let response = r.send(0, Operation::Vault, &request).unwrap();
    vault::Reply::from_bytes(pending.open(&response).unwrap().as_ref()).unwrap()
}

/// A policy without sessions accepts none, and starting one is refused.
fn sessions_stop_without_policy(
    r: &Realm,
    adv: &VerifiedRealm,
    device: &ExchangeKeyPair,
    policy: &vault::Policy,
    with_session: impl Fn(&ExchangeKeyPair) -> Result<SecretBuf, Error>,
) {
    // A policy without sessions stops accepting them, and starting one.
    vault_op(
        r,
        adv,
        ALICE,
        &VaultOp::SetPolicy {
            name: "s".into(),
            policy: vault::Policy {
                max_unlocks: None,
                sessions: vault::Sessions::default(),
                ..policy.clone()
            },
        },
    )
    .unwrap();
    assert!(with_session(device).is_err());
    let p = Prepared::new(
        adv,
        Operation::Vault,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let op = VaultOp::Unlock {
        name: "s".into(),
        device: device.public().kid().to_string(),
        offline: false,
        passkey: None,
    };
    let (request, _) = p
        .with_kerberos(fake_binding(ALICE, &cb))
        .seal(&gss_token(ALICE, &cb), &[], &op.to_bytes())
        .unwrap();
    assert!(r.send(0, Operation::Vault, &request).is_err());
}

/// A session stands in for the ticket, for its own device only, and the
/// vault counts its releases against the limit.
fn session_limit_counts_releases(
    r: &Realm,
    adv: &VerifiedRealm,
    anchors: &[Thumbprint],
    device: &ExchangeKeyPair,
    other: &ExchangeKeyPair,
    with_session: &dyn Fn(&ExchangeKeyPair) -> Result<SecretBuf, Error>,
) {
    // The session stands in for the ticket, for its own device only.
    assert_eq!(with_session(device).unwrap().as_ref(), b"s");
    assert!(with_session(other).is_err());
    // Two more releases reach the limit; the third is refused, and the
    // vault reports what was counted.
    assert!(with_session(device).is_ok());
    assert!(with_session(device).is_ok());
    assert!(matches!(with_session(device), Err(Error::Refused)));
    let shown = vault_op(r, adv, ALICE, &VaultOp::Show { name: "s".into() }).unwrap();
    assert_eq!(
        shown[0]
            .verify(REALM, anchors, &Policy::default())
            .unwrap()
            .vault()
            .unlocks,
        3
    );
}

/// A session without the device factor would be a bearer token: refused.
fn bearer_sessions_are_refused(r: &Realm, adv: &VerifiedRealm) {
    // A session without the device factor would be a bearer token.
    let bearer = vault::Policy {
        factors: Factors {
            device: None,
            ticket: true,
            passkey: false,
        },
        sessions: vault::Sessions {
            reauth: Some(600),
            offline: None,
            epoch: None,
        },
        ..vault::Policy::default()
    };
    assert!(
        vault_op(
            r,
            adv,
            ALICE,
            &VaultOp::Create {
                name: "b".into(),
                policy: bearer
            }
        )
        .is_err()
    );
}

#[test]
fn vault_sessions_and_unlock_limits() {
    let r = realm();
    let advs = [r.verify(0), r.verify(1)];
    let adv = &advs[0];
    let anchors = r.all_anchors();
    let device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let other = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let factors = Factors {
        device: Some(Level::Any),
        ticket: true,
        passkey: false,
    };

    bearer_sessions_are_refused(&r, adv);

    let policy = vault::Policy {
        factors,
        max_unlocks: Some(3),
        sessions: vault::Sessions {
            reauth: Some(600),
            offline: None,
            epoch: None,
        },
        ..vault::Policy::default()
    };
    vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::Create {
            name: "s".into(),
            policy: policy.clone(),
        },
    )
    .unwrap();
    for key in [&device, &other] {
        vault_op(
            &r,
            adv,
            ALICE,
            &VaultOp::AddDevice {
                name: "s".into(),
                label: "d".into(),
                kind: DeviceType::File,
                alg: key.public().alg().id(),
                key: tang_pqc::b64::encode(key.public().as_bytes()),
            },
        )
        .unwrap();
    }
    let reply = vault_reply(
        &r,
        adv,
        ALICE,
        &VaultOp::Unlock {
            name: "s".into(),
            device: device.public().kid().to_string(),
            offline: false,
            passkey: None,
        },
    );
    let session = reply.session.unwrap();
    let v = reply.descriptors[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap();
    let sealed = SealedVaultFile::seal(&v, &[&advs[0], &advs[1]], b"s").unwrap();
    let ask = |s: &str, req: &EscrowRequest| {
        let req = EscrowRequest::from_bytes(&req.to_bytes()).unwrap();
        r.servers[usize::from(s == "ipa2.example.test")]
            .recover(&req, &r.dir)
            .ok()
            .map(|a| a.to_bytes())
    };
    let with_session = |key: &ExchangeKeyPair| {
        sealed.open(
            Unlock {
                device: Some(key),
                session: Some(&session),
                ticket: None,
                release: None,
                passkey: None,
            },
            ask,
        )
    };

    session_limit_counts_releases(&r, adv, &anchors, &device, &other, &with_session);

    sessions_stop_without_policy(&r, adv, &device, &policy, with_session);
}

/// The shared vault test's state, as its sections use it.
struct Shared {
    r: Realm,
    advs: [VerifiedRealm; 2],
    anchors: Vec<Thumbprint>,
    alice_key: ExchangeKeyPair,
    bob_key: ExchangeKeyPair,
    carol_key: ExchangeKeyPair,
    v: kuipa_enroll::vault::VerifiedDescriptor,
    sealed: SealedVaultFile,
}

impl Shared {
    /// The advertisement of the first server.
    fn adv(&self) -> &VerifiedRealm {
        &self.advs[0]
    }
}

/// The members of `names`, as a share's members.
fn member_users(names: &[&str]) -> vault::Members {
    vault::Members {
        users: names.iter().map(|&n| n.to_owned()).collect(),
        ..vault::Members::default()
    }
}

/// The members of the group `g`.
fn member_group(g: &str) -> vault::Members {
    vault::Members {
        groups: vec![g.to_owned()],
        ..vault::Members::default()
    }
}

/// Share `name` with `managers` and `members`.
fn share_op(name: &str, managers: vault::Members, members: vault::Members) -> VaultOp {
    VaultOp::Share {
        name: name.into(),
        managers,
        members,
        depositors: vault::Members::default(),
    }
}

/// Unshare `name` from `managers` and `members`.
fn unshare_op(name: &str, managers: vault::Members, members: vault::Members) -> VaultOp {
    VaultOp::Unshare {
        name: name.into(),
        managers,
        members,
        depositors: vault::Members::default(),
    }
}

/// The descriptor `d` verified against `anchors`.
fn verified_descriptor(
    anchors: &[Thumbprint],
    d: &[Descriptor],
) -> kuipa_enroll::vault::VerifiedDescriptor {
    d[0].verify(REALM, anchors, &Policy::default()).unwrap()
}

/// Open `sealed` as `who` with `key`, with the servers' escrow.
fn open_as(
    r: &Realm,
    sealed: &SealedVaultFile,
    who: &'static str,
    key: &ExchangeKeyPair,
) -> Result<SecretBuf, Error> {
    let mut ticket = move |_: &str, cb: &[u8; 32]| Some(gss_token(who, cb));
    sealed.open(
        Unlock {
            device: Some(key as &dyn vault::DeviceKey),
            session: None,
            ticket: Some(&mut ticket),
            release: None,
            passkey: None,
        },
        |s, req| ask_server(r, s, req),
    )
}

/// The shared vault test's fixture: Alice's vault, shared with the dba group
/// and with Carol, and the file she sealed to its members.
fn shared_fixture() -> Shared {
    // Server 0 keeps a log, so removals are seen to be logged.
    let (r, _) = logged_realm();
    let advs = [r.verify(0), r.verify(1)];
    let anchors = r.all_anchors();
    let alice_key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let bob_key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let carol_key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    r.dir
        .groups
        .borrow_mut()
        .insert(BOB.into(), vec!["dba".into()]);

    vault_op(
        &r,
        &advs[0],
        ALICE,
        &VaultOp::Create {
            name: "db".into(),
            policy: vault::Policy {
                factors: Factors {
                    device: Some(Level::Any),
                    ticket: true,
                    passkey: false,
                },
                sessions: vault::Sessions {
                    reauth: Some(600),
                    offline: None,
                    epoch: None,
                },
                ..vault::Policy::default()
            },
        },
    )
    .unwrap();
    vault_op(&r, &advs[0], ALICE, &add_device_op("db", &alice_key)).unwrap();
    // A slash names an owner: no vault is created under one.
    let slashed = VaultOp::Create {
        name: "a/b".into(),
        policy: vault::Policy::default(),
    };
    assert!(vault_op(&r, &advs[0], ALICE, &slashed).is_err());

    // Before it is shared, Bob cannot see it, by either spelling.
    for name in ["alice/db", "alice@EXAMPLE.TEST/db", "db"] {
        assert!(vault_op(&r, &advs[0], BOB, &VaultOp::Show { name: name.into() }).is_err());
    }
    assert!(
        vault_op(
            &r,
            &advs[0],
            BOB,
            &share_op("alice/db", member_users(&[BOB]), member_users(&[]))
        )
        .is_err()
    );

    // Alice shares it with the dba group and with Carol by name.
    let shared = vault_op(
        &r,
        &advs[0],
        ALICE,
        &share_op("db", vault::Members::default(), {
            let mut m = member_group("dba");
            m.users.push("carol".into());
            m
        }),
    )
    .unwrap();
    let v = verified_descriptor(&anchors, &shared);
    assert_eq!(v.vault().members.users, [CAROL], "normalized to the realm");
    assert_eq!(v.vault().members.groups, ["dba"]);

    // Bob sees it in his list and registers his own device in it.
    let listed = vault_op(&r, &advs[0], BOB, &VaultOp::List).unwrap();
    assert_eq!(listed.len(), 1);
    vault_op(&r, &advs[0], BOB, &add_device_op("alice/db", &bob_key)).unwrap();
    let v = verified_descriptor(
        &anchors,
        &vault_op(
            &r,
            &advs[0],
            CAROL,
            &add_device_op("alice@EXAMPLE.TEST/db", &carol_key),
        )
        .unwrap(),
    );
    let holders: Vec<_> = v
        .vault()
        .devices
        .iter()
        .map(|d| v.vault().holder(d).to_owned())
        .collect();
    assert_eq!(holders, [ALICE, BOB, CAROL]);
    let sealed = SealedVaultFile::seal(&v, &[&advs[0], &advs[1]], b"db=hunter2\n").unwrap();
    let sealed = SealedVaultFile::from_bytes(&sealed.to_bytes()).unwrap();
    Shared {
        r,
        advs,
        anchors,
        alice_key,
        bob_key,
        carol_key,
        v,
        sealed,
    }
}

fn members_not_managers(c: &Shared) {
    let v = &c.v;
    let r = &c.r;
    let adv = c.adv();
    let alice_key = &c.alice_key;
    // Members are not managers: no policy, sharing, revoking or other
    // members' devices.
    let alices_device = alice_key.public().kid().to_string();
    for op in [
        VaultOp::SetPolicy {
            name: "alice/db".into(),
            policy: v.vault().policy.clone(),
        },
        share_op(
            "alice/db",
            vault::Members::default(),
            member_users(&["eve"]),
        ),
        unshare_op(
            "alice/db",
            vault::Members::default(),
            member_users(&["carol"]),
        ),
        VaultOp::Revoke {
            name: "alice/db".into(),
        },
        VaultOp::RemoveDevice {
            name: "alice/db".into(),
            id: alices_device.clone(),
        },
    ] {
        assert!(vault_op(r, adv, BOB, &op).is_err(), "{op:?}");
    }
}

/// Any member seals to every member's device; each opens with their own
/// device and ticket, and only so.
fn members_open_with_their_own_devices(c: &Shared) {
    let r = &c.r;
    let alice_key = &c.alice_key;
    let bob_key = &c.bob_key;
    let carol_key = &c.carol_key;
    let sealed = &c.sealed;
    assert_eq!(sealed.devices().len(), 3);
    assert_eq!(sealed.principal().to_string(), ALICE, "P is the owner");
    for (who, key) in [(ALICE, &alice_key), (BOB, &bob_key), (CAROL, &carol_key)] {
        assert_eq!(
            open_as(r, sealed, who, key).unwrap().as_ref(),
            b"db=hunter2\n",
            "{who}"
        );
    }
    assert!(
        open_as(r, sealed, BOB, alice_key).is_err(),
        "Alice's device, Bob's ticket"
    );
    assert!(
        open_as(r, sealed, ALICE, bob_key).is_err(),
        "Bob's device, Alice's ticket"
    );
    assert!(open_as(r, sealed, "eve@EXAMPLE.TEST", bob_key).is_err());
}

fn members_open_and_membership(c: &Shared) {
    let alices_device = c.alice_key.public().kid().to_string();
    let r = &c.r;
    let adv = c.adv();
    let alice_key = &c.alice_key;
    let bob_key = &c.bob_key;
    let carol_key = &c.carol_key;
    let sealed = &c.sealed;
    // A session is the member's own, for their own device.
    let bob_device = bob_key.public().kid().to_string();
    let unlock = |device: &str| VaultOp::Unlock {
        name: "alice/db".into(),
        device: device.into(),
        offline: false,
        passkey: None,
    };
    let reply = vault_reply(r, adv, BOB, &unlock(&bob_device));
    let session = reply.session.unwrap();
    let in_session = |key: &ExchangeKeyPair| {
        sealed.open(
            Unlock {
                device: Some(key),
                session: Some(&session),
                ticket: None,
                release: None,
                passkey: None,
            },
            |s, req| ask_server(r, s, req),
        )
    };
    assert!(in_session(bob_key).is_ok());
    assert!(in_session(alice_key).is_err());
    assert!(vault_op(r, adv, BOB, &unlock(&alices_device)).is_err());

    // Membership is the directory's: out of the group, Bob opens nothing,
    // in or out of his session; back in, he does again.
    r.dir.groups.borrow_mut().remove(BOB);
    assert!(open_as(r, sealed, BOB, bob_key).is_err());
    assert!(in_session(bob_key).is_err());
    assert_eq!(vault_op(r, adv, BOB, &VaultOp::List).unwrap(), Vec::new());
    // His device goes at the next vault operation anyone makes, even a
    // read, and is logged as a removal.
    let shown = vault_reply(r, adv, ALICE, &VaultOp::Show { name: "db".into() });
    let v = verified_descriptor(&c.anchors, &shown.descriptors);
    let holders: Vec<_> = v
        .vault()
        .devices
        .iter()
        .map(|d| v.vault().holder(d))
        .collect();
    assert_eq!(holders, [ALICE, CAROL]);
    assert_eq!(shown.receipts.len(), 1, "one device removal logged");
    r.dir
        .groups
        .borrow_mut()
        .insert(BOB.into(), vec!["dba".into()]);
    assert!(
        open_as(r, sealed, BOB, bob_key).is_err(),
        "no device any more"
    );
    // Back in the group, he registers it again; the file has its slot.
    vault_op(r, adv, BOB, &add_device_op("alice/db", bob_key)).unwrap();
    assert!(open_as(r, sealed, BOB, bob_key).is_ok());
    // A disabled member is refused; the others are not.
    r.dir.disabled.borrow_mut().insert(BOB.into());
    assert!(open_as(r, sealed, BOB, bob_key).is_err());
    assert!(open_as(r, sealed, CAROL, carol_key).is_ok());
    r.dir.disabled.borrow_mut().remove(BOB);

    // Carol may leave, but not remove anyone else.
    assert!(
        vault_op(
            r,
            adv,
            CAROL,
            &unshare_op("alice/db", vault::Members::default(), member_group("dba"))
        )
        .is_err()
    );
    let left = verified_descriptor(
        &c.anchors,
        &vault_op(
            r,
            adv,
            CAROL,
            &unshare_op(
                "alice/db",
                vault::Members::default(),
                member_users(&["carol"]),
            ),
        )
        .unwrap(),
    );
    assert_eq!(left.vault().members.users, Vec::<String>::new());
    assert_eq!(left.vault().devices.len(), 2, "her device went with her");
    assert!(open_as(r, sealed, CAROL, carol_key).is_err());
}

fn managers_share_and_unshare(c: &Shared) {
    let r = &c.r;
    let adv = c.adv();
    let alice_key = &c.alice_key;
    let bob_key = &c.bob_key;
    let sealed = &c.sealed;
    // Bob made a manager can share and unshare; dropping the group drops
    // his membership but not his management, so his device stays.
    vault_op(
        r,
        adv,
        ALICE,
        &share_op("db", member_users(&["bob"]), vault::Members::default()),
    )
    .unwrap();
    vault_op(
        r,
        adv,
        BOB,
        &share_op(
            "alice/db",
            vault::Members::default(),
            member_users(&["carol"]),
        ),
    )
    .unwrap();
    let v = verified_descriptor(
        &c.anchors,
        &vault_op(
            r,
            adv,
            BOB,
            &unshare_op("alice/db", vault::Members::default(), member_group("dba")),
        )
        .unwrap(),
    );
    assert_eq!(v.vault().managers.users, [BOB]);
    assert_eq!(v.vault().members.users, [CAROL]);
    assert_eq!(v.vault().devices.len(), 2);
    assert!(open_as(r, sealed, BOB, bob_key).is_ok());
    // Removed as manager, his device goes, and with it his files.
    let v = verified_descriptor(
        &c.anchors,
        &vault_op(
            r,
            adv,
            ALICE,
            &unshare_op("db", member_users(&["bob"]), vault::Members::default()),
        )
        .unwrap(),
    );
    assert!(v.vault().managers.is_empty());
    assert_eq!(v.vault().devices.len(), 1);
    assert!(open_as(r, sealed, BOB, bob_key).is_err());
    assert!(open_as(r, sealed, ALICE, alice_key).is_ok());
}

fn realm_caps_sharing(c: &Shared) {
    let v = &c.v;
    let r = &c.r;
    let adv = c.adv();
    // The realm caps who may share a vault; 0 keeps vaults to their owners.
    r.dir.limits.borrow_mut().max_members = 1;
    assert!(
        vault_op(
            r,
            adv,
            ALICE,
            &share_op("db", vault::Members::default(), member_users(&["dave"]))
        )
        .is_err()
    );
    r.dir.limits.borrow_mut().max_members = 0;
    let lonely = VaultOp::Create {
        name: "lonely".into(),
        policy: v.vault().policy.clone(),
    };
    vault_op(r, adv, ALICE, &lonely).unwrap();
    assert!(
        vault_op(
            r,
            adv,
            ALICE,
            &share_op("lonely", vault::Members::default(), member_users(&["bob"]))
        )
        .is_err()
    );
}

/// Releases of a user vault are limited by opener, not by `P`: a member
/// out of allowance does not stop the owner.
fn openers_have_their_own_allowance(c: &Shared) {
    let r = &c.r;
    let open = |who: &'static str, key: &ExchangeKeyPair| {
        let mut ticket = move |_: &str, cb: &[u8; 32]| Some(gss_token(who, cb));
        c.sealed.open(
            Unlock {
                device: Some(key as &dyn vault::DeviceKey),
                session: None,
                ticket: Some(&mut ticket),
                release: None,
                passkey: None,
            },
            |s, req| {
                let req = EscrowRequest::from_bytes(&req.to_bytes()).unwrap();
                let server = &r.servers[usize::from(s == "ipa2.example.test")];
                assert!(!server.is_machine_request(&req), "P names the owner");
                server
                    .recover_admitted(&req, &r.dir, &|opener| opener.to_string() != BOB)
                    .ok()
                    .map(|a| a.to_bytes())
            },
        )
    };
    assert!(open(BOB, &c.bob_key).is_err());
    assert!(open(ALICE, &c.alice_key).is_ok());
}

#[test]
fn shared_vaults_open_for_their_members_with_their_own_devices() {
    let c = shared_fixture();
    members_not_managers(&c);
    members_open_with_their_own_devices(&c);
    members_open_and_membership(&c);
    openers_have_their_own_allowance(&c);
    managers_share_and_unshare(&c);
    realm_caps_sharing(&c);
}

#[test]
fn removing_a_member_starts_a_new_offline_epoch() {
    let r = realm();
    let adv = &r.verify(0);
    let anchors = r.all_anchors();
    r.dir.limits.borrow_mut().offline_sessions = true;
    let key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let epochs = |d: &[Descriptor]| {
        d[0].verify(REALM, &anchors, &Policy::default())
            .unwrap()
            .vault()
            .session_keys
            .len()
    };
    let created = vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::Create {
            name: "travel".into(),
            policy: vault::Policy {
                factors: Factors {
                    device: Some(Level::Any),
                    ticket: true,
                    passkey: false,
                },
                sessions: vault::Sessions {
                    reauth: None,
                    offline: Some(3600),
                    epoch: None,
                },
                ..vault::Policy::default()
            },
        },
    )
    .unwrap();
    let members = vault::Members {
        users: vec!["bob".into()],
        ..vault::Members::default()
    };
    let shared = vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::Share {
            name: "travel".into(),
            managers: vault::Members::default(),
            members: members.clone(),
            depositors: vault::Members::default(),
        },
    )
    .unwrap();
    assert_eq!(epochs(&shared), epochs(&created), "sharing keeps the epoch");
    vault_op(
        &r,
        adv,
        BOB,
        &VaultOp::AddDevice {
            name: "alice/travel".into(),
            label: "bob".into(),
            kind: DeviceType::File,
            alg: key.public().alg().id(),
            key: tang_pqc::b64::encode(key.public().as_bytes()),
        },
    )
    .unwrap();
    let removed = vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::Unshare {
            name: "travel".into(),
            managers: vault::Members::default(),
            members,
            depositors: vault::Members::default(),
        },
    )
    .unwrap();
    assert_eq!(epochs(&removed), epochs(&created) + 1);
}

#[test]
fn a_vaults_limits_are_its_owners_by_their_groups() {
    let r = realm();
    let adv = &r.verify(0);
    // The realm: one vault each, and always a device.  Travellers: three
    // vaults, and offline sessions.
    *r.dir.limits.borrow_mut() = serde_json::from_value(serde_json::json!({
        "max_lifetime": 400 * 86_400, "max_vaults": 1, "max_devices": 8,
        "max_reauth": 3600, "without_device": true, "descriptor_age": 86_400,
        "factors": [{ "device": "any" }],
        "groups": [{ "group": "travellers", "priority": 10,
                     "max_vaults": 3, "offline_sessions": true }],
    }))
    .unwrap();
    r.dir
        .groups
        .borrow_mut()
        .insert(BOB.into(), vec!["travellers".into()]);
    let with = |device: bool, offline: bool| vault::Policy {
        factors: Factors {
            device: device.then_some(Level::Any),
            ticket: true,
            passkey: false,
        },
        sessions: vault::Sessions {
            reauth: None,
            offline: offline.then_some(3600),
            epoch: None,
        },
        ..vault::Policy::default()
    };
    let create = |who: &str, name: &str, policy: vault::Policy| {
        vault_op(
            &r,
            adv,
            who,
            &VaultOp::Create {
                name: name.into(),
                policy,
            },
        )
    };

    // Alice has the realm's limits.
    create(ALICE, "a1", with(true, false)).unwrap();
    assert!(create(ALICE, "a2", with(true, false)).is_err(), "one vault");
    let offline = VaultOp::SetPolicy {
        name: "a1".into(),
        policy: with(true, true),
    };
    assert!(
        vault_op(&r, adv, ALICE, &offline).is_err(),
        "no offline sessions"
    );

    // Bob, a traveller, has his group's, and the realm's factor rule.
    assert!(
        create(BOB, "b0", with(false, false)).is_err(),
        "ticket alone"
    );
    for name in ["b1", "b2", "b3"] {
        create(BOB, name, with(true, true)).unwrap();
    }
    assert!(
        create(BOB, "b4", with(true, false)).is_err(),
        "three vaults"
    );

    // As a manager of Alice's vault, Bob still gets her limits, not his.
    vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::Share {
            name: "a1".into(),
            managers: vault::Members {
                users: vec!["bob".into()],
                ..vault::Members::default()
            },
            members: vault::Members::default(),
            depositors: vault::Members::default(),
        },
    )
    .unwrap();
    let offline = VaultOp::SetPolicy {
        name: "alice/a1".into(),
        policy: with(true, true),
    };
    assert!(vault_op(&r, adv, BOB, &offline).is_err());
    let within = VaultOp::SetPolicy {
        name: "alice/a1".into(),
        policy: with(true, false),
    };
    vault_op(&r, adv, BOB, &within).unwrap();
}

const DAVE: &str = "dave@EXAMPLE.TEST";

/// Alice's break-glass vault, whose releases two of the on-call group
/// approve, with two files sealed to it.  Bob, Carol, Dave and Alice
/// herself are on call.
struct BreakGlass {
    r: Realm,
    vault: VaultId,
    key: ExchangeKeyPair,
    password: SealedVaultFile,
    recovery: SealedVaultFile,
}

impl BreakGlass {
    fn new() -> Self {
        let r = realm();
        let adv = &r.verify(0);
        for who in [ALICE, BOB, CAROL, DAVE] {
            r.dir
                .groups
                .borrow_mut()
                .insert(who.into(), vec!["oncall".into()]);
        }
        let policy = vault::Policy {
            factors: Factors {
                device: Some(Level::Any),
                ticket: true,
                passkey: false,
            },
            approvals: Some(vault::Approvals {
                m: 2,
                from: vault::Members {
                    groups: vec!["oncall".into()],
                    ..vault::Members::default()
                },
                window: None,
                uses: None,
            }),
            ..vault::Policy::default()
        };
        // Offline sessions open without a server, hence without approvals.
        let offline = vault::Policy {
            sessions: vault::Sessions {
                reauth: None,
                offline: Some(600),
                epoch: None,
            },
            ..policy.clone()
        };
        let create = |name: &str, policy| VaultOp::Create {
            name: name.into(),
            policy,
        };
        assert!(vault_op(&r, adv, ALICE, &create("bad", offline)).is_err());
        vault_op(&r, adv, ALICE, &create("break-glass", policy)).unwrap();
        let key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let added = vault_op(&r, adv, ALICE, &add_device_op("break-glass", &key)).unwrap();
        let v = added[0]
            .verify(REALM, &r.all_anchors(), &Policy::default())
            .unwrap();
        let advs = [r.verify(0), r.verify(1)];
        let seal = |text: &[u8]| {
            let f = SealedVaultFile::seal(&v, &[&advs[0], &advs[1]], text).unwrap();
            SealedVaultFile::from_bytes(&f.to_bytes()).unwrap()
        };
        Self {
            vault: v.vault().id,
            password: seal(b"root password"),
            recovery: seal(b"recovery key"),
            r,
            key,
        }
    }

    /// Open `file` as Alice, with her device and ticket, naming request `id`.
    fn open(&self, file: &SealedVaultFile, id: Option<&str>) -> Result<SecretBuf, Error> {
        let mut ticket = move |_: &str, cb: &[u8; 32]| Some(gss_token(ALICE, cb));
        file.open(
            Unlock {
                device: Some(&self.key as &dyn vault::DeviceKey),
                session: None,
                ticket: Some(&mut ticket),
                release: id.map(|i| vault::ReleaseRequest::id_bytes(i).unwrap()),
                passkey: None,
            },
            |s, req| ask_server(&self.r, s, req),
        )
    }

    /// The request op for `file`, as `name` names the vault.
    fn request_op(name: &str, file: &SealedVaultFile) -> VaultOp {
        VaultOp::Request {
            name: name.into(),
            bindings: file
                .bindings()
                .unwrap()
                .iter()
                .map(vault::binding_hex)
                .collect(),
            reason: "INC-1: the database is down".into(),
        }
    }

    /// Alice asks for the release of `file`; the request's id.
    fn request(&self, file: &SealedVaultFile) -> String {
        let reply = vault_reply(
            &self.r,
            &self.r.verify(0),
            ALICE,
            &Self::request_op("break-glass", file),
        );
        reply.requests[0].id.clone()
    }

    /// `who` approves, or with `deny` denies, request `id`.
    fn decide(&self, who: &str, id: &str, deny: bool) -> Result<Vec<Descriptor>, ()> {
        let (name, id) = ("alice/break-glass".to_owned(), id.to_owned());
        let op = if deny {
            VaultOp::Deny { name, id }
        } else {
            VaultOp::Approve { name, id }
        };
        vault_op(&self.r, &self.r.verify(0), who, &op)
    }
}

/// Approvals count once each, never the requester's, and an approved
/// request covers one release of the files it names.
fn approvals_count_others_once(c: &BreakGlass) {
    let (password, recovery) = (&c.password, &c.recovery);
    // Without a request, the factors are not enough.
    assert!(c.open(password, None).is_err());
    let id = c.request(password);
    assert!(c.open(password, Some(&id)).is_err(), "no approvals yet");
    // Alice is on call, but her own approval does not count; Eve is not.
    assert!(c.decide(ALICE, &id, false).is_err());
    assert!(c.decide("eve@EXAMPLE.TEST", &id, false).is_err());
    c.decide(BOB, &id, false).unwrap();
    assert!(c.decide(BOB, &id, false).is_err(), "once each");
    assert!(c.open(password, Some(&id)).is_err(), "one of two");
    c.decide(CAROL, &id, false).unwrap();
    assert_eq!(
        c.open(password, Some(&id)).unwrap().as_ref(),
        b"root password"
    );
    assert!(c.open(password, Some(&id)).is_err(), "used up");
    assert!(c.open(recovery, Some(&id)).is_err(), "another file");
    // Dave approves for the vault without being its member: he sees the
    // request pending.
    let pending = vault_reply(&c.r, &c.r.verify(0), DAVE, &VaultOp::Pending { name: None });
    assert_eq!(pending.requests.len(), 1);
    assert_eq!(pending.requests[0].approvals.len(), 2);
}

/// Approvers count while they are on call and not locked.
fn approvers_count_while_admitted(c: &BreakGlass) {
    let id = c.request(&c.recovery);
    c.decide(BOB, &id, false).unwrap();
    c.decide(CAROL, &id, false).unwrap();
    c.r.dir.groups.borrow_mut().remove(CAROL);
    assert!(c.open(&c.recovery, Some(&id)).is_err(), "Carol left");
    c.r.dir.disabled.borrow_mut().insert(BOB.into());
    c.decide(DAVE, &id, false).unwrap();
    assert!(c.open(&c.recovery, Some(&id)).is_err(), "Bob is locked");
    c.r.dir.disabled.borrow_mut().remove(BOB);
    assert_eq!(
        c.open(&c.recovery, Some(&id)).unwrap().as_ref(),
        b"recovery key"
    );
}

/// A denial, or the end of its window, ends a request; and only those with
/// a part in the vault ask.
fn requests_end(c: &BreakGlass) {
    let id = c.request(&c.recovery);
    c.decide(BOB, &id, true).unwrap();
    assert!(c.decide(DAVE, &id, false).is_err());
    assert!(c.open(&c.recovery, Some(&id)).is_err(), "denied");
    let id = c.request(&c.recovery);
    c.decide(BOB, &id, false).unwrap();
    c.decide(DAVE, &id, false).unwrap();
    c.r.dir
        .releases
        .borrow_mut()
        .get_mut(&(c.vault, id.clone()))
        .unwrap()
        .not_after = 1;
    assert!(c.open(&c.recovery, Some(&id)).is_err(), "expired");
    let by_bob = BreakGlass::request_op("alice/break-glass", &c.recovery);
    assert!(vault_op(&c.r, &c.r.verify(0), BOB, &by_bob).is_err());
}

#[test]
fn releases_wait_for_approvals_from_others() {
    let c = BreakGlass::new();
    approvals_count_others_once(&c);
    approvers_count_while_admitted(&c);
    requests_end(&c);
}

#[test]
fn device_keys_are_escrowed_for_their_holders_and_logged() {
    let (r, _) = logged_realm();
    let adv = &r.verify(0);
    let key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let device = key.public().kid().to_string();
    let escrow = |who: &str, device: &str, blob: &[u8]| {
        vault_reply_at(
            &r,
            0,
            adv,
            who,
            &VaultOp::EscrowCode {
                device: device.into(),
                blob: tang_pqc::b64::encode(blob),
            },
        )
    };
    // Only a device the caller holds in a vault.
    assert!(escrow(ALICE, &device, b"blob").is_err());
    vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::Create {
            name: "notes".into(),
            policy: vault::Policy {
                factors: Factors {
                    device: Some(Level::Any),
                    ticket: true,
                    passkey: false,
                },
                ..vault::Policy::default()
            },
        },
    )
    .unwrap();
    vault_op(&r, adv, ALICE, &add_device_op("notes", &key)).unwrap();
    assert!(escrow(BOB, &device, b"blob").is_err(), "not Bob's device");
    assert!(escrow(ALICE, &device, b"").is_err(), "empty");
    let big = vec![7u8; vault::MAX_ESCROW_BLOB + 1];
    assert!(escrow(ALICE, &device, &big).is_err(), "too large");

    // Kept, replaced by the next, and logged in the vault of the device.
    let first = escrow(ALICE, &device, b"first").unwrap();
    assert_eq!(first.escrows.len(), 1);
    assert_eq!(first.receipts.len(), 1, "logged");
    escrow(ALICE, &device, b"second").unwrap();
    let fetched = vault_reply_at(&r, 0, adv, ALICE, &VaultOp::RecoverCode).unwrap();
    assert_eq!(fetched.escrows.len(), 1);
    assert_eq!(
        tang_pqc::b64::decode(&fetched.escrows[0].blob).unwrap(),
        b"second"
    );
    assert_eq!(fetched.receipts.len(), 1, "the fetch is logged too");
    // Bob fetches only his own: none.
    let bobs = vault_reply_at(&r, 0, adv, BOB, &VaultOp::RecoverCode).unwrap();
    assert_eq!(bobs.escrows, Vec::new());
}

/// Alice's helpdesk vault for disks: Carol a member, Bob a depositor.
struct Disks {
    r: Realm,
    carol_key: ExchangeKeyPair,
    other: VerifiedDescriptor,
}

impl Disks {
    fn new() -> Self {
        let (r, _) = logged_realm();
        let adv = &r.verify(0);
        let policy = vault::Policy {
            factors: Factors {
                device: Some(Level::Any),
                ticket: true,
                passkey: false,
            },
            sealing: vault::Sealing::Registered,
            ..vault::Policy::default()
        };
        for name in ["disks", "other"] {
            let op = VaultOp::Create {
                name: name.into(),
                policy: policy.clone(),
            };
            vault_op(&r, adv, ALICE, &op).unwrap();
        }
        let alice_key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        vault_op(&r, adv, ALICE, &add_device_op("disks", &alice_key)).unwrap();
        let other = vault_op(&r, adv, ALICE, &add_device_op("other", &alice_key)).unwrap();
        let other = other[0]
            .verify(REALM, &r.all_anchors(), &Policy::default())
            .unwrap();
        let shared = VaultOp::Share {
            name: "disks".into(),
            managers: vault::Members::default(),
            members: member_users(&["carol"]),
            depositors: member_users(&["bob"]),
        };
        vault_op(&r, adv, ALICE, &shared).unwrap();
        let carol_key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        vault_op(&r, adv, CAROL, &add_device_op("alice/disks", &carol_key)).unwrap();
        Self {
            r,
            carol_key,
            other,
        }
    }

    /// `who`'s view of the vault, to seal with.
    fn descriptor(&self, who: &str) -> VerifiedDescriptor {
        let shown = vault_op(
            &self.r,
            &self.r.verify(0),
            who,
            &VaultOp::Show {
                name: "alice/disks".into(),
            },
        )
        .unwrap();
        shown[0]
            .verify(REALM, &self.r.all_anchors(), &Policy::default())
            .unwrap()
    }

    fn seal(&self, d: &VerifiedDescriptor, text: &[u8]) -> SealedVaultFile {
        let advs = [self.r.verify(0), self.r.verify(1)];
        SealedVaultFile::seal(d, &[&advs[0], &advs[1]], text).unwrap()
    }

    fn op(&self, who: &str, op: &VaultOp) -> Result<vault::Reply, ()> {
        vault_reply_at(&self.r, 0, &self.r.verify(0), who, op)
    }

    /// Bob deposits `file` as the LUKS key of volume `uuid`.
    fn deposit(&self, file: &SealedVaultFile, uuid: &str) -> Result<vault::Reply, ()> {
        self.op(
            BOB,
            &VaultOp::Deposit {
                name: "alice/disks".into(),
                kind: vault::DepositKind::Luks,
                subject: [("uuid".to_owned(), uuid.to_owned())].into(),
                sealed: tang_pqc::b64::encode(&file.to_bytes()),
            },
        )
    }

    /// The deposits `who` lists.
    fn listed(&self, who: &str) -> Vec<vault::Deposit> {
        let name = "alice/disks".into();
        self.op(who, &VaultOp::Deposits { name }).unwrap().deposits
    }

    /// Deposit `id`'s file, as Carol fetches it.
    fn fetched(&self, id: &str) -> SealedVaultFile {
        let fetch = VaultOp::FetchDeposit {
            name: "alice/disks".into(),
            id: id.into(),
        };
        let reply = self.op(CAROL, &fetch).unwrap();
        SealedVaultFile::from_bytes(&tang_pqc::b64::decode(&reply.deposits[0].sealed).unwrap())
            .unwrap()
    }
}

/// Bob deposits and never opens; Carol finds the deposit and opens it.
fn depositors_deposit_members_open(d: &Disks) {
    let bobs = d.descriptor(BOB);
    let key = d.seal(&bobs, b"luks recovery key");
    let made = d.deposit(&key, "1234").unwrap();
    assert_eq!(made.receipts.len(), 1, "logged");
    let id = made.deposits[0].id.clone();
    assert!(made.deposits[0].sealed.is_empty(), "not sent back");
    // Bob may not open: no device, no registering, no fetching.
    let bob_key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    assert!(d.op(BOB, &add_device_op("alice/disks", &bob_key)).is_err());
    let fetch = VaultOp::FetchDeposit {
        name: "alice/disks".into(),
        id: id.clone(),
    };
    assert!(d.op(BOB, &fetch).is_err());
    assert!(open_as(&d.r, &key, BOB, &bob_key).is_err());
    assert_eq!(d.listed(BOB).len(), 1);
    // Carol, a member, opens the deposited file: the deposit registered it.
    let fetched = d.fetched(&id);
    assert_eq!(
        open_as(&d.r, &fetched, CAROL, &d.carol_key)
            .unwrap()
            .as_ref(),
        b"luks recovery key"
    );
}

/// A deposit of the same kind and subject replaces the last, whose file
/// stops opening; others count against the limit; files sealed to other
/// vaults are refused.
fn deposits_replace_and_are_limited(d: &Disks) {
    let bobs = d.descriptor(BOB);
    let old = d.fetched(&d.listed(CAROL)[0].id);
    let new = d.seal(&bobs, b"new recovery key");
    d.deposit(&new, "1234").unwrap();
    let listed = d.listed(CAROL);
    assert_eq!(listed.len(), 1, "replaced");
    assert!(open_as(&d.r, &old, CAROL, &d.carol_key).is_err(), "retired");
    let fresh = d.fetched(&listed[0].id);
    assert_eq!(
        open_as(&d.r, &fresh, CAROL, &d.carol_key).unwrap().as_ref(),
        b"new recovery key"
    );
    let elsewhere = d.seal(&d.other, b"x");
    assert!(
        d.deposit(&elsewhere, "5678").is_err(),
        "another vault's file"
    );
    d.r.dir.limits.borrow_mut().max_deposits = 1;
    assert!(d.deposit(&new, "5678").is_err(), "one deposit each");
    d.r.dir.limits.borrow_mut().max_deposits = 32;
}

/// Bob retires his own deposits, Carol nobody's; Bob may leave.
fn deposits_retire(d: &Disks) {
    let id = d.listed(BOB)[0].id.clone();
    let retire = |who: &str| {
        let op = VaultOp::RetireDeposit {
            name: "alice/disks".into(),
            id: id.clone(),
        };
        d.op(who, &op)
    };
    assert!(retire(CAROL).is_err(), "not hers, and not a manager");
    retire(BOB).unwrap();
    assert_eq!(d.listed(CAROL), Vec::new());
    let leave = VaultOp::Unshare {
        name: "alice/disks".into(),
        managers: vault::Members::default(),
        members: vault::Members::default(),
        depositors: member_users(&["bob"]),
    };
    d.op(BOB, &leave).unwrap();
    assert!(d.deposit(&d.seal(&d.descriptor(CAROL), b"x"), "9").is_err());
}

#[test]
fn depositors_deposit_and_never_open() {
    let d = Disks::new();
    depositors_deposit_members_open(&d);
    deposits_replace_and_are_limited(&d);
    deposits_retire(&d);
}

/// Carol's escrow vault, which the realm names for device keys and whose
/// depositor Alice is, with deposits required; Alice's vault `notes`.
fn helpdesk_realm() -> Realm {
    let (r, _) = logged_realm();
    let adv = &r.verify(0);
    let policy = vault::Policy {
        factors: Factors {
            device: Some(Level::Any),
            ticket: true,
            passkey: false,
        },
        ..vault::Policy::default()
    };
    for (who, name) in [(CAROL, "escrow"), (ALICE, "notes")] {
        let create = VaultOp::Create {
            name: name.into(),
            policy: policy.clone(),
        };
        vault_op(&r, adv, who, &create).unwrap();
    }
    let carol_key = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    vault_op(&r, adv, CAROL, &add_device_op("escrow", &carol_key)).unwrap();
    let shared = VaultOp::Share {
        name: "escrow".into(),
        managers: vault::Members::default(),
        members: vault::Members::default(),
        depositors: member_users(&["alice"]),
    };
    vault_op(&r, adv, CAROL, &shared).unwrap();
    *r.dir.recovery.borrow_mut() = Some(vault::RecoverySettings {
        device_vault: "carol/escrow".into(),
        required: true,
    });
    r
}

/// Alice's device is registered only once its key is deposited.
fn device_keys_are_deposited_first(r: &Realm, laptop: &ExchangeKeyPair) {
    let adv = &r.verify(0);
    let op = |who: &str, op: &VaultOp| vault_reply_at(r, 0, adv, who, op);
    let settings = op(BOB, &VaultOp::RecoverySettings).unwrap().recovery;
    assert_eq!(settings.unwrap().device_vault, "carol/escrow");
    assert!(
        op(ALICE, &add_device_op("notes", laptop)).is_err(),
        "not deposited"
    );
    let escrow = op(
        ALICE,
        &VaultOp::Show {
            name: "carol/escrow".into(),
        },
    )
    .unwrap();
    let escrow = escrow.descriptors[0]
        .verify(REALM, &r.all_anchors(), &Policy::default())
        .unwrap();
    let advs = [r.verify(0), r.verify(1)];
    let jwk = laptop.to_jwk().unwrap();
    let sealed = SealedVaultFile::seal(&escrow, &[&advs[0], &advs[1]], jwk.as_ref()).unwrap();
    let deposit = VaultOp::Deposit {
        name: "carol/escrow".into(),
        kind: vault::DepositKind::Device,
        subject: [("device".to_owned(), laptop.public().kid().to_string())].into(),
        sealed: tang_pqc::b64::encode(&sealed.to_bytes()),
    };
    op(ALICE, &deposit).unwrap();
    op(ALICE, &add_device_op("notes", laptop)).unwrap();
}

/// Only the helpdesk looks up a user's device and delivers to it, and
/// only to a device the user registered; only that device opens it.
fn the_helpdesk_delivers(r: &Realm, laptop: &ExchangeKeyPair) {
    let adv = &r.verify(0);
    let op = |who: &str, op: &VaultOp| vault_reply_at(r, 0, adv, who, op);
    let id = laptop.public().kid().to_string();
    let key_of = |who: &str, device: &str| {
        let lookup = VaultOp::DeviceKey {
            user: ALICE.into(),
            device: device.into(),
        };
        op(who, &lookup)
    };
    assert!(key_of(BOB, &id).is_err(), "not the helpdesk");
    assert!(key_of(CAROL, "no-such-device").is_err());
    let found = key_of(CAROL, &id).unwrap().devices;
    assert_eq!(found[0].public().unwrap().kid(), laptop.public().kid());
    let lost = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let blob = vault::seal_delivery(laptop.public(), &lost).unwrap();
    let deliver = |who: &str, blob: &[u8]| {
        let delivery = VaultOp::Deliver {
            user: ALICE.into(),
            device: id.clone(),
            blob: tang_pqc::b64::encode(blob),
        };
        op(who, &delivery)
    };
    assert!(deliver(BOB, &blob).is_err(), "not the helpdesk");
    assert!(deliver(CAROL, b"not a delivery").is_err());
    let delivered = deliver(CAROL, &blob).unwrap();
    assert_eq!(delivered.receipts.len(), 1, "logged in Alice's vault");
    let escrows = op(ALICE, &VaultOp::RecoverCode).unwrap().escrows;
    let delivery = escrows.iter().find(|e| e.kind == "delivery").unwrap();
    let opened =
        vault::open_delivery(&tang_pqc::b64::decode(&delivery.blob).unwrap(), laptop).unwrap();
    assert_eq!(opened.public().kid(), lost.public().kid());
}

#[test]
fn the_helpdesk_delivers_deposited_device_keys() {
    let r = helpdesk_realm();
    let laptop = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    device_keys_are_deposited_first(&r, &laptop);
    the_helpdesk_delivers(&r, &laptop);
}

/// Run a vault operation as `caller` against server `i`.
fn vault_reply_at(
    r: &Realm,
    i: usize,
    adv: &VerifiedRealm,
    caller: &str,
    op: &VaultOp,
) -> Result<vault::Reply, ()> {
    let p = Prepared::new(
        adv,
        Operation::Vault,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding(caller, &cb))
        .seal(&gss_token(caller, &cb), &[], &op.to_bytes())
        .unwrap();
    let response = r.send(i, Operation::Vault, &request)?;
    vault::Reply::from_bytes(pending.open(&response).map_err(|_| ())?.as_ref()).map_err(|_| ())
}

/// Unlock the travel vault as Alice from server `i`, offline, with `device`.
fn unlock_travel(
    r: &Realm,
    advs: &[VerifiedRealm; 2],
    i: usize,
    device: &ExchangeKeyPair,
) -> Result<vault::Reply, ()> {
    vault_reply_at(
        r,
        i,
        &advs[i],
        ALICE,
        &VaultOp::Unlock {
            name: "travel".into(),
            device: device.public().kid().to_string(),
            offline: true,
            passkey: None,
        },
    )
}

/// The epoch turns: new files use epoch 2, which an offline release from
/// before the turn lacks.
fn the_epoch_turns(
    r: &Realm,
    advs: &[VerifiedRealm; 2],
    anchors: &[Thumbprint],
    show: &VaultOp,
    device: &ExchangeKeyPair,
    vault: &VaultId,
    keys: &[(u64, ExchangeKeyPair)],
) {
    // The epoch turns: new files use epoch 2, which the old release lacks.
    r.dir
        .vaults
        .borrow_mut()
        .get_mut(vault)
        .unwrap()
        .session_keys[0]
        .started -= vault::DEFAULT_EPOCH + 1;
    let turned = vault_reply_at(r, 0, &advs[0], ALICE, show).unwrap();
    let d2 = turned.descriptors[0]
        .verify(REALM, anchors, &Policy::default())
        .unwrap();
    assert_eq!(d2.vault().session_keys.len(), 2);
    let newer = vault::SessionSealedFile::seal(&d2, b"later").unwrap();
    assert_eq!(newer.epoch(), 2);
    assert!(!keys.iter().any(|(e, _)| *e == 2));
    let again = unlock_travel(r, advs, 0, device).unwrap().released.unwrap();
    let keys = again.open(device, vault).unwrap();
    let (_, k2) = keys.iter().find(|(e, _)| *e == 2).unwrap();
    assert_eq!(newer.open(k2, device).unwrap().as_ref(), b"later");

    // Without the realm's permission no offline session starts.
    r.dir.limits.borrow_mut().offline_sessions = false;
    assert!(unlock_travel(r, advs, 0, device).is_err());
}

#[test]
fn offline_sessions_release_epoch_keys_to_the_device() {
    let r = realm();
    let advs = [r.verify(0), r.verify(1)];
    let anchors = r.all_anchors();
    let device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let other = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let policy = vault::Policy {
        factors: Factors {
            device: Some(Level::Any),
            ticket: true,
            passkey: false,
        },
        sessions: vault::Sessions {
            reauth: None,
            offline: Some(3600),
            epoch: None,
        },
        ..vault::Policy::default()
    };
    let create = VaultOp::Create {
        name: "travel".into(),
        policy,
    };
    // The realm allows no offline sessions until an administrator says so.
    assert!(vault_reply_at(&r, 0, &advs[0], ALICE, &create).is_err());
    r.dir.limits.borrow_mut().offline_sessions = true;
    vault_reply_at(&r, 0, &advs[0], ALICE, &create).unwrap();
    vault_reply_at(
        &r,
        0,
        &advs[0],
        ALICE,
        &VaultOp::AddDevice {
            name: "travel".into(),
            label: "laptop".into(),
            kind: DeviceType::File,
            alg: device.public().alg().id(),
            key: tang_pqc::b64::encode(device.public().as_bytes()),
        },
    )
    .unwrap();

    // ipa2 publishes its escrow key on its first operation; ipa1 then seals
    // the epoch key to it too, so ipa2 can release it.
    let show = VaultOp::Show {
        name: "travel".into(),
    };
    vault_reply_at(&r, 1, &advs[1], ALICE, &show).unwrap();
    let shown = vault_reply_at(&r, 0, &advs[0], ALICE, &show).unwrap();
    let d = shown.descriptors[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap();
    assert_eq!(d.vault().session_keys.len(), 1);
    assert!(d.vault().session_keys[0].slots.is_empty(), "public only");
    let stored = r.dir.vaults.borrow()[&d.vault().id].clone();
    assert_eq!(
        stored.session_keys[0].slots.len(),
        2,
        "sealed to both servers"
    );

    let sealed = vault::SessionSealedFile::seal(&d, b"boarding pass").unwrap();
    let sealed = vault::SessionSealedFile::from_bytes(&sealed.to_bytes()).unwrap();
    assert_eq!(sealed.epoch(), 1);

    let released = unlock_travel(&r, &advs, 1, &device)
        .unwrap()
        .released
        .unwrap();
    assert!(
        released.open(&other, &d.vault().id).is_err(),
        "only the device opens it"
    );
    let keys = released.open(&device, &d.vault().id).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        sealed.open(&keys[0].1, &device).unwrap().as_ref(),
        b"boarding pass"
    );
    assert!(
        sealed.open(&keys[0].1, &other).is_err(),
        "the device share too"
    );
    let counted = vault_reply_at(&r, 0, &advs[0], ALICE, &show).unwrap();
    assert_eq!(
        counted.descriptors[0]
            .verify(REALM, &anchors, &Policy::default())
            .unwrap()
            .vault()
            .unlocks,
        1
    );

    the_epoch_turns(&r, &advs, &anchors, &show, &device, &d.vault().id, &keys);
}

#[test]
fn registered_sealing_opens_only_registered_files() {
    let r = realm();
    let advs = [r.verify(0), r.verify(1)];
    let anchors = r.all_anchors();
    let device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let registered = vault::Policy {
        factors: Factors {
            device: Some(Level::Any),
            ticket: false,
            passkey: false,
        },
        sealing: vault::Sealing::Registered,
        ..vault::Policy::default()
    };
    let op = |o: &VaultOp| vault_reply_at(&r, 0, &advs[0], ALICE, o);
    op(&VaultOp::Create {
        name: "r".into(),
        policy: registered.clone(),
    })
    .unwrap();
    let reply = op(&VaultOp::AddDevice {
        name: "r".into(),
        label: "d".into(),
        kind: DeviceType::File,
        alg: device.public().alg().id(),
        key: tang_pqc::b64::encode(device.public().as_bytes()),
    })
    .unwrap();
    let d = reply.descriptors[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap();
    let sealed = SealedVaultFile::seal(&d, &[&advs[0], &advs[1]], b"r").unwrap();
    let hashes: Vec<String> = sealed
        .bindings()
        .unwrap()
        .iter()
        .map(vault::binding_hex)
        .collect();
    let ask = |s: &str, req: &EscrowRequest| {
        let req = EscrowRequest::from_bytes(&req.to_bytes()).unwrap();
        r.servers[usize::from(s == "ipa2.example.test")]
            .recover(&req, &r.dir)
            .ok()
            .map(|a| a.to_bytes())
    };
    let open = || {
        sealed.open(
            Unlock {
                device: Some(&device),
                session: None,
                ticket: None,
                release: None,
                passkey: None,
            },
            ask,
        )
    };
    // Not registered yet: no server opens it.
    assert!(open().is_err());
    let register = |add: &[String], retire: &[String]| {
        op(&VaultOp::Register {
            name: "r".into(),
            add: add.to_vec(),
            retire: retire.to_vec(),
        })
    };
    let shown = register(&hashes, &[]).unwrap();
    assert!(
        shown.descriptors[0]
            .verify(REALM, &anchors, &Policy::default())
            .unwrap()
            .vault()
            .bindings
            .is_empty(),
        "descriptors leave the registered bindings out"
    );
    assert_eq!(open().unwrap().as_ref(), b"r");
    // Retired: no copy of it opens any more.
    register(&[], &hashes).unwrap();
    assert!(open().is_err());
    assert!(register(&["not hex".into()], &[]).is_err());

    // A vault that seals offline does not register.
    op(&VaultOp::Create {
        name: "o".into(),
        policy: vault::Policy {
            sealing: vault::Sealing::Offline,
            ..registered
        },
    })
    .unwrap();
    assert!(
        op(&VaultOp::Register {
            name: "o".into(),
            add: hashes,
            retire: Vec::new(),
        })
        .is_err()
    );
}

#[test]
fn sealed_passwords_are_gone() {
    // Auth type 4 carried a user's password to the server; password joins
    // now get a ticket on the host and use Kerberos (§5.3).
    let r = realm();
    let adv = r.verify(0);
    let (request, _) = Prepared::new(
        &adv,
        Operation::Join,
        HOST,
        AuthType::Otp,
        &Enctype::DEFAULT,
    )
    .unwrap()
    .seal(b"Secret123", &[], &[])
    .unwrap();
    let mut bytes = request.to_bytes();
    let host = HOST.as_bytes();
    let at = bytes.windows(host.len()).position(|w| w == host).unwrap() + host.len();
    assert_eq!(bytes[at], 1, "the auth type byte");
    bytes[at] = 4;
    assert!(Request::from_bytes(Operation::Join, &bytes).is_err());
}

#[test]
fn advertisement_bootstraps_kerberos() {
    let r = realm();
    let adv = r.verify(1);
    assert_eq!(adv.info().pkinit_anchors, vec![CA.to_vec()]);
    let both = Deployment::servers(&["ipa1.example.test".into(), "ipa2.example.test".into()]);
    let conf = adv.krb5_conf("/var/lib/ipa-client/ku/pkinit-anchors.pem", &both);
    // The issuing server first, then the others.
    let first = conf.find("kdc = ipa2.example.test").unwrap();
    let second = conf.find("kdc = ipa1.example.test").unwrap();
    assert!(first < second);
    assert!(conf.contains("dns_lookup_kdc = false"));
    // Told to use only the issuing server: the other is not a KDC either.
    let only = Deployment::servers(&["ipa2.example.test".into()]);
    let conf = adv.krb5_conf("/var/lib/ipa-client/ku/pkinit-anchors.pem", &only);
    assert!(conf.contains("kdc = ipa2.example.test"));
    assert!(!conf.contains("ipa1.example.test"));
}

/// A `keys` fetch (§18.2): the promotion-shaped policy checks and the
/// value's round trip, with the caller's ticket inside the sealed body.
#[test]
fn keys_fetch_follows_the_masters_policy() {
    let r = realm();
    let adv = r.verify(0);
    let dm = kuipa_enroll::keys::KeysFetch {
        namespace: kuipa_enroll::keys::Namespace::Dm,
        nickname: "DMHash".into(),
        alg: None,
    };
    let wrapped = kuipa_enroll::keys::KeysFetch {
        namespace: kuipa_enroll::keys::Namespace::CaWrapped,
        nickname: "lwca-signing".into(),
        alg: Some(kuipa_enroll::keys::WrapAlg::Aes256CbcPad),
    };
    *r.dir.masters.borrow_mut() = vec![SERVERS[0].to_owned()];
    *r.dir.ca_masters.borrow_mut() = vec![SERVERS[0].to_owned()];
    r.dir.key_secrets.borrow_mut().insert(
        (dm.namespace.id(), dm.nickname.clone()),
        b"{\"dmhash\":\"x\"}".to_vec(),
    );
    r.dir.key_secrets.borrow_mut().insert(
        (wrapped.namespace.id(), wrapped.nickname.clone()),
        b"{\"wrapped_key\":\"x\"}".to_vec(),
    );

    let request = |caller: &str, fetch: &kuipa_enroll::keys::KeysFetch| {
        let p = Prepared::new(
            &adv,
            Operation::Keys,
            HOST,
            AuthType::Kerberos,
            &Enctype::DEFAULT,
        )
        .unwrap();
        let cb = p.channel_binding().unwrap();
        p.with_kerberos(fake_binding(caller, &cb))
            .seal(&gss_token(caller, &cb), &[], &fetch.to_bytes().unwrap())
            .unwrap()
    };

    // A server in cn=masters fetches dm/ra/ca; the answer round trips.
    let server = format!("host/{}@{REALM}", SERVERS[0]);
    let (req, pending) = request(&server, &dm);
    let response = r.send(0, Operation::Keys, &req).unwrap();
    let answer = pending.finish_keys(&response, &adv).unwrap();
    assert_eq!(answer.value, b"{\"dmhash\":\"x\"}");

    // A host outside cn=masters — a client, or a removed server — is
    // refused, before any secret is touched.
    let client = Principal::host(HOST, REALM).to_string();
    let (req, _) = request(&client, &dm);
    assert!(r.send(0, Operation::Keys, &req).is_err());

    // dogtag/ of a CA server fetches the wrapped keys; of a non-CA
    // server it may not, and it may never fetch dm.
    let dogtag = format!("dogtag/{}@{REALM}", SERVERS[0]);
    let (req, pending) = request(&dogtag, &wrapped);
    let response = r.send(0, Operation::Keys, &req).unwrap();
    assert_eq!(
        pending.finish_keys(&response, &adv).unwrap().value,
        b"{\"wrapped_key\":\"x\"}"
    );
    let (req, _) = request(&dogtag, &dm);
    assert!(r.send(0, Operation::Keys, &req).is_err());
    let other_dogtag = format!("dogtag/{}@{REALM}", SERVERS[1]);
    let (req, _) = request(&other_dogtag, &wrapped);
    assert!(r.send(0, Operation::Keys, &req).is_err());

    // A user's ticket may not fetch anything.
    let (req, _) = request("admin@EXAMPLE.TEST", &dm);
    assert!(r.send(0, Operation::Keys, &req).is_err());

    // An unknown nickname is refused.
    let missing = kuipa_enroll::keys::KeysFetch {
        namespace: kuipa_enroll::keys::Namespace::Dm,
        nickname: "no-such".into(),
        alg: None,
    };
    let (req, _) = request(&server, &missing);
    assert!(r.send(0, Operation::Keys, &req).is_err());

    // A wrap algorithm outside ca_wrapped does not even parse.
    assert!(
        kuipa_enroll::keys::KeysFetch {
            namespace: kuipa_enroll::keys::Namespace::Ca,
            nickname: "x".into(),
            alg: Some(kuipa_enroll::keys::WrapAlg::Aes256CbcPad),
        }
        .to_bytes()
        .is_err()
    );
}

/// A signing request by `caller` at server 0, finished by the client.
fn sign_as(
    r: &Realm,
    adv: &VerifiedRealm,
    caller: &str,
    asked: &kuipa_enroll::sign::Request,
) -> Result<Vec<kuipa_enroll::sign::Bundle>, ()> {
    let p = Prepared::new(
        adv,
        Operation::Sign,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let (request, pending) = p
        .with_kerberos(fake_binding(caller, &cb))
        .seal(&gss_token(caller, &cb), &[], &asked.to_bytes().unwrap())
        .unwrap();
    let response = r.send(0, Operation::Sign, &request)?;
    pending.finish_sign(&response, adv, asked).map_err(|_| ())
}

#[test]
fn signing_is_stated_logged_and_bound_by_policy() {
    use kuipa_enroll::sign::{Digest, DigestAlg, Request as SignRequest, Signers};

    let mut r = realm();
    let asked = SignRequest {
        purpose: "blob".into(),
        digests: vec![
            Digest::of(DigestAlg::Sha256, b"release-1.0.tar").unwrap(),
            Digest::of(DigestAlg::Sha512, b"release-1.0.sig").unwrap(),
        ],
    };
    let adv = r.verify(0);
    // No log, no statement.
    r.dir.sign_policy.borrow_mut().purposes.insert(
        "blob".into(),
        Signers {
            users: vec!["alice".into()],
            groups: vec!["release".into()],
            ..Signers::default()
        },
    );
    assert!(sign_as(&r, &adv, ALICE, &asked).is_err());

    let ledger = Arc::new(MemoryLedger::new(SERVERS[0]));
    let first = r.servers.remove(0).with_ledger(ledger.clone());
    r.servers.insert(0, first);
    let adv = r.verify(0);
    let anchors = r.all_anchors();
    let bundles = sign_as(&r, &adv, ALICE, &asked).unwrap();
    assert_eq!(bundles.len(), 2);
    let v = bundles[1]
        .verify(b"release-1.0.sig", REALM, &anchors, &Policy::default())
        .unwrap();
    assert_eq!(v.principal.to_string(), ALICE);
    assert_eq!(
        (v.purpose.as_str(), v.server.as_str()),
        ("blob", SERVERS[0])
    );
    assert!(
        bundles[0]
            .verify(b"release-1.0.sig", REALM, &anchors, &Policy::default())
            .is_err()
    );

    // The statement is in the log, committed: its leaf names nobody and no
    // purpose, and only its opening says it is Alice's.
    let leaves = ledger.leaves();
    let at = usize::try_from(v.index).unwrap();
    let leaf = &leaves[at];
    assert_eq!(leaf.kind, tlog::Kind::STATEMENT);
    assert_eq!(
        leaf.index,
        kuipa_enroll::merkle::Hash::zero(TreeHash::Sha256)
    );
    for secret in [&b"alice"[..], b"blob"] {
        assert!(!leaf.to_bytes().windows(secret.len()).any(|w| w == secret));
    }
    assert_eq!(ledger.openings()[at].subject, ALICE.as_bytes());
    // Alice finds it with a lookup of her principal's entries.
    let mine = tlog_lookup(
        &r,
        &adv,
        ALICE,
        &tlog::Query {
            vault: String::new(),
            from: 0,
        },
    )
    .unwrap();
    assert_eq!(mine.entries.len(), 1);

    // Bob may not sign for blob, until he joins the release group; nobody
    // signs for an unknown purpose; a locked principal signs nothing.
    assert!(sign_as(&r, &adv, BOB, &asked).is_err());
    r.dir
        .groups
        .borrow_mut()
        .insert(BOB.into(), vec!["release".into()]);
    sign_as(&r, &adv, BOB, &asked).unwrap();
    let other = SignRequest {
        purpose: "git-commit".into(),
        ..asked.clone()
    };
    assert!(sign_as(&r, &adv, ALICE, &other).is_err());
    r.dir.disabled.borrow_mut().insert(ALICE.into());
    assert!(sign_as(&r, &adv, ALICE, &asked).is_err());
}

/// Alice's passkeys, ML-DSA and ES256, and Bob's, in a realm that
/// requires user verification.
struct PasskeyCase {
    r: Realm,
    advs: [VerifiedRealm; 2],
    anchors: Vec<Thumbprint>,
    mldsa: SoftAuthenticator,
    es256: SoftAuthenticator,
    bobs: SoftAuthenticator,
}

impl PasskeyCase {
    fn new() -> Self {
        let r = realm();
        let advs = [r.verify(0), r.verify(1)];
        let anchors = r.all_anchors();
        let c = Self {
            r,
            advs,
            anchors,
            mldsa: SoftAuthenticator::new(Algorithm::MlDsa(SignatureAlg::MlDsa65)),
            es256: SoftAuthenticator::new(Algorithm::Es256),
            bobs: SoftAuthenticator::new(Algorithm::EdDsa),
        };
        let mut passkeys = c.r.dir.passkeys.borrow_mut();
        passkeys.insert(ALICE.into(), vec![c.mldsa.ipa_value(), c.es256.ipa_value()]);
        passkeys.insert(BOB.into(), vec![c.bobs.ipa_value()]);
        drop(passkeys);
        c.r.dir.passkey_uv.set(true);
        c
    }

    /// Create Alice's vault `name` with `factors` (and sessions when it
    /// has a device), register `device` if given, and seal `contents`.
    fn seal(
        &self,
        name: &str,
        factors: Factors,
        device: Option<&ExchangeKeyPair>,
        contents: &[u8],
    ) -> SealedVaultFile {
        let adv = &self.advs[0];
        let policy = vault::Policy {
            sessions: vault::Sessions {
                reauth: factors.device.map(|_| 600),
                offline: None,
                epoch: None,
            },
            factors,
            ..vault::Policy::default()
        };
        vault_op(
            &self.r,
            adv,
            ALICE,
            &VaultOp::Create {
                name: name.into(),
                policy,
            },
        )
        .unwrap();
        let described = match device {
            Some(d) => vault_op(&self.r, adv, ALICE, &add_device_op(name, d)),
            None => vault_op(&self.r, adv, ALICE, &VaultOp::Show { name: name.into() }),
        }
        .unwrap();
        let v = described[0]
            .verify(REALM, &self.anchors, &Policy::default())
            .unwrap();
        SealedVaultFile::seal(&v, &[&self.advs[0], &self.advs[1]], contents).unwrap()
    }

    /// Open `sealed` with `device` and whatever `sign` makes of each
    /// request's challenge.
    fn open(
        &self,
        sealed: &SealedVaultFile,
        device: Option<&ExchangeKeyPair>,
        sign: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>,
    ) -> Result<SecretBuf, Error> {
        let mut passkey = |_: &str, challenge: &[u8; 32]| sign(challenge);
        sealed.open(
            Unlock {
                device: device.map(|d| d as &dyn vault::DeviceKey),
                session: None,
                ticket: None,
                release: None,
                passkey: Some(&mut passkey),
            },
            |s, req| {
                // Version 3 carries a release id and an assertion both.
                let both = req.clone().with_release([7; 16]);
                assert_eq!(EscrowRequest::from_bytes(&both.to_bytes()).unwrap(), both);
                ask_server(&self.r, s, req)
            },
        )
    }
}

/// What `a` signs for a challenge, with the authenticator data `flags`.
fn assert_by(a: &SoftAuthenticator, flags: u8) -> impl Fn(&[u8; 32]) -> Option<Vec<u8>> + '_ {
    move |c| Some(a.assert_with("example.test", c, flags).to_bytes())
}

/// Start a session on Alice's vault `keys` for `device` as `caller`, with
/// `auth`'s assertion over the exchange's challenge when given.
fn session_with_passkey(
    r: &Realm,
    adv: &VerifiedRealm,
    caller: &str,
    device: &ExchangeKeyPair,
    auth: Option<&SoftAuthenticator>,
) -> Result<vault::Reply, ()> {
    let p = Prepared::new(
        adv,
        Operation::Vault,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    let challenge = vault::session_passkey_challenge(&cb).unwrap();
    let op = VaultOp::Unlock {
        name: "keys".into(),
        device: device.public().kid().to_string(),
        offline: false,
        passkey: auth
            .map(|a| tang_pqc::b64::encode(&a.assert("example.test", &challenge).to_bytes())),
    };
    let (request, pending) = p
        .with_kerberos(fake_binding(caller, &cb))
        .seal(&gss_token(caller, &cb), &[], &op.to_bytes())
        .unwrap();
    let response = r.send(0, Operation::Vault, &request)?;
    vault::Reply::from_bytes(pending.open(&response).map_err(|_| ())?.as_ref()).map_err(|_| ())
}

/// The passkey factor (§7.6.5): an assertion from one of the opener's IPA
/// passkeys, classical or ML-DSA, over the request's own challenge, with
/// user verification when the realm requires it; a session stands in for
/// it once an assertion started the session.
#[test]
fn passkey_factor() {
    let c = PasskeyCase::new();
    let adv = &c.advs[0];

    // What the client allows its authenticator to answer with.
    let info = vault_reply(&c.r, adv, ALICE, &VaultOp::Passkeys)
        .passkeys
        .unwrap();
    assert_eq!(info.rp_id, "example.test");
    assert!(info.user_verification);
    assert_eq!(
        info.credential_ids().unwrap(),
        vec![c.mldsa.id().to_vec(), c.es256.id().to_vec()]
    );

    let device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let factors = Factors {
        device: Some(Level::Any),
        ticket: false,
        passkey: true,
    };
    let sealed = c.seal("keys", factors, Some(&device), b"pin=1234\n");
    let open = |sign: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>| c.open(&sealed, Some(&device), sign);

    // Either of Alice's passkeys, classical or post-quantum.
    for a in [&c.mldsa, &c.es256] {
        assert_eq!(open(&assert_by(a, 0x05)).unwrap().as_ref(), b"pin=1234\n");
    }
    // Not without user verification, which the realm requires.
    assert!(matches!(
        open(&assert_by(&c.mldsa, 0x01)),
        Err(Error::Refused)
    ));
    c.r.dir.passkey_uv.set(false);
    assert!(open(&assert_by(&c.mldsa, 0x01)).is_ok());
    // Not Bob's passkey, not one for another relying party, not one made
    // for another request, and not without one.
    assert!(matches!(
        open(&assert_by(&c.bobs, 0x05)),
        Err(Error::Refused)
    ));
    assert!(matches!(
        open(&|ch| Some(c.mldsa.assert("other.test", ch).to_bytes())),
        Err(Error::Refused)
    ));
    assert!(matches!(
        open(&|_| Some(c.mldsa.assert("example.test", &[0u8; 32]).to_bytes())),
        Err(Error::Refused)
    ));
    assert!(matches!(open(&|_| None), Err(Error::Refused)));
    let plain = sealed.open(
        Unlock {
            device: Some(&device),
            session: None,
            ticket: None,
            release: None,
            passkey: None,
        },
        |s, req| ask_server(&c.r, s, req),
    );
    assert!(matches!(plain, Err(Error::Refused)));

    passkey_sessions(&c, &sealed, &device);
    passkey_alone(&c);
}

/// A session needs the caller's own assertion to start, and then stands
/// in for it.
fn passkey_sessions(c: &PasskeyCase, sealed: &SealedVaultFile, device: &ExchangeKeyPair) {
    let adv = &c.advs[0];
    assert!(session_with_passkey(&c.r, adv, ALICE, device, None).is_err());
    assert!(session_with_passkey(&c.r, adv, ALICE, device, Some(&c.bobs)).is_err());
    let session = session_with_passkey(&c.r, adv, ALICE, device, Some(&c.mldsa))
        .unwrap()
        .session
        .unwrap();
    let in_session = sealed.open(
        Unlock {
            device: Some(device),
            session: Some(&session),
            ticket: None,
            release: None,
            passkey: None,
        },
        |s, req| ask_server(&c.r, s, req),
    );
    assert_eq!(in_session.unwrap().as_ref(), b"pin=1234\n");
}

/// With the passkey alone, without a ticket or a device, it is the
/// owner's.
fn passkey_alone(c: &PasskeyCase) {
    let factors = Factors {
        device: None,
        ticket: false,
        passkey: true,
    };
    let notes = c.seal("notes", factors, None, b"note\n");
    let open = |a: &SoftAuthenticator| c.open(&notes, None, &assert_by(a, 0x05));
    assert_eq!(open(&c.es256).unwrap().as_ref(), b"note\n");
    assert!(matches!(open(&c.bobs), Err(Error::Refused)));
}
