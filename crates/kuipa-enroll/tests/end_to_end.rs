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
use kuipa_enroll::realm::{Deployment, RealmInfo, ServerKeys, VerifiedRealm};
use kuipa_enroll::server::{
    Accepted, Appended, Directory, DirectoryError, Ledger, Staged, parse_stage_result,
};
use kuipa_enroll::tlog::{self, Head, Leaf, Log, LogId, SignedHead, VaultAction, VaultEvent};
use kuipa_enroll::vault::{
    self, Descriptor, DeviceType, Factors, Level, Recovered, SealedVaultFile, TicketDelegation,
    Unlock, Vault, VaultOp,
};
use kuipa_enroll::{EnrollServer, Error};
use native_ossl::util::SecretBuf;
use tang_pqc::{
    ExchangeKeyPair, KemAlg, Policy, SignatureAlg, SignedAdvertisement, SigningKey, Thumbprint,
    unix_seconds,
};

const REALM: &str = "EXAMPLE.TEST";
const HOST: &str = "web1.example.test";
const CA: &[u8] = b"IPA CA certificate (DER)";

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
    escrow: RefCell<HashMap<String, Vec<[u8; 32]>>>,
    escrow_files: RefCell<HashMap<String, Vec<[u8; 32]>>>,
    disabled: RefCell<HashSet<String>>,
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
        bindings: &[[u8; 32]],
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
        binding: &[u8; 32],
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
        bindings: &[[u8; 32]],
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

    fn principal_locked(&self, principal: &Principal) -> Result<bool, DirectoryError> {
        Ok(self.disabled.borrow().contains(&principal.to_string()))
    }

    fn vault_limits(&self) -> Result<vault::Limits, DirectoryError> {
        Ok(self.limits.borrow().clone())
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

#[test]
#[allow(clippy::too_many_lines)]
fn kerberos_join_and_rekey() {
    let r = realm();
    let adv = r.verify(0);
    let prepared = Prepared::new(
        &adv,
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
        .finish(&r.send(0, Operation::Join, &request).unwrap(), &adv)
        .unwrap();
    assert_eq!(e.keytab.kvno(), Some(1));

    // A token made for another exchange does not verify (channel binding).
    let p2 = Prepared::new(
        &adv,
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

    // Rekey by the host itself; not by someone else.
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
    let e = pending
        .finish(&r.send(0, Operation::Rekey, &request).unwrap(), &adv)
        .unwrap();
    assert_eq!(e.keytab.kvno(), Some(2));

    // A server that cannot accept this realm's tickets derives another
    // binding: its response does not open, though its anchor verified.
    r.dir.impostor.set(true);
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
    let response = r.send(0, Operation::Rekey, &request).unwrap();
    assert!(matches!(
        pending.finish(&response, &adv),
        Err(Error::BadResponse)
    ));
    r.dir.impostor.set(false);

    // A Kerberos request without the binding is not even sealed.
    let p = Prepared::new(
        &adv,
        Operation::Rekey,
        HOST,
        AuthType::Kerberos,
        &Enctype::DEFAULT,
    )
    .unwrap();
    let cb = p.channel_binding().unwrap();
    assert!(p.seal(&gss_token(&host, &cb), &[], &[]).is_err());

    let p = Prepared::new(
        &adv,
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
        &adv,
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
    bindings: &[[u8; 32]],
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
    let seal = |contents: &[u8], retire: Vec<[u8; 32]>| {
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
    assert_eq!(req.vault(), &VaultId::machine(&host, Kind::Keytab).unwrap());

    // Eve's own principal and machine vault, where the binding is registered.
    let eves = renamed(req, &eve, &VaultId::machine(&eve, Kind::Keytab).unwrap());
    assert!(answer(&eves).is_err());
    // The host's file vault, where the binding is registered too.
    let file = renamed(req, &host, &VaultId::machine(&host, Kind::File).unwrap());
    assert!(answer(&file).is_err());
    // A vault that does not exist.
    let none = renamed(req, &host, &VaultId::from_bytes([9; 16]));
    assert!(answer(&none).is_err());
}

const ALICE: &str = "alice@EXAMPLE.TEST";
const BOB: &str = "bob@EXAMPLE.TEST";

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

#[test]
#[allow(clippy::too_many_lines)]
fn user_vault_seals_and_opens_under_its_policy() {
    let r = realm();
    let advs = [r.verify(0), r.verify(1)];
    let adv = &advs[0];
    let anchors = r.all_anchors();
    let device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let other_device = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let add = |name: &str, key: &ExchangeKeyPair| VaultOp::AddDevice {
        name: name.into(),
        label: "laptop".into(),
        kind: DeviceType::File,
        alg: key.public().alg().id(),
        key: tang_pqc::b64::encode(key.public().as_bytes()),
    };
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

    let described = vault_op(&r, adv, ALICE, &add("personal", &device)).unwrap();
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

    let ask = |s: &str, req: &EscrowRequest| {
        let req = EscrowRequest::from_bytes(&req.to_bytes()).unwrap();
        r.servers[usize::from(s == "ipa2.example.test")]
            .recover(&req, &r.dir)
            .ok()
            .map(|a| a.to_bytes())
    };
    let open_as = |who: &'static str, key: Option<&ExchangeKeyPair>| {
        let mut ticket = move |_: &str, cb: &[u8; 32]| Some(gss_token(who, cb));
        sealed.open(
            Unlock {
                device: key.map(|k| k as &dyn vault::DeviceKey),
                session: None,
                ticket: Some(&mut ticket),
            },
            ask,
        )
    };

    assert_eq!(
        open_as(ALICE, Some(&device)).unwrap().as_ref(),
        b"token=secret\n"
    );
    // Without the device, or with one the file was not sealed to.
    assert!(open_as(ALICE, None).is_err());
    assert!(open_as(ALICE, Some(&other_device)).is_err());
    // Bob's ticket is not the owner's.
    assert!(matches!(open_as(BOB, Some(&device)), Err(Error::Refused)));
    // Without any ticket.
    let no_ticket = sealed.open(
        Unlock {
            device: Some(&device),
            session: None,
            ticket: None,
        },
        ask,
    );
    assert!(matches!(no_ticket, Err(Error::Refused)));

    // Delegated tickets: allowed by default, refused or limited by policy.
    let via = "alice@EXAMPLE.TEST via host/vm1.example.test@EXAMPLE.TEST";
    assert!(open_as(via, Some(&device)).is_ok());
    let set = |p: vault::Policy| {
        vault_op(
            &r,
            adv,
            ALICE,
            &VaultOp::SetPolicy {
                name: "personal".into(),
                policy: p,
            },
        )
        .unwrap()
    };
    set(vault::Policy {
        ticket_delegation: TicketDelegation::Refuse,
        ..policy.clone()
    });
    assert!(open_as(via, Some(&device)).is_err());
    assert!(open_as(ALICE, Some(&device)).is_ok());
    set(vault::Policy {
        ticket_delegation: TicketDelegation::Via(vec!["host/vm1.example.test@EXAMPLE.TEST".into()]),
        ..policy.clone()
    });
    assert!(open_as(via, Some(&device)).is_ok());
    let elsewhere = "alice@EXAMPLE.TEST via host/vm2.example.test@EXAMPLE.TEST";
    assert!(open_as(elsewhere, Some(&device)).is_err());
    // A level the device does not have.
    set(vault::Policy {
        factors: Factors {
            device: Some(Level::HardwareBound),
            ..policy.factors.clone()
        },
        ..policy.clone()
    });
    assert!(open_as(ALICE, Some(&device)).is_err());
    set(policy.clone());

    // Bob's vault cannot release Alice's binding, even under his policy.
    let bobs = vault_op(
        &r,
        adv,
        BOB,
        &VaultOp::Create {
            name: "personal".into(),
            policy: policy.clone(),
        },
    )
    .unwrap();
    let bob_vault = bobs[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap()
        .vault()
        .id;
    let mut seen = Vec::new();
    sealed
        .open(
            Unlock {
                device: Some(&device),
                session: None,
                ticket: Some(&mut |_: &str, cb: &[u8; 32]| Some(gss_token(ALICE, cb))),
            },
            |s, req| {
                seen.push(req.clone());
                ask(s, req)
            },
        )
        .unwrap();
    let theirs = renamed(&seen[0], &BOB.parse().unwrap(), &bob_vault);
    assert!(r.servers[0].recover(&theirs, &r.dir).is_err());
    // "personal" names Bob's own vault when Bob asks: Alice's is not his.
    let shown = vault_op(
        &r,
        adv,
        BOB,
        &VaultOp::Show {
            name: "personal".into(),
        },
    )
    .unwrap();
    let shown = shown[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap();
    assert_ne!(shown.vault().id, id);

    // Removing the device, locking the owner and revoking the vault each
    // stop unlocks.
    let device_id = device.public().kid().to_string();
    vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::RemoveDevice {
            name: "personal".into(),
            id: device_id,
        },
    )
    .unwrap();
    assert!(open_as(ALICE, Some(&device)).is_err());
    vault_op(&r, adv, ALICE, &add("personal", &device)).unwrap();
    assert!(open_as(ALICE, Some(&device)).is_ok());
    r.dir.disabled.borrow_mut().insert(ALICE.into());
    assert!(open_as(ALICE, Some(&device)).is_err());
    r.dir.disabled.borrow_mut().clear();
    vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::Revoke {
            name: "personal".into(),
        },
    )
    .unwrap();
    assert!(open_as(ALICE, Some(&device)).is_err());
    let listed = vault_op(&r, adv, ALICE, &VaultOp::List).unwrap();
    assert_eq!(listed.len(), 1);
}

/// Run a vault operation as `caller` and keep the whole reply.
/// A ledger over an in-memory log, as the daemon keeps one on disk.
#[derive(Debug)]
struct MemoryLedger {
    key: [u8; 32],
    log: Mutex<(Log, Vec<Leaf>)>,
}

impl MemoryLedger {
    /// The test servers sign with ML-DSA-65, so their logs are SHA-256.
    fn new(server: &str) -> Self {
        let id = LogId::of(REALM, server, TreeHash::Sha256).unwrap();
        Self {
            key: [7; 32],
            log: Mutex::new((Log::new(id), Vec::new())),
        }
    }

    fn leaves(&self) -> Vec<Leaf> {
        self.log.lock().unwrap().1.clone()
    }

    fn head(&self) -> (Head, Log) {
        let log = self.log.lock().unwrap().0.clone();
        (log.head(now()).unwrap(), log)
    }
}

impl Ledger for MemoryLedger {
    fn append(
        &self,
        kind: tlog::Kind,
        subject: &[u8],
        body: &[u8],
    ) -> Result<Option<Appended>, DirectoryError> {
        let leaf = Leaf {
            kind,
            time: now(),
            index: tlog::index(TreeHash::Sha256, &self.key, subject)?,
            body: body.to_vec(),
        };
        let mut log = self.log.lock().unwrap();
        let index = log.0.append(&leaf)?;
        log.1.push(leaf.clone());
        Ok(Some(Appended {
            log: log.0.id(),
            index,
            leaf: leaf.hash()?,
            time: leaf.time,
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
        let index = tlog::index(TreeHash::Sha256, &self.key, subject)?;
        let log = self.log.lock().unwrap();
        let size = usize::try_from(size)?;
        let hashes = &log.0.hashes()[..size];
        Ok(log.1[..size]
            .iter()
            .enumerate()
            .skip(usize::try_from(from)?)
            .filter(|(_, l)| l.index == index)
            .take(max)
            .map(|(i, l)| tlog::Entry {
                index: i as u64,
                leaf: l.clone(),
                path: kuipa_enroll::merkle::path(hashes, i).unwrap(),
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
    fn append(
        &self,
        _: tlog::Kind,
        _: &[u8],
        _: &[u8],
    ) -> Result<Option<Appended>, DirectoryError> {
        Err("disk full".into())
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn vault_events_are_logged_with_receipts() {
    let mut r = realm();
    let ledger = Arc::new(MemoryLedger::new(SERVERS[0]));
    let first = r.servers.remove(0).with_ledger(ledger.clone());
    r.servers.insert(0, first);
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
    let event = VaultEvent::from_bytes(&leaves[1].body).unwrap();
    assert_eq!(event.action, VaultAction::AddDevice);
    assert_eq!(
        event.device.as_deref(),
        Some(v.vault().devices[0].id.as_str())
    );

    // Opening a sealed file logs the release on the server that answered.
    let sealed = SealedVaultFile::seal(&v, &[&advs[0], &advs[1]], b"x").unwrap();
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
                device: Some(&device),
                session: None,
                ticket: Some(&mut ticket),
            },
            ask,
        )
        .unwrap();
    let leaves = ledger.leaves();
    let release = leaves.last().unwrap();
    assert_eq!(release.kind, tlog::Kind::ESCROW_RELEASE);
    let event = VaultEvent::from_bytes(&release.body).unwrap();
    assert_eq!(event.action, VaultAction::Release);
    assert_eq!(
        event.device.as_deref(),
        Some(v.vault().devices[0].id.as_str())
    );

    // Every leaf is indexed by the vault, and none names it or its owner.
    let index = tlog::index(TreeHash::Sha256, &ledger.key, sealed.vault().as_bytes()).unwrap();
    for leaf in &leaves {
        assert_eq!(leaf.index, index);
        let bytes = leaf.to_bytes();
        for name in [&b"personal"[..], b"alice"] {
            assert!(!bytes.windows(name.len()).any(|w| w == name));
        }
    }

    // The owner looks their vault's entries up, with proofs the client
    // checks against the head; pages on with `from`.
    let lookup = |who: &str, vault: &str, from: u64| {
        tlog_lookup(
            &r,
            adv,
            who,
            &tlog::Query {
                vault: vault.into(),
                from,
            },
        )
    };
    let answer = lookup(ALICE, "personal", 0).unwrap();
    assert_eq!(answer.entries.len(), leaves.len());
    assert_eq!(answer.entries[1].leaf, leaves[1]);
    assert_eq!(lookup(ALICE, "personal", 2).unwrap().entries.len(), 1);
    // Nothing is about Alice's principal; Bob cannot look up her vault.
    assert_eq!(
        lookup(ALICE, "", 0).unwrap().entries,
        [] as [kuipa_enroll::tlog::Entry; 0]
    );
    assert!(lookup(BOB, "personal", 0).is_err());
    // A tampered answer does not verify.
    let mut forged = answer.clone();
    forged.entries[0].leaf.body.push(0);
    assert!(forged.verify(adv.signer(), &Policy::default()).is_err());

    // A server whose ledger fails refuses the change, and does not make
    // it: the vault is still enabled.
    let first = r.servers.remove(0).with_ledger(Arc::new(BrokenLedger));
    r.servers.insert(0, first);
    assert!(
        vault_op(
            &r,
            adv,
            ALICE,
            &VaultOp::Revoke {
                name: "personal".into()
            }
        )
        .is_err()
    );
    let shown = vault_reply(
        &r,
        adv,
        ALICE,
        &VaultOp::Show {
            name: "personal".into(),
        },
    );
    let v = shown.descriptors[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap();
    assert_eq!(v.vault().state, vault::State::Enabled);
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

#[test]
#[allow(clippy::too_many_lines)]
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
            &r,
            adv,
            ALICE,
            &VaultOp::Create {
                name: "b".into(),
                policy: bearer
            }
        )
        .is_err()
    );

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
            },
            ask,
        )
    };

    // The session stands in for the ticket, for its own device only.
    assert_eq!(with_session(&device).unwrap().as_ref(), b"s");
    assert!(with_session(&other).is_err());
    // Two more releases reach the limit; the third is refused, and the
    // vault reports what was counted.
    assert!(with_session(&device).is_ok());
    assert!(with_session(&device).is_ok());
    assert!(matches!(with_session(&device), Err(Error::Refused)));
    let shown = vault_op(&r, adv, ALICE, &VaultOp::Show { name: "s".into() }).unwrap();
    assert_eq!(
        shown[0]
            .verify(REALM, &anchors, &Policy::default())
            .unwrap()
            .vault()
            .unlocks,
        3
    );

    // A policy without sessions stops accepting them, and starting one.
    vault_op(
        &r,
        adv,
        ALICE,
        &VaultOp::SetPolicy {
            name: "s".into(),
            policy: vault::Policy {
                max_unlocks: None,
                sessions: vault::Sessions::default(),
                ..policy
            },
        },
    )
    .unwrap();
    assert!(with_session(&device).is_err());
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
    };
    let (request, _) = p
        .with_kerberos(fake_binding(ALICE, &cb))
        .seal(&gss_token(ALICE, &cb), &[], &op.to_bytes())
        .unwrap();
    assert!(r.send(0, Operation::Vault, &request).is_err());
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

#[test]
#[allow(clippy::too_many_lines)]
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

    let unlock = |i: usize| {
        vault_reply_at(
            &r,
            i,
            &advs[i],
            ALICE,
            &VaultOp::Unlock {
                name: "travel".into(),
                device: device.public().kid().to_string(),
                offline: true,
            },
        )
    };
    let released = unlock(1).unwrap().released.unwrap();
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

    // The epoch turns: new files use epoch 2, which the old release lacks.
    r.dir
        .vaults
        .borrow_mut()
        .get_mut(&d.vault().id)
        .unwrap()
        .session_keys[0]
        .started -= vault::DEFAULT_EPOCH + 1;
    let turned = vault_reply_at(&r, 0, &advs[0], ALICE, &show).unwrap();
    let d2 = turned.descriptors[0]
        .verify(REALM, &anchors, &Policy::default())
        .unwrap();
    assert_eq!(d2.vault().session_keys.len(), 2);
    let newer = vault::SessionSealedFile::seal(&d2, b"later").unwrap();
    assert_eq!(newer.epoch(), 2);
    assert!(!keys.iter().any(|(e, _)| *e == 2));
    let again = unlock(0).unwrap().released.unwrap();
    let keys = again.open(&device, &d.vault().id).unwrap();
    let (_, k2) = keys.iter().find(|(e, _)| *e == 2).unwrap();
    assert_eq!(newer.open(k2, &device).unwrap().as_ref(), b"later");

    // Without the realm's permission no offline session starts.
    r.dir.limits.borrow_mut().offline_sessions = false;
    assert!(unlock(0).is_err());
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

    // The statement is in the log, under Alice's index, naming nobody.
    let leaves = ledger.leaves();
    let leaf = &leaves[usize::try_from(v.index).unwrap()];
    assert_eq!(leaf.kind, tlog::Kind::STATEMENT);
    assert_eq!(
        leaf.index,
        tlog::index(TreeHash::Sha256, &ledger.key, ALICE.as_bytes()).unwrap()
    );
    assert!(!leaf.to_bytes().windows(5).any(|w| w == b"alice"));
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
