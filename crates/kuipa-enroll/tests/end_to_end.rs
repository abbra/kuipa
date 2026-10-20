//! Every protocol flow, client and server, against an in-memory directory.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
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
use kuipa_enroll::realm::{Deployment, RealmInfo, ServerKeys, VerifiedRealm};
use kuipa_enroll::server::{Directory, DirectoryError, Staged, parse_stage_result};
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
        let leaves = trust(&state, i).leaves().unwrap();
        let vouch =
            SignedVouch::issue(anchor, REALM, leaves, now() - 60, now() + VOUCH_VALIDITY).unwrap();
        state
            .put(Entry::Vouch(vouch), REALM, &policy, now(), &clock)
            .unwrap();
    }
    for (i, server) in servers.iter().enumerate() {
        let t = trust(&state, i);
        server.publish(t.own_delegation(&state).unwrap(), t.anchors());
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
    rotated.publish(server.delegation(), server.anchors());
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
        r.servers[i].recover(&req, &r.dir).ok()
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
        r.servers[0].recover(&req, &r.dir)
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
