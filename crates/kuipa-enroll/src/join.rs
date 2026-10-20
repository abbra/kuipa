//! Join, rekey, stage and registration messages and their key schedule
//! (§5.1, §5.2, §6, §7.5, §8.3).
//!
//! ```text
//! (ct, ss)     = Encaps(ek_kid)            (dk_e, ek_e) = KeyGen()
//! T  = H(op ‖ alg ‖ kid ‖ thp ‖ realm ‖ fqdn ‖ auth_type ‖ enctypes ‖ H(ct) ‖ H(ek_e))
//! cb = HKDF(ss, "cb" ‖ T)                  k = HKDF(ss, "req" ‖ T)
//!      ── Request(alg, kid, realm, fqdn, auth_type, enctypes, ct, ek_e, GCM_k(body)) ──▶
//! (ct_e, ss_e) = Encaps(ek_e)              T' = H(T ‖ H(ct_e))
//! k' = HKDF(ss ‖ ss_e [‖ kb], "rsp" ‖ T')
//!      ◀── Response(ct_e, GCM_k'(payload)) ──
//! ```
//!
//! The operation is part of `T`, so a request sent to another endpoint
//! than the one it was made for does not open.
//!
//! With a Kerberos authenticator, `kb` is the [`KerberosBinding`]: 32 bytes
//! that both ends of the GSS-API context derive from it (RFC 4401) with
//! input `"ipa-ku-enroll/v1 rsp" ‖ cb`.  Only the holder of the
//! `ipa-ku/<server>` key the ticket was issued for can derive it, so a
//! server whose anchor proof verified but that cannot accept the ticket (a
//! stolen anchor) cannot answer: the realm's Kerberos keys authenticate the
//! response independently of the anchors.

use native_ossl::util::SecretBuf;
use tang_pqc::primitives::{self, Domain};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{ExchangeKey, ExchangeKeyPair, KemAlg, Thumbprint};

use crate::error::{Error, Result};
use crate::keytab::{Enctype, Principal};
use crate::payload::Enrollment;
use crate::realm::VerifiedRealm;

/// Domain of all join, rekey and stage derivations.
pub const DOMAIN: Domain = Domain::new("ipa-ku-enroll/v1");

/// What a request asks for.  Selected by the endpoint it is sent to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// `POST /ipa/ku/join/{kid}`.
    Join,
    /// `POST /ipa/ku/rekey/{kid}`.
    Rekey,
    /// `POST /ipa/ku/stage/{kid}`.
    Stage,
    /// `POST /ipa/ku/register/{kid}`: escrow bindings outside a rekey
    /// (§7.5).
    Register,
}

impl Operation {
    const fn label(self) -> &'static str {
        match self {
            Self::Join => "join",
            Self::Rekey => "rekey",
            Self::Stage => "stage",
            Self::Register => "register",
        }
    }

    /// The endpoint path segment, `/ipa/ku/<label>/{kid}`.
    #[must_use]
    pub const fn path(self) -> &'static str {
        self.label()
    }

    const fn magic(self) -> [u8; 4] {
        match self {
            Self::Join | Self::Rekey | Self::Register => *b"IPJQ",
            Self::Stage => *b"IPSQ",
        }
    }
}

/// How the request is authorised (§5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthType {
    /// One-time password.
    Otp,
    /// GSS-API initial token with channel bindings.
    Kerberos,
    /// Enrollment voucher.
    Voucher,
}

impl AuthType {
    const fn id(self) -> u8 {
        match self {
            Self::Otp => 1,
            Self::Kerberos => 2,
            Self::Voucher => 3,
        }
    }

    fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Otp),
            2 => Ok(Self::Kerberos),
            3 => Ok(Self::Voucher),
            // 4 was a principal and password sealed to the server; password
            // joins now get a ticket on the host instead (§5.3).
            _ => Err(Error::Malformed("auth type")),
        }
    }
}

/// Client → server.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    op: Operation,
    alg: KemAlg,
    kid: Thumbprint,
    realm: String,
    fqdn: String,
    auth_type: AuthType,
    enctypes: Vec<Enctype>,
    ciphertext: Box<[u8]>,
    ephemeral_key: Box<[u8]>,
    sealed: Box<[u8]>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("op", &self.op)
            .field("kid", &self.kid)
            .field("realm", &self.realm)
            .field("fqdn", &self.fqdn)
            .field("auth_type", &self.auth_type)
            .finish_non_exhaustive()
    }
}

impl Request {
    /// The operation.
    #[must_use]
    pub fn operation(&self) -> Operation {
        self.op
    }

    /// The join key the request is encrypted to (`/{kid}`).
    #[must_use]
    pub fn kid(&self) -> &Thumbprint {
        &self.kid
    }

    /// The host the request is about.
    #[must_use]
    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    /// The realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The authenticator type.
    #[must_use]
    pub fn auth_type(&self) -> AuthType {
        self.auth_type
    }

    /// The host's ephemeral encapsulation key.
    #[must_use]
    pub fn ephemeral_key(&self) -> &[u8] {
        &self.ephemeral_key
    }

    /// Encode.
    ///
    /// # Panics
    ///
    /// Never for requests made by this crate (at most 255 enctypes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(self.op.magic());
        w.u8(self.alg.id())
            .fixed(self.kid.as_bytes())
            .str(&self.realm)
            .str(&self.fqdn)
            .u8(self.auth_type.id())
            .u8(u8::try_from(self.enctypes.len()).expect("at most 255 enctypes"));
        for e in &self.enctypes {
            w.fixed(&e.0.to_be_bytes());
        }
        w.bytes(&self.ciphertext)
            .bytes(&self.ephemeral_key)
            .bytes(&self.sealed)
            .finish()
    }

    /// Decode a request sent to the endpoint of `op`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for a request of another operation's
    /// format.
    pub fn from_bytes(op: Operation, bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, op.magic(), "request")?;
        let alg = KemAlg::from_id(r.u8()?)?;
        let kid = Thumbprint::from_bytes(r.fixed()?);
        let realm = r.str()?.to_owned();
        let fqdn = r.str()?.to_owned();
        let auth_type = AuthType::from_id(r.u8()?)?;
        let enctypes = (0..r.u8()?)
            .map(|_| r.fixed().map(|b| Enctype(i32::from_be_bytes(b))))
            .collect::<Result<_, _>>()?;
        let request = Self {
            op,
            alg,
            kid,
            realm,
            fqdn,
            auth_type,
            enctypes,
            ciphertext: r.bytes_exact(alg.ciphertext_len())?.into(),
            ephemeral_key: r.bytes_exact(alg.encapsulation_key_len())?.into(),
            sealed: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(request)
    }

    pub(crate) fn alg(&self) -> KemAlg {
        self.alg
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub(crate) fn enctypes(&self) -> &[Enctype] {
        &self.enctypes
    }

    /// `T`, as computed by both sides; `signer` is the server signing key.
    pub(crate) fn transcript(&self, signer: &Thumbprint) -> Result<Vec<u8>> {
        let hash = self.alg.hash();
        let mut w = Writer::new(*b"IPJT");
        w.str(self.op.label())
            .u8(self.alg.id())
            .fixed(self.kid.as_bytes())
            .fixed(signer.as_bytes())
            .str(&self.realm)
            .str(&self.fqdn)
            .u8(self.auth_type.id());
        for e in &self.enctypes {
            w.fixed(&e.0.to_be_bytes());
        }
        w.fixed(&primitives::digest(hash, &[&self.ciphertext])?)
            .fixed(&primitives::digest(hash, &[&self.ephemeral_key])?);
        Ok(primitives::digest(hash, &[&w.finish()])?)
    }

    pub(crate) fn open_body(&self, ss: &[u8], t: &[u8]) -> Result<RequestBody> {
        let k = DOMAIN.derive_key(self.alg.hash(), &[ss], "req", &[t])?;
        let plain = primitives::open(k.as_ref(), &self.sealed).map_err(|_| Error::Refused)?;
        RequestBody::from_bytes(plain.as_ref(), self.auth_type)
    }

    /// Encrypt `payload` to the client's ephemeral key, bound to the
    /// Kerberos context `kb` for a Kerberos authenticator.
    pub(crate) fn respond(
        &self,
        ss: &[u8],
        t: &[u8],
        kb: Option<&KerberosBinding>,
        payload: &[u8],
    ) -> Result<Response> {
        check_binding(self.auth_type, kb)?;
        // Importing runs the FIPS 203 encapsulation-key check.
        let ephemeral = ExchangeKey::from_bytes(self.alg, &self.ephemeral_key)?;
        let (ct_e, ss_e) = ephemeral.encapsulate()?;
        let k = response_key(self.alg, ss, ss_e.as_ref(), kb, t, &ct_e)?;
        Ok(Response {
            sealed: primitives::seal(k.as_ref(), payload)?.into(),
            ciphertext: ct_e.into(),
        })
    }
}

/// What both ends of a Kerberos authenticator's GSS-API context derive
/// (RFC 4401 `GSS_C_PRF_KEY_FULL`, [`KERBEROS_BINDING_LEN`] bytes) from
/// [`kerberos_prf_input`]; mixed into the response key.
pub struct KerberosBinding(SecretBuf);

impl KerberosBinding {
    /// Wrap the derived bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a length other than
    /// [`KERBEROS_BINDING_LEN`].
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KERBEROS_BINDING_LEN {
            return Err(Error::Malformed("Kerberos binding"));
        }
        Ok(Self(SecretBuf::from_slice(bytes)))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Debug for KerberosBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KerberosBinding(..)")
    }
}

/// Length of a [`KerberosBinding`].
pub const KERBEROS_BINDING_LEN: usize = 32;

/// The GSS-API pseudo-random function input for the [`KerberosBinding`] of
/// an exchange with channel binding `cb`.
#[must_use]
pub fn kerberos_prf_input(cb: &[u8; 32]) -> Vec<u8> {
    [b"ipa-ku-enroll/v1 rsp".as_slice(), cb].concat()
}

/// The binding must be present exactly for Kerberos authenticators.
fn check_binding(auth_type: AuthType, kb: Option<&KerberosBinding>) -> Result<()> {
    match (auth_type, kb) {
        (AuthType::Kerberos, None) => Err(Error::Missing("Kerberos binding")),
        (AuthType::Kerberos, Some(_)) | (_, None) => Ok(()),
        (_, Some(_)) => Err(Error::Mismatch("Kerberos binding without Kerberos")),
    }
}

pub(crate) fn channel_binding(alg: KemAlg, ss: &[u8], t: &[u8]) -> Result<[u8; 32]> {
    let mut cb = [0u8; 32];
    DOMAIN.hkdf(alg.hash(), &[ss], "cb", &[t], &mut cb)?;
    Ok(cb)
}

fn response_key(
    alg: KemAlg,
    ss: &[u8],
    ss_e: &[u8],
    kb: Option<&KerberosBinding>,
    t: &[u8],
    ct_e: &[u8],
) -> Result<SecretBuf> {
    let hash = alg.hash();
    let t2 = primitives::digest(hash, &[t, &primitives::digest(hash, &[ct_e])?])?;
    let ikm: Vec<&[u8]> = [ss, ss_e]
        .into_iter()
        .chain(kb.map(KerberosBinding::as_bytes))
        .collect();
    Ok(DOMAIN.derive_key(hash, &ikm, "rsp", &[&t2])?)
}

/// The sealed part of a request.
pub(crate) struct RequestBody {
    pub(crate) authenticator: SecretBuf,
    pub(crate) registrations: Vec<[u8; 32]>,
    pub(crate) extra: Vec<u8>,
}

const BODY_MAGIC: [u8; 4] = *b"IPRB";

impl RequestBody {
    fn to_bytes(&self, auth_type: AuthType) -> Result<SecretBuf> {
        let mut w = Writer::new(BODY_MAGIC);
        w.u8(auth_type.id())
            .u8(u8::try_from(self.registrations.len())
                .map_err(|_| Error::Malformed("too many registrations"))?);
        for r in &self.registrations {
            w.fixed(r);
        }
        w.bytes(&self.extra).bytes(self.authenticator.as_ref());
        Ok(SecretBuf::new(w.finish()))
    }

    fn from_bytes(bytes: &[u8], auth_type: AuthType) -> Result<Self> {
        let mut r = Reader::new(bytes, BODY_MAGIC, "request body")?;
        if r.u8()? != auth_type.id() {
            return Err(Error::Malformed("request body"));
        }
        let registrations = (0..r.u8()?).map(|_| r.fixed()).collect::<Result<_, _>>()?;
        let extra = r.bytes()?.to_vec();
        let authenticator = SecretBuf::from_slice(r.bytes()?);
        r.finish()?;
        Ok(Self {
            authenticator,
            registrations,
            extra,
        })
    }
}

/// Server → client.
#[derive(Clone, PartialEq, Eq)]
pub struct Response {
    ciphertext: Box<[u8]>,
    sealed: Box<[u8]>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response").finish_non_exhaustive()
    }
}

const RESPONSE_MAGIC: [u8; 4] = *b"IPJS";

impl Response {
    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(RESPONSE_MAGIC)
            .bytes(&self.ciphertext)
            .bytes(&self.sealed)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, RESPONSE_MAGIC, "response")?;
        let response = Self {
            ciphertext: r.bytes()?.into(),
            sealed: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(response)
    }
}

/// A request being prepared: the KEM exchange is done, the authenticator
/// is not sealed yet.  For a Kerberos authenticator, make the GSS-API token
/// with [`channel_binding`](Self::channel_binding) first, and give its
/// context's [`KerberosBinding`] to [`with_kerberos`](Self::with_kerberos).
#[must_use]
pub struct Prepared {
    request: Request,
    signer: Thumbprint,
    ss: SecretBuf,
    ephemeral: ExchangeKeyPair,
    transcript: Vec<u8>,
    kerberos: Option<KerberosBinding>,
}

impl Prepared {
    /// Start a request to the server of `realm` about host `fqdn`.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] if the server advertises no join key, or an
    /// OpenSSL error (including a KEM the system policy disables).
    pub fn new(
        realm: &VerifiedRealm,
        op: Operation,
        fqdn: &str,
        auth_type: AuthType,
        enctypes: &[Enctype],
    ) -> Result<Self> {
        if enctypes.len() > 255 {
            return Err(Error::Malformed("too many enctypes"));
        }
        let key = realm.join_key()?;
        let (ciphertext, ss) = key.encapsulate()?;
        let ephemeral = ExchangeKeyPair::generate(key.alg())?;
        let request = Request {
            op,
            alg: key.alg(),
            kid: *key.kid(),
            realm: realm.info().realm.clone(),
            fqdn: fqdn.into(),
            auth_type,
            enctypes: enctypes.to_vec(),
            ciphertext: ciphertext.into(),
            ephemeral_key: ephemeral.public().as_bytes().into(),
            sealed: Box::default(),
        };
        let signer = *realm.signer();
        let transcript = request.transcript(&signer)?;
        Ok(Self {
            request,
            signer,
            ss,
            ephemeral,
            transcript,
            kerberos: None,
        })
    }

    /// The binding derived from the GSS-API context of the authenticator;
    /// required for, and only allowed with, [`AuthType::Kerberos`].
    pub fn with_kerberos(mut self, binding: KerberosBinding) -> Self {
        self.kerberos = Some(binding);
        self
    }

    /// The GSS-API channel binding value for this exchange.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn channel_binding(&self) -> Result<[u8; 32]> {
        channel_binding(self.request.alg, self.ss.as_ref(), &self.transcript)
    }

    /// Use `ephemeral` (made in advance, e.g. for a voucher bound to it)
    /// instead of a fresh ephemeral key.
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] if it is not of the join key's algorithm.
    pub fn with_ephemeral(mut self, ephemeral: ExchangeKeyPair) -> Result<Self> {
        if ephemeral.public().alg() != self.request.alg {
            return Err(Error::Mismatch("ephemeral key algorithm"));
        }
        self.request.ephemeral_key = ephemeral.public().as_bytes().into();
        self.transcript = self.request.transcript(&self.signer)?;
        self.ephemeral = ephemeral;
        Ok(self)
    }

    /// Seal the authenticator, with escrow registrations (§7.2) and
    /// operation-specific `extra` data, into the finished request.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for more than 255 registrations, or an OpenSSL
    /// error.
    pub fn seal(
        mut self,
        authenticator: &[u8],
        registrations: &[[u8; 32]],
        extra: &[u8],
    ) -> Result<(Request, PendingJoin)> {
        check_binding(self.request.auth_type, self.kerberos.as_ref())?;
        let body = RequestBody {
            authenticator: SecretBuf::from_slice(authenticator),
            registrations: registrations.to_vec(),
            extra: extra.to_vec(),
        }
        .to_bytes(self.request.auth_type)?;
        let k = DOMAIN.derive_key(
            self.request.alg.hash(),
            &[self.ss.as_ref()],
            "req",
            &[&self.transcript],
        )?;
        self.request.sealed = primitives::seal(k.as_ref(), body.as_ref())?.into();
        let pending = PendingJoin {
            op: self.request.op,
            alg: self.request.alg,
            fqdn: self.request.fqdn.clone(),
            realm: self.request.realm.clone(),
            ss: self.ss,
            ephemeral: self.ephemeral,
            transcript: self.transcript,
            signer: self.signer,
            kerberos: self.kerberos,
        };
        Ok((self.request, pending))
    }
}

/// Client state while a request is in flight.
#[must_use = "finish the exchange with the server's response"]
pub struct PendingJoin {
    op: Operation,
    alg: KemAlg,
    fqdn: String,
    realm: String,
    ss: SecretBuf,
    ephemeral: ExchangeKeyPair,
    transcript: Vec<u8>,
    signer: Thumbprint,
    kerberos: Option<KerberosBinding>,
}

impl std::fmt::Debug for PendingJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingJoin")
            .field("op", &self.op)
            .field("fqdn", &self.fqdn)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl PendingJoin {
    /// The operation.
    #[must_use]
    pub fn operation(&self) -> Operation {
        self.op
    }

    /// Decrypt the response payload.
    ///
    /// # Errors
    ///
    /// [`Error::BadResponse`] if it is not for this request.
    pub fn open(self, response: &Response) -> Result<SecretBuf> {
        if response.ciphertext.len() != self.alg.ciphertext_len() {
            return Err(Error::BadResponse);
        }
        let ss_e = self.ephemeral.decapsulate(&response.ciphertext)?;
        let k = response_key(
            self.alg,
            self.ss.as_ref(),
            ss_e.as_ref(),
            self.kerberos.as_ref(),
            &self.transcript,
            &response.ciphertext,
        )?;
        primitives::open(k.as_ref(), &response.sealed).map_err(|_| Error::BadResponse)
    }

    /// Finish a registration (§7.5): decrypt the server's answer and check
    /// it registered for `params.principal`.
    ///
    /// # Errors
    ///
    /// [`Error::BadResponse`], [`Error::Malformed`], or [`Error::Mismatch`]
    /// for another server or principal.
    pub fn finish_register(
        self,
        response: &Response,
        realm: &VerifiedRealm,
        params: &crate::escrow::RegisterParams,
    ) -> Result<()> {
        if realm.signer() != &self.signer {
            return Err(Error::Mismatch("server"));
        }
        params.check_acknowledgement(self.open(response)?.as_ref())
    }

    /// Finish a join or rekey: decrypt the enrollment, and check it is for
    /// this host and that its CA chain is the one `realm` advertises.
    ///
    /// # Errors
    ///
    /// [`Error::BadResponse`], [`Error::Malformed`], or [`Error::Mismatch`]
    /// for keys of another principal or an unadvertised CA certificate.
    pub fn finish(self, response: &Response, realm: &VerifiedRealm) -> Result<Enrollment> {
        if realm.signer() != &self.signer {
            return Err(Error::Mismatch("server"));
        }
        let expected = Principal::host(&self.fqdn, &self.realm);
        let enrollment = Enrollment::from_bytes(self.open(response)?.as_ref())?;
        if enrollment.keytab.principal() != &expected {
            return Err(Error::Mismatch("keytab principal"));
        }
        realm.check_ca_certs(&enrollment.ca_certs)?;
        if enrollment.anchors.is_empty() {
            return Err(Error::Missing("anchors"));
        }
        Ok(enrollment)
    }
}
