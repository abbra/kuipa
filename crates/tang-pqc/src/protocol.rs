//! Recovery messages (the Tang `POST /rec/{kid}` exchange) and the transport
//! encryption shared by client and server.
//!
//! ```text
//! Client (binding: kid, ct, r; ek for kid)          Server (dk for kid)
//! (ct_t, ss_t)  = ML-KEM.Encaps(ek)
//! k_req ‖ k_rsp = HKDF(ss_t, transcript)
//!                ── RecoveryRequest(kid, ct_t, Seal_k_req(ct)) ──▶
//!                                                   ss_t = ML-KEM.Decaps(dk, ct_t)
//!                                                   ct   = Open_k_req(...)
//!                                                   ss   = ML-KEM.Decaps(dk, ct)
//!                ◀── RecoveryResponse(Seal_k_rsp(ss)) ──
//! ss = Open_k_rsp(...); K ‖ confirm = HKDF(ss ‖ r, …); check confirm
//! ```
//!
//! The binding's ciphertext travels sealed, so a network observer sees a
//! fresh `ct_t` on every attempt, even when the binding never changes.

use std::fmt;

use native_ossl::util::{SecretBuf, ct_eq};

use crate::alg::KemAlg;
use crate::error::{Error, Result};
use crate::keys::{ExchangeKey, ExchangeKeyPair, Thumbprint};
use crate::primitives::{self, Domain, TAG_LEN};
use crate::wire::{Reader, Writer};

const REQUEST_MAGIC: [u8; 4] = *b"TQRQ";
const RESPONSE_MAGIC: [u8; 4] = *b"TQRS";

/// ML-KEM shared secret length.
const SS_LEN: usize = 32;

/// Client → server.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryRequest {
    alg: KemAlg,
    kid: Thumbprint,
    transport: Box<[u8]>,
    sealed: Box<[u8]>,
}

impl RecoveryRequest {
    /// The exchange key the client asks the server to use (`/rec/{kid}`).
    #[must_use]
    pub fn kid(&self) -> &Thumbprint {
        &self.kid
    }

    /// The KEM of the binding being recovered.
    #[must_use]
    pub fn alg(&self) -> KemAlg {
        self.alg
    }

    /// Encode for transport.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(REQUEST_MAGIC)
            .u8(self.alg.id())
            .fixed(self.kid.as_bytes())
            .bytes(&self.transport)
            .bytes(&self.sealed)
            .finish()
    }

    /// Decode from transport.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] or [`Error::UnsupportedAlgorithm`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, REQUEST_MAGIC, "recovery request")?;
        let alg = KemAlg::from_id(r.u8()?)?;
        let request = Self {
            alg,
            kid: Thumbprint::from_bytes(r.fixed()?),
            transport: r.bytes_exact(alg.ciphertext_len())?.into(),
            sealed: r.bytes_exact(alg.ciphertext_len() + TAG_LEN)?.into(),
        };
        r.finish()?;
        Ok(request)
    }
}

impl fmt::Debug for RecoveryRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryRequest")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Server → client.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryResponse {
    sealed: Box<[u8]>,
}

impl RecoveryResponse {
    /// Encode for transport.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(RESPONSE_MAGIC).bytes(&self.sealed).finish()
    }

    /// Decode from transport.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for invalid encodings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, RESPONSE_MAGIC, "recovery response")?;
        let response = Self {
            sealed: r.bytes_exact(SS_LEN + TAG_LEN)?.into(),
        };
        r.finish()?;
        Ok(response)
    }
}

impl fmt::Debug for RecoveryResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryResponse").finish_non_exhaustive()
    }
}

/// Single-use AES-256-GCM keys for the request and the response, both bound
/// to this exchange's transport encapsulation.
fn transport_keys(
    domain: Domain,
    alg: KemAlg,
    kid: &Thumbprint,
    transport: &[u8],
    transport_secret: &[u8],
) -> Result<(SecretBuf, SecretBuf)> {
    let hash = alg.hash();
    let mut okm = SecretBuf::with_len(64);
    domain.hkdf(
        hash,
        &[transport_secret],
        "transport",
        &[
            &[alg.id()],
            kid.as_bytes(),
            &primitives::digest(hash, &[transport])?,
        ],
        okm.as_mut_slice(),
    )?;
    let (request, response) = okm.as_ref().split_at(32);
    Ok((
        SecretBuf::from_slice(request),
        SecretBuf::from_slice(response),
    ))
}

/// `HKDF(ss, "<domain> commit" ‖ alg ‖ kid ‖ H(ct) ‖ data)`: a commitment
/// to `data` that only the binding's creator (who held `ss` once) and the
/// holder of the exchange key can compute.
pub(crate) fn commitment(
    domain: Domain,
    alg: KemAlg,
    kid: &Thumbprint,
    ciphertext: &[u8],
    shared_secret: &[u8],
    data: &[u8],
) -> Result<[u8; 32]> {
    let hash = alg.hash();
    let mut tag = [0u8; 32];
    domain.hkdf(
        hash,
        &[shared_secret],
        "commit",
        &[
            &[alg.id()],
            kid.as_bytes(),
            &primitives::digest(hash, &[ciphertext])?,
            data,
        ],
        &mut tag,
    )?;
    Ok(tag)
}

/// Client: seal the binding's ciphertext to the server's exchange key.
/// Returns the request and the key that opens the response.
pub(crate) fn seal_request(
    domain: Domain,
    exchange: &ExchangeKey,
    ciphertext: &[u8],
) -> Result<(RecoveryRequest, SecretBuf)> {
    let (transport, transport_secret) = exchange.encapsulate()?;
    let (request_key, response_key) = transport_keys(
        domain,
        exchange.alg(),
        exchange.kid(),
        &transport,
        transport_secret.as_ref(),
    )?;
    let request = RecoveryRequest {
        alg: exchange.alg(),
        kid: *exchange.kid(),
        sealed: primitives::seal(request_key.as_ref(), ciphertext)?.into(),
        transport: transport.into(),
    };
    Ok((request, response_key))
}

/// Client: recover the shared secret from the server's response.
pub(crate) fn open_response(response_key: &[u8], response: &RecoveryResponse) -> Result<SecretBuf> {
    let shared_secret = primitives::open(response_key, &response.sealed)?;
    if shared_secret.len() == SS_LEN {
        Ok(shared_secret)
    } else {
        Err(Error::RecoveryFailed)
    }
}

impl RecoveryRequest {
    /// Open this request with `key`, the exchange key it names, in the
    /// protocol `domain` the binding was provisioned under.
    ///
    /// Servers that authorise requests themselves open the request, check
    /// [`OpenedRequest::ciphertext_hash`], then
    /// [`respond`](OpenedRequest::respond).
    ///
    /// # Errors
    ///
    /// [`Error::UnknownKey`] if `key` is not the one the request names,
    /// [`Error::Malformed`] if the request does not open under it (tampered,
    /// or sealed to another key or domain), [`Error::DisabledBySystemPolicy`]
    /// if the system crypto policy disables its KEM, or an OpenSSL error.
    pub fn open<'k>(&self, key: &'k ExchangeKeyPair, domain: Domain) -> Result<OpenedRequest<'k>> {
        if key.public().kid() != &self.kid || key.public().alg() != self.alg {
            return Err(Error::UnknownKey(self.kid));
        }
        let transport_secret = key.decapsulate(&self.transport)?;
        let (request_key, response_key) = transport_keys(
            domain,
            self.alg,
            &self.kid,
            &self.transport,
            transport_secret.as_ref(),
        )?;
        // A modified `ct_t` decapsulates to a pseudorandom secret (implicit
        // rejection), so this also catches transport tampering.
        let ciphertext = primitives::open(request_key.as_ref(), &self.sealed)
            .map_err(|_| Error::Malformed("recovery request"))?;
        if ciphertext.len() != self.alg.ciphertext_len() {
            return Err(Error::Malformed("recovery request"));
        }
        Ok(OpenedRequest {
            key,
            domain,
            ciphertext: ciphertext.as_ref().into(),
            response_key,
        })
    }

    /// Answer this request: [`open`](Self::open) followed by
    /// [`OpenedRequest::respond`].
    ///
    /// [`Server::recover`](crate::Server::recover) does this for Tang.
    ///
    /// # Errors
    ///
    /// As for those.
    pub fn respond(&self, key: &ExchangeKeyPair, domain: Domain) -> Result<RecoveryResponse> {
        self.open(key, domain)?.respond()
    }
}

/// A recovery request opened by the server: the binding's ciphertext is
/// known, and the response is not yet sent.
pub struct OpenedRequest<'k> {
    key: &'k ExchangeKeyPair,
    domain: Domain,
    ciphertext: Box<[u8]>,
    response_key: SecretBuf,
}

impl OpenedRequest<'_> {
    /// SHA-256 of the binding ciphertext, matching
    /// [`Binding::ciphertext_hash`](crate::Binding::ciphertext_hash), so a
    /// server can check the request against registered bindings.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn ciphertext_hash(&self) -> Result<[u8; 32]> {
        primitives::sha256(&[&self.ciphertext])
    }

    /// Check that `tag` commits this binding to `data`: the tag
    /// [`Advertisement::provision_committed`](crate::Advertisement::provision_committed)
    /// returned for the same data.  Without it a server that authorises by
    /// application data (a vault, a principal) sees only the ciphertext, and
    /// a client could present someone else's binding under data it is
    /// authorised for.
    ///
    /// # Errors
    ///
    /// [`Error::CommitmentMismatch`], [`Error::DisabledBySystemPolicy`] or
    /// an OpenSSL error.
    pub fn verify_commitment(&self, data: &[u8], tag: &[u8; 32]) -> Result<()> {
        let alg = self.key.public().alg();
        let shared_secret = self.key.decapsulate(&self.ciphertext)?;
        let expected = commitment(
            self.domain,
            alg,
            self.key.public().kid(),
            &self.ciphertext,
            shared_secret.as_ref(),
            data,
        )?;
        if ct_eq(&expected, tag) {
            Ok(())
        } else {
            Err(Error::CommitmentMismatch)
        }
    }

    /// Decapsulate the binding ciphertext and seal the shared secret for the
    /// client.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] or an OpenSSL error.
    pub fn respond(self) -> Result<RecoveryResponse> {
        let shared_secret = self.key.decapsulate(&self.ciphertext)?;
        Ok(RecoveryResponse {
            sealed: primitives::seal(self.response_key.as_ref(), shared_secret.as_ref())?.into(),
        })
    }
}

impl fmt::Debug for OpenedRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedRequest")
            .field("kid", self.key.public().kid())
            .finish_non_exhaustive()
    }
}
