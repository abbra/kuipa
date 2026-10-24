//! Client side: provisioning (Clevis `encrypt`) and recovery (Clevis `decrypt`).

use std::fmt;

use native_ossl::rand::Rand;
use native_ossl::util::{SecretBuf, ct_eq};

use crate::adv::Advertisement;
use crate::alg::KemAlg;
use crate::error::{Error, Result};
use crate::keys::{ExchangeKey, Thumbprint};
use crate::primitives::{self, Domain};
use crate::protocol::{self, RecoveryRequest, RecoveryResponse};
use crate::wire::{Reader, Writer};

const BINDING_MAGIC: [u8; 4] = *b"TQBD";

/// Length of the recovered key in bytes.
pub const KEY_LEN: usize = 32;

/// The secret protected by the server: use it as a LUKS passphrase, a JWE
/// content-encryption key, and so on.  Wiped on drop.
pub struct Key(SecretBuf);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

/// What a binding's key is bound to besides the binding itself: the
/// protocol [`Domain`] and optional application data (for example the name
/// of the principal whose keytab the key protects).
///
/// Neither is stored in the binding, so the same context must be supplied
/// when the binding is loaded again ([`Binding::from_bytes_with`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BindingContext {
    domain: Domain,
    info: Vec<u8>,
}

impl BindingContext {
    /// A context for `domain`, binding the key to `info` as well.
    #[must_use]
    pub fn new(domain: Domain, info: &[u8]) -> Self {
        Self {
            domain,
            info: info.to_vec(),
        }
    }

    /// The protocol domain.
    #[must_use]
    pub fn domain(&self) -> Domain {
        self.domain
    }
}

/// `HKDF(ss ‖ r, "<domain> key" ‖ alg ‖ kid ‖ thp ‖ H(ct) ‖ info)`, split
/// into the key and its confirmation tag.  `H` and the HKDF hash follow the
/// suite (SHA-256 for ML-KEM-768, SHA-384 for ML-KEM-1024).
///
/// Every stored field except `confirm` itself is bound into the output, so a
/// binding edited on disk (including its trust anchor) fails cleanly.
fn derive(shared_secret: &[u8], b: &Binding) -> Result<(Key, [u8; 32])> {
    let hash = b.alg.hash();
    let mut okm = SecretBuf::with_len(KEY_LEN + 32);
    b.context.domain.hkdf(
        hash,
        &[shared_secret, &b.share],
        "key",
        &[
            &[b.alg.id()],
            b.kid.as_bytes(),
            b.signing_thumbprint.as_bytes(),
            &primitives::digest(hash, &[&b.ciphertext])?,
            &b.context.info,
        ],
        okm.as_mut_slice(),
    )?;
    let (key, confirm) = okm.as_ref().split_at(KEY_LEN);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(confirm);
    Ok((Key(SecretBuf::from_slice(key)), tag))
}

impl Advertisement {
    /// Create a new binding: the metadata to store next to the encrypted data,
    /// and the key it protects.
    ///
    /// Uses the exchange key `kid`, or the first advertised one if `None`.
    /// Works offline once the advertisement has been obtained and verified.
    ///
    /// # Errors
    ///
    /// [`Error::NoExchangeKey`] / [`Error::UnknownKey`] if no suitable key is
    /// advertised, or an OpenSSL error.
    pub fn provision(&self, kid: Option<&Thumbprint>) -> Result<(Binding, Key)> {
        self.provision_with(&BindingContext::default(), kid)
    }

    /// As [`provision`](Self::provision), bound to `context`.
    ///
    /// `kid` may name any exchange key in the advertisement, including one
    /// with a role member; `None` picks the first key without one.
    ///
    /// # Errors
    ///
    /// As for [`provision`](Self::provision).
    pub fn provision_with(
        &self,
        context: &BindingContext,
        kid: Option<&Thumbprint>,
    ) -> Result<(Binding, Key)> {
        let (binding, key, _) = self.provision_inner(context, kid, None)?;
        Ok((binding, key))
    }

    /// As [`provision_with`](Self::provision_with), and commit the binding
    /// to `data`: the returned tag, sent with a recovery request, lets the
    /// server check the request's claim to `data` with
    /// [`OpenedRequest::verify_commitment`](crate::OpenedRequest::verify_commitment).
    ///
    /// # Errors
    ///
    /// As for [`provision`](Self::provision).
    pub fn provision_committed(
        &self,
        context: &BindingContext,
        kid: Option<&Thumbprint>,
        data: &[u8],
    ) -> Result<(Binding, Key, [u8; 32])> {
        let (binding, key, tag) = self.provision_inner(context, kid, Some(data))?;
        Ok((binding, key, tag.unwrap_or_default()))
    }

    fn provision_inner(
        &self,
        context: &BindingContext,
        kid: Option<&Thumbprint>,
        commit: Option<&[u8]>,
    ) -> Result<(Binding, Key, Option<[u8; 32]>)> {
        let exchange = match kid {
            Some(kid) => self.exchange_key(kid).ok_or(Error::UnknownKey(*kid))?,
            None => self.exchange_keys().first().ok_or(Error::NoExchangeKey)?,
        };
        exchange.alg().ensure_allowed()?;
        let (ciphertext, shared_secret) = exchange.encapsulate()?;
        let mut share = [0u8; 32];
        Rand::fill_private(&mut share)?;
        let mut binding = Binding {
            alg: exchange.alg(),
            kid: *exchange.kid(),
            signing_thumbprint: *self.trusted_thumbprint(),
            ciphertext: ciphertext.into(),
            share,
            confirm: [0; 32],
            context: context.clone(),
        };
        let (key, confirm) = derive(shared_secret.as_ref(), &binding)?;
        binding.confirm = confirm;
        let tag = commit
            .map(|data| {
                protocol::commitment(
                    context.domain,
                    binding.alg,
                    &binding.kid,
                    &binding.ciphertext,
                    shared_secret.as_ref(),
                    data,
                )
            })
            .transpose()?;
        Ok((binding, key, tag))
    }
}

/// Client metadata for one protected key (what Clevis keeps in the LUKS
/// token or JWE header).
///
/// Not secret against the threat model: the disk holder sees it, and the key
/// still needs the server.  It should still not be published.
#[derive(Clone, PartialEq, Eq)]
pub struct Binding {
    alg: KemAlg,
    kid: Thumbprint,
    signing_thumbprint: Thumbprint,
    ciphertext: Box<[u8]>,
    share: [u8; 32],
    confirm: [u8; 32],
    context: BindingContext,
}

impl Binding {
    /// Id of the server exchange key this binding uses.
    #[must_use]
    pub fn kid(&self) -> &Thumbprint {
        &self.kid
    }

    /// The KEM of the server exchange key this binding uses.
    #[must_use]
    pub fn alg(&self) -> KemAlg {
        self.alg
    }

    /// Thumbprint of the signing key that vouched for the exchange key; pin
    /// it again when re-provisioning after key rotation.
    #[must_use]
    pub fn signing_thumbprint(&self) -> &Thumbprint {
        &self.signing_thumbprint
    }

    /// Replace this binding with a fresh one, then swap the protected secret
    /// (e.g. add a LUKS keyslot for the new key and token, then remove the
    /// old ones).
    ///
    /// Use it for `clevis luks regen` and to move bindings off rotated or
    /// policy-disabled keys.  A client *may* also rebind after each unlock,
    /// which stops the server from linking unlocks by ciphertext and retires
    /// shared secrets the server may have logged.  That is defence in depth
    /// only: the server cannot tell whether a client rebinds, so the
    /// protocol's guarantees do not depend on it.
    ///
    /// The exchange key of this binding is reused if it is still advertised
    /// (and allowed by the policy the advertisement was verified under);
    /// otherwise the first advertised key is used, which also migrates the
    /// binding off rotated keys.
    ///
    /// # Errors
    ///
    /// [`Error::UntrustedAdvertisement`] if `adv` was verified against a
    /// different signing key than this binding's, so rotation never changes
    /// the trust anchor silently; otherwise as for
    /// [`Advertisement::provision`].
    pub fn rebind(&self, adv: &Advertisement) -> Result<(Binding, Key)> {
        if adv.trusted_thumbprint() != &self.signing_thumbprint {
            return Err(Error::UntrustedAdvertisement);
        }
        let kid = adv.exchange_key(&self.kid).map(|_| &self.kid);
        adv.provision_with(&self.context, kid)
    }

    /// Start recovery: seal this binding's ciphertext to `exchange_key`
    /// with a fresh encapsulation, so every request looks different on the
    /// wire.
    ///
    /// `exchange_key` is the server key [`kid`](Self::kid), from
    /// `GET /key/{kid}` ([`ExchangeKey::from_jwk_json`]), from a verified
    /// advertisement, or stored next to the binding.  Its thumbprint must
    /// equal `kid`, which authenticates it.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// this binding's KEM (rebind to an allowed key before changing the
    /// policy), [`Error::KeyMismatch`] if `exchange_key` is not the
    /// binding's key, or an OpenSSL error.
    pub fn recovery_request(
        &self,
        exchange_key: &ExchangeKey,
    ) -> Result<(RecoveryRequest, PendingRecovery<'_>)> {
        self.alg.ensure_allowed()?;
        if exchange_key.kid() != &self.kid {
            return Err(Error::KeyMismatch);
        }
        let (request, response_key) =
            protocol::seal_request(self.context.domain, exchange_key, &self.ciphertext)?;
        let pending = PendingRecovery {
            binding: self,
            response_key,
        };
        Ok((request, pending))
    }

    /// Encode for storage.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(BINDING_MAGIC)
            .u8(self.alg.id())
            .fixed(self.kid.as_bytes())
            .fixed(self.signing_thumbprint.as_bytes())
            .bytes(&self.ciphertext)
            .fixed(&self.share)
            .fixed(&self.confirm)
            .finish()
    }

    /// The suite hash of the binding's ciphertext (SHA-256 for ML-KEM-768,
    /// SHA-384 for ML-KEM-1024, as the KEM's HKDF uses): a stable
    /// identifier a server can register without learning anything secret.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn ciphertext_hash(&self) -> Result<Vec<u8>> {
        primitives::digest(self.alg.hash(), &[&self.ciphertext])
    }

    /// The context this binding was created with.
    #[must_use]
    pub fn context(&self) -> &BindingContext {
        &self.context
    }

    /// Decode from storage, with the default (Tang) context.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] or [`Error::UnsupportedAlgorithm`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes_with(&BindingContext::default(), bytes)
    }

    /// Decode from storage, with the context it was provisioned under.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] or [`Error::UnsupportedAlgorithm`].
    pub fn from_bytes_with(context: &BindingContext, bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, BINDING_MAGIC, "binding")?;
        let alg = KemAlg::from_id(r.u8()?)?;
        let binding = Self {
            alg,
            kid: Thumbprint::from_bytes(r.fixed()?),
            signing_thumbprint: Thumbprint::from_bytes(r.fixed()?),
            ciphertext: r.bytes_exact(alg.ciphertext_len())?.into(),
            share: r.fixed()?,
            confirm: r.fixed()?,
            context: context.clone(),
        };
        r.finish()?;
        Ok(binding)
    }
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Binding")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .field("signing_thumbprint", &self.signing_thumbprint)
            .finish_non_exhaustive()
    }
}

/// Client state while a [`RecoveryRequest`] is in flight.
#[must_use = "finish recovery with the server's response"]
pub struct PendingRecovery<'a> {
    binding: &'a Binding,
    response_key: SecretBuf,
}

impl PendingRecovery<'_> {
    /// Unwrap the server's response and re-derive the key.
    ///
    /// # Errors
    ///
    /// [`Error::RecoveryFailed`] if the response is not for this request, was
    /// tampered with, or came from a server without the right exchange key.
    pub fn finish(self, response: &RecoveryResponse) -> Result<Key> {
        let shared_secret = protocol::open_response(self.response_key.as_ref(), response)?;
        let (key, confirm) = derive(shared_secret.as_ref(), self.binding)?;
        if ct_eq(&confirm, &self.binding.confirm) {
            Ok(key)
        } else {
            Err(Error::RecoveryFailed)
        }
    }
}

impl fmt::Debug for PendingRecovery<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingRecovery")
            .field("binding", self.binding)
            .finish_non_exhaustive()
    }
}
