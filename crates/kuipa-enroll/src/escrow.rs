//! Sealed keytabs (§7.1) and escrow recovery requests (§7.2).
//!
//! ```text
//! DEK ←$ 32 bytes                         (fresh on every seal)
//! for each server i:  (B_i, K_i) = tang-pqc provision to its escrow key,
//!                     domain "ipa-ku-enroll/v1 escrow", info = principal
//!                     W_i = GCM_{K_i}(DEK)
//! IPSK = principal ‖ [(server_i, B_i, ek_i, W_i)] ‖ GCM_DEK(MIT keytab)
//! ```
//!
//! Any one server can unseal.  Each server answers only for bindings
//! registered on an enabled host entry (`H(ct_i)`, see
//! [`Binding::ciphertext_hash`]), which it learns by opening the sealed
//! recovery request.  Each slot keeps the server's public escrow key, so
//! unsealing needs no extra round trip to seal the request.  The key is
//! authenticated by the binding's `kid`.

use native_ossl::rand::Rand;
use native_ossl::util::SecretBuf;
use tang_pqc::primitives::{self, Domain};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{Binding, BindingContext, ExchangeKey, RecoveryRequest, RecoveryResponse};

use crate::error::{Error, Result};
use crate::keytab::{Keytab, Principal};
use crate::realm::VerifiedRealm;

/// Domain of escrow bindings and recovery responses.
pub const DOMAIN: Domain = Domain::new("ipa-ku-enroll/v1 escrow");

const SEALED_MAGIC: [u8; 4] = *b"IPSK";
const REQUEST_MAGIC: [u8; 4] = *b"IPEQ";

fn context(principal: &Principal) -> BindingContext {
    BindingContext::new(DOMAIN, principal.to_string().as_bytes())
}

/// One server's way into the sealed keytab.
#[derive(Clone, PartialEq, Eq)]
struct Slot {
    server: String,
    binding: Binding,
    escrow_key: ExchangeKey,
    wrapped: Box<[u8]>,
}

/// A keytab sealed to the realm's escrow keys.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedKeytab {
    principal: Principal,
    slots: Vec<Slot>,
    sealed: Box<[u8]>,
}

impl std::fmt::Debug for SealedKeytab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedKeytab")
            .field("principal", &self.principal)
            .field("servers", &self.servers())
            .finish_non_exhaustive()
    }
}

/// The binding hash to register on each server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The server.
    pub server: String,
    /// `H(ct)` of the binding to that server.
    pub binding: [u8; 32],
}

/// Bindings and a data key, made before the keytab they will protect is
/// known: the registrations travel in the same rekey request that delivers
/// the new keys (§7.2).
pub struct Sealer {
    principal: Principal,
    dek: SecretBuf,
    slots: Vec<Slot>,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer")
            .field("principal", &self.principal)
            .finish_non_exhaustive()
    }
}

impl Sealer {
    /// Bind a fresh data key to the escrow key of every server in
    /// `servers` (each verified for `principal`'s realm).
    ///
    /// Returns the sealer and the registrations to send.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] without servers or when one has no escrow key,
    /// [`Error::WrongRealm`] for a server of another realm, or a crypto
    /// error.
    pub fn prepare(
        principal: &Principal,
        servers: &[&VerifiedRealm],
    ) -> Result<(Self, Vec<Registration>)> {
        if servers.is_empty() {
            return Err(Error::Missing("escrow servers"));
        }
        let ctx = context(principal);
        let mut dek = SecretBuf::with_len(32);
        Rand::fill_private(dek.as_mut_slice())?;
        let mut slots = Vec::with_capacity(servers.len());
        let mut registrations = Vec::with_capacity(servers.len());
        for realm in servers {
            if realm.info().realm != principal.realm() {
                return Err(Error::WrongRealm);
            }
            let escrow_key = realm.escrow_key()?.clone();
            let (binding, key) = realm
                .advertisement()
                .provision_with(&ctx, Some(escrow_key.kid()))?;
            registrations.push(Registration {
                server: realm.server().into(),
                binding: binding.ciphertext_hash()?,
            });
            slots.push(Slot {
                server: realm.server().into(),
                wrapped: primitives::seal(key.as_ref(), dek.as_ref())?.into(),
                binding,
                escrow_key,
            });
        }
        Ok((
            Self {
                principal: principal.clone(),
                dek,
                slots,
            },
            registrations,
        ))
    }

    /// Seal `keytab`.  Consumes the sealer: each data key encrypts once.
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] for a keytab of another principal, or a crypto
    /// error.
    pub fn seal(self, keytab: &Keytab) -> Result<SealedKeytab> {
        if keytab.principal() != &self.principal {
            return Err(Error::Mismatch("keytab principal"));
        }
        let sealed = primitives::seal(self.dek.as_ref(), keytab.to_mit()?.as_ref())?.into();
        Ok(SealedKeytab {
            principal: self.principal,
            slots: self.slots,
            sealed,
        })
    }
}

impl SealedKeytab {
    /// Seal `keytab` to the escrow key of every server in `servers`:
    /// [`Sealer::prepare`] followed by [`Sealer::seal`].
    ///
    /// # Errors
    ///
    /// As for those.
    pub fn seal(keytab: &Keytab, servers: &[&VerifiedRealm]) -> Result<(Self, Vec<Registration>)> {
        let (sealer, registrations) = Sealer::prepare(keytab.principal(), servers)?;
        Ok((sealer.seal(keytab)?, registrations))
    }

    /// The principal whose keytab this is.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The servers that can unseal it, in order.
    #[must_use]
    pub fn servers(&self) -> Vec<&str> {
        self.slots.iter().map(|s| s.server.as_str()).collect()
    }

    /// Unseal, trying each server in turn.
    ///
    /// `recover(server, request)` sends the request to `server` and returns
    /// its response, or `None` if the server could not be reached or
    /// refused.  The first server that answers correctly wins.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] if no server could unseal it, or a crypto error.
    pub fn unseal(
        &self,
        mut recover: impl FnMut(&str, &EscrowRequest) -> Option<RecoveryResponse>,
    ) -> Result<Keytab> {
        for slot in &self.slots {
            let (request, pending) = slot.binding.recovery_request(&slot.escrow_key)?;
            let request = EscrowRequest {
                principal: self.principal.clone(),
                request,
            };
            let Some(response) = recover(&slot.server, &request) else {
                continue;
            };
            let Ok(key) = pending.finish(&response) else {
                continue;
            };
            let dek =
                primitives::open(key.as_ref(), &slot.wrapped).map_err(|_| Error::BadResponse)?;
            let plain =
                primitives::open(dek.as_ref(), &self.sealed).map_err(|_| Error::BadResponse)?;
            let keytab = Keytab::from_mit(plain.as_ref())?;
            if keytab.principal() != &self.principal {
                return Err(Error::Mismatch("sealed keytab principal"));
            }
            return Ok(keytab);
        }
        Err(Error::Refused)
    }

    /// Encode for storage.
    ///
    /// # Panics
    ///
    /// Never for keytabs sealed by this crate (at most 255 servers).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(SEALED_MAGIC);
        w.str(&self.principal.to_string())
            .u8(u8::try_from(self.slots.len()).expect("at most 255 servers"));
        for s in &self.slots {
            w.str(&s.server)
                .bytes(&s.binding.to_bytes())
                .bytes(s.escrow_key.as_bytes())
                .bytes(&s.wrapped);
        }
        w.bytes(&self.sealed).finish()
    }

    /// Decode from storage.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, SEALED_MAGIC, "sealed keytab")?;
        let principal: Principal = r.str()?.parse()?;
        let ctx = context(&principal);
        let slots = (0..r.u8()?)
            .map(|_| {
                let server = r.str()?.to_owned();
                let binding = Binding::from_bytes_with(&ctx, r.bytes()?)?;
                let escrow_key = ExchangeKey::from_bytes(binding.alg(), r.bytes()?)?;
                if escrow_key.kid() != binding.kid() {
                    return Err(Error::Mismatch("escrow key"));
                }
                Ok(Slot {
                    server,
                    binding,
                    escrow_key,
                    wrapped: r.bytes()?.into(),
                })
            })
            .collect::<Result<_>>()?;
        let sealed = r.bytes()?.into();
        r.finish()?;
        Ok(Self {
            principal,
            slots,
            sealed,
        })
    }
}

/// `POST /ipa/ku/rec/{kid}`: a `tang-pqc` recovery request naming the
/// principal, so the server can check the binding is registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowRequest {
    principal: Principal,
    request: RecoveryRequest,
}

impl EscrowRequest {
    /// The principal.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The recovery request.
    #[must_use]
    pub fn recovery(&self) -> &RecoveryRequest {
        &self.request
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(REQUEST_MAGIC)
            .str(&self.principal.to_string())
            .bytes(&self.request.to_bytes())
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, REQUEST_MAGIC, "escrow request")?;
        let principal = r.str()?.parse()?;
        let request = RecoveryRequest::from_bytes(r.bytes()?)?;
        r.finish()?;
        Ok(Self { principal, request })
    }
}
