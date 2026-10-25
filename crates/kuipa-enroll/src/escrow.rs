//! Sealed keytabs and files (§7.1, §7.5), their registration (§7.5) and
//! the unified escrow recovery request (§7.2, §7.6.5).
//!
//! ```text
//! DEK ←$ 32 bytes                         (fresh on every seal)
//! V = machine vault of (principal, kind)  (§7.6.8)
//! for each server i:  (B_i, K_i, t_i) = tang-pqc provision to its escrow key,
//!                     domain "ipa-ku-enroll/v1 escrow", info = principal,
//!                     committed to (principal, V)
//!                     W_i = GCM_{K_i}(DEK)
//! IPSK = principal ‖ [(server_i, B_i, ek_i, t_i, W_i)] ‖ GCM_DEK(MIT keytab)
//! IPSF = principal ‖ [(server_i, B_i, ek_i, t_i, W_i)] ‖ GCM_DEK(file)
//! ```
//!
//! Any one server can unseal.  A recovery request names the principal and
//! the vault and carries the slot's commitment `t_i`, which the server
//! checks after opening the request, so a binding cannot be presented under
//! another principal or vault than it was made for.  For a machine vault
//! the server then answers only for bindings registered in that kind's set
//! on the enabled directory entry of the principal (`H(ct_i)`, see
//! [`Binding::ciphertext_hash`]).  Each slot keeps the server's public escrow key, so
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

/// A binding's identity: the suite hash of its ciphertext
/// ([`Binding::ciphertext_hash`]), 32 bytes for ML-KEM-768 and 48 for
/// ML-KEM-1024 (CNSA 2.0), as the KEM's HKDF hash goes.
pub use crate::merkle::Hash as BindingHash;

/// Domain of escrow bindings and recovery responses.
pub const DOMAIN: Domain = Domain::new("ipa-ku-enroll/v1 escrow");

const SEALED_MAGIC: [u8; 4] = *b"IPSK";
const SEALED_FILE_MAGIC: [u8; 4] = *b"IPSF";
const REQUEST_MAGIC: [u8; 4] = *b"IPEQ";
const REGISTER_MAGIC: [u8; 4] = *b"IPRP";
const REGISTERED_MAGIC: [u8; 4] = *b"IPRA";
const COMMIT_MAGIC: [u8; 4] = *b"IPCV";

fn context(principal: &Principal) -> BindingContext {
    BindingContext::new(DOMAIN, principal.to_string().as_bytes())
}

/// What a sealed object holds, and so which of its principal's binding
/// sets opens it (§7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The principal's keytab.  Its bindings are replaced at every seal.
    Keytab,
    /// Any other file.  Its bindings are added beside the others', and
    /// retired one seal at a time.
    File,
}

impl Kind {
    const fn magic(self) -> [u8; 4] {
        match self {
            Self::Keytab => SEALED_MAGIC,
            Self::File => SEALED_FILE_MAGIC,
        }
    }

    const fn id(self) -> u8 {
        match self {
            Self::Keytab => 1,
            Self::File => 2,
        }
    }

    fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Keytab),
            2 => Ok(Self::File),
            _ => Err(Error::Malformed("binding set")),
        }
    }
}

/// A vault: a user vault's random id, or the id a machine vault derives
/// from its principal and kind (§7.6.8).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaultId([u8; 16]);

impl VaultId {
    /// From its bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The machine vault of `principal`'s `kind` set, as escrowed to an
    /// `alg` key: `H("ipa-ku-enroll/v1 machine vault" ‖ kind ‖ principal)`,
    /// truncated, `H` the KEM's suite hash (SHA-256 for ML-KEM-768,
    /// SHA-384 for ML-KEM-1024).
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn machine(principal: &Principal, kind: Kind, alg: tang_pqc::KemAlg) -> Result<Self> {
        let digest = primitives::digest(
            alg.hash(),
            &[
                b"ipa-ku-enroll/v1 machine vault",
                &[kind.id()],
                principal.to_string().as_bytes(),
            ],
        )?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        Ok(Self(id))
    }

    /// Which machine vault of `principal` this is, if it is one, for a
    /// request to an `alg` key.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn machine_kind(
        &self,
        principal: &Principal,
        alg: tang_pqc::KemAlg,
    ) -> Result<Option<Kind>> {
        for kind in [Kind::Keytab, Kind::File] {
            if Self::machine(principal, kind, alg)? == *self {
                return Ok(Some(kind));
            }
        }
        Ok(None)
    }
}

impl std::fmt::Display for VaultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl std::str::FromStr for VaultId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Malformed("vault id"));
        }
        let mut id = [0u8; 16];
        for (i, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_| Error::Malformed("vault id"))?;
        }
        Ok(Self(id))
    }
}

impl serde::Serialize for VaultId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for VaultId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for VaultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VaultId({self})")
    }
}

/// What a binding commits to: its principal and vault.
#[must_use]
pub fn commitment_data(principal: &Principal, vault: &VaultId) -> Vec<u8> {
    Writer::new(COMMIT_MAGIC)
        .str(&principal.to_string())
        .fixed(vault.as_bytes())
        .finish()
}

/// One server's way into the sealed object.
#[derive(Clone, PartialEq, Eq)]
struct Slot {
    server: String,
    binding: Binding,
    escrow_key: ExchangeKey,
    commitment: [u8; 32],
    wrapped: Box<[u8]>,
}

/// A keytab or file sealed to the realm's escrow keys.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    kind: Kind,
    principal: Principal,
    slots: Vec<Slot>,
    ciphertext: Box<[u8]>,
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("kind", &self.kind)
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
    pub binding: BindingHash,
}

/// Bindings and a data key, made before what they will protect is known:
/// for a host keytab, the registrations travel in the same rekey request
/// that delivers the new keys (§7.2); otherwise in a registration of their
/// own (§7.5).
pub struct Sealer {
    kind: Kind,
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
    /// `servers` (each verified for `principal`'s realm), committed to
    /// `principal`'s machine vault for `kind`.
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
        kind: Kind,
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
            // Each slot commits to the vault id of its own KEM's hash.
            let vault = VaultId::machine(principal, kind, escrow_key.alg())?;
            let committed = commitment_data(principal, &vault);
            let (binding, key, commitment) = realm.advertisement().provision_committed(
                &ctx,
                Some(escrow_key.kid()),
                &committed,
            )?;
            registrations.push(Registration {
                server: realm.server().into(),
                binding: BindingHash::from_slice(&binding.ciphertext_hash()?)?,
            });
            slots.push(Slot {
                server: realm.server().into(),
                wrapped: primitives::seal(key.as_ref(), dek.as_ref())?.into(),
                binding,
                escrow_key,
                commitment,
            });
        }
        Ok((
            Self {
                kind,
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
    pub fn seal(self, keytab: &Keytab) -> Result<Sealed> {
        if keytab.principal() != &self.principal {
            return Err(Error::Mismatch("keytab principal"));
        }
        self.seal_as(Kind::Keytab, keytab.to_mit()?.as_ref())
    }

    /// Seal an MIT keytab as it is, byte for byte (the name types its
    /// writer chose stay).  Consumes the sealer.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for no keytab, [`Error::Mismatch`] for a keytab
    /// of another principal, or a crypto error.
    pub fn seal_mit(self, mit: &[u8]) -> Result<Sealed> {
        if Keytab::from_mit(mit)?.principal() != &self.principal {
            return Err(Error::Mismatch("keytab principal"));
        }
        self.seal_as(Kind::Keytab, mit)
    }

    /// Seal the contents of a file.  Consumes the sealer.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn seal_file(self, contents: &[u8]) -> Result<Sealed> {
        self.seal_as(Kind::File, contents)
    }

    fn seal_as(self, kind: Kind, plain: &[u8]) -> Result<Sealed> {
        if kind != self.kind {
            return Err(Error::Mismatch("prepared for another kind"));
        }
        let ciphertext = primitives::seal(self.dek.as_ref(), plain)?.into();
        Ok(Sealed {
            kind,
            principal: self.principal,
            slots: self.slots,
            ciphertext,
        })
    }
}

impl Sealed {
    /// Seal `keytab` to the escrow key of every server in `servers`:
    /// [`Sealer::prepare`] followed by [`Sealer::seal`].
    ///
    /// # Errors
    ///
    /// As for those.
    pub fn seal(keytab: &Keytab, servers: &[&VerifiedRealm]) -> Result<(Self, Vec<Registration>)> {
        let (sealer, registrations) = Sealer::prepare(keytab.principal(), Kind::Keytab, servers)?;
        Ok((sealer.seal(keytab)?, registrations))
    }

    /// A keytab or a file.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The principal whose keytab this is, or on whose entry the bindings
    /// of a file are registered.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// `H(ct)` of each slot's binding: what is registered for it.
    ///
    /// # Errors
    ///
    /// A crypto error.
    pub fn bindings(&self) -> Result<Vec<BindingHash>> {
        self.slots
            .iter()
            .map(|s| BindingHash::from_slice(&s.binding.ciphertext_hash()?))
            .collect()
    }

    /// The servers that can unseal it, in order.
    #[must_use]
    pub fn servers(&self) -> Vec<&str> {
        self.slots.iter().map(|s| s.server.as_str()).collect()
    }

    /// Unseal a keytab, trying each server in turn: as
    /// [`unseal_contents`](Self::unseal_contents), for a sealed keytab of
    /// its principal.
    ///
    /// # Errors
    ///
    /// As for that, and [`Error::Mismatch`] for a sealed file or a keytab
    /// of another principal.
    pub fn unseal(
        &self,
        recover: impl FnMut(&str, &EscrowRequest) -> Option<RecoveryResponse>,
    ) -> Result<Keytab> {
        Keytab::from_mit(self.unseal_mit(recover)?.as_ref())
    }

    /// Unseal a keytab, trying each server in turn, and return it in MIT
    /// form as it was sealed.
    ///
    /// # Errors
    ///
    /// As for [`unseal`](Self::unseal).
    pub fn unseal_mit(
        &self,
        recover: impl FnMut(&str, &EscrowRequest) -> Option<RecoveryResponse>,
    ) -> Result<SecretBuf> {
        if self.kind != Kind::Keytab {
            return Err(Error::Mismatch("a sealed file, not a keytab"));
        }
        let plain = self.unseal_contents(recover)?;
        if Keytab::from_mit(plain.as_ref())?.principal() != &self.principal {
            return Err(Error::Mismatch("sealed keytab principal"));
        }
        Ok(plain)
    }

    /// Unseal, trying each server in turn, and return what was sealed.
    ///
    /// `recover(server, request)` sends the request to `server` and returns
    /// its response, or `None` if the server could not be reached or
    /// refused.  The first server that answers correctly wins.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] if no server could unseal it, or a crypto error.
    pub fn unseal_contents(
        &self,
        mut recover: impl FnMut(&str, &EscrowRequest) -> Option<RecoveryResponse>,
    ) -> Result<SecretBuf> {
        for slot in &self.slots {
            let vault = VaultId::machine(&self.principal, self.kind, slot.escrow_key.alg())?;
            let (request, pending) = slot.binding.recovery_request(&slot.escrow_key)?;
            let request = EscrowRequest::for_vault(
                self.principal.clone(),
                vault,
                slot.commitment,
                request,
                None,
            );
            let Some(response) = recover(&slot.server, &request) else {
                continue;
            };
            let Ok(key) = pending.finish(&response) else {
                continue;
            };
            let dek =
                primitives::open(key.as_ref(), &slot.wrapped).map_err(|_| Error::BadResponse)?;
            return primitives::open(dek.as_ref(), &self.ciphertext)
                .map_err(|_| Error::BadResponse);
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
        let mut w = Writer::new(self.kind.magic());
        w.str(&self.principal.to_string())
            .u8(u8::try_from(self.slots.len()).expect("at most 255 servers"));
        for s in &self.slots {
            w.str(&s.server)
                .bytes(&s.binding.to_bytes())
                .bytes(s.escrow_key.as_bytes())
                .fixed(&s.commitment)
                .bytes(&s.wrapped);
        }
        w.bytes(&self.ciphertext).finish()
    }

    /// Decode from storage: a sealed keytab or file.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let kind = if bytes.starts_with(&SEALED_FILE_MAGIC) {
            Kind::File
        } else {
            Kind::Keytab
        };
        let mut r = Reader::new(bytes, kind.magic(), "sealed keytab or file")?;
        let principal: Principal = r.str()?.parse()?;
        let ctx = context(&principal);
        let slots = (0..r.u8()?)
            .map(|_| {
                let server = r.str()?.to_owned();
                if !crate::realm::is_safe_name(&server) {
                    return Err(Error::Malformed("sealed slot server"));
                }
                let binding = Binding::from_bytes_with(&ctx, r.bytes()?)?;
                let escrow_key = ExchangeKey::from_bytes(binding.alg(), r.bytes()?)?;
                if escrow_key.kid() != binding.kid() {
                    return Err(Error::Mismatch("escrow key"));
                }
                Ok(Slot {
                    server,
                    binding,
                    escrow_key,
                    commitment: r.fixed()?,
                    wrapped: r.bytes()?.into(),
                })
            })
            .collect::<Result<_>>()?;
        let ciphertext = r.bytes()?.into();
        r.finish()?;
        Ok(Self {
            kind,
            principal,
            slots,
            ciphertext,
        })
    }
}

/// What a registration (`POST /ipa/ku/register/{kid}`, §7.5) changes,
/// sent as the request's operation data beside the new bindings.  The
/// caller must be `principal` itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterParams {
    /// Whose entry holds the bindings.
    pub principal: Principal,
    /// [`Kind::Keytab`]: the new bindings replace the keytab set.
    /// [`Kind::File`]: they join the file set, and `retire` leaves it.
    pub kind: Kind,
    /// File bindings to remove: those of the seal being replaced or undone.
    pub retire: Vec<BindingHash>,
}

impl RegisterParams {
    /// Encode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for more than 255 bindings to retire.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(REGISTER_MAGIC);
        w.str(&self.principal.to_string())
            .u8(self.kind.id())
            .u8(u8::try_from(self.retire.len())
                .map_err(|_| Error::Malformed("too many bindings to retire"))?);
        for b in &self.retire {
            w.bytes(b);
        }
        Ok(w.finish())
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, REGISTER_MAGIC, "registration")?;
        let principal = r.str()?.parse()?;
        let kind = Kind::from_id(r.u8()?)?;
        let retire = (0..r.u8()?)
            .map(|_| BindingHash::from_slice(r.bytes()?))
            .collect::<Result<_>>()?;
        r.finish()?;
        Ok(Self {
            principal,
            kind,
            retire,
        })
    }

    /// The server's answer to an accepted registration: the principal it
    /// changed.
    #[must_use]
    pub fn acknowledgement(&self) -> Vec<u8> {
        Writer::new(REGISTERED_MAGIC)
            .str(&self.principal.to_string())
            .finish()
    }

    /// Check the server's answer.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], or [`Error::Mismatch`] for another principal.
    pub fn check_acknowledgement(&self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload, REGISTERED_MAGIC, "registration answer")?;
        let principal: Principal = r.str()?.parse()?;
        r.finish()?;
        if principal != self.principal {
            return Err(Error::Mismatch("registered principal"));
        }
        Ok(())
    }
}

/// `POST /ipa/ku/rec/{kid}`: the unified recovery request (§7.6.5): a
/// `tang-pqc` recovery request naming the principal and the vault, with the
/// binding's commitment to both; for a user vault also the device to answer
/// to and the owner's GSS-API token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowRequest {
    principal: Principal,
    vault: VaultId,
    commitment: [u8; 32],
    request: RecoveryRequest,
    device: Option<tang_pqc::Thumbprint>,
    session: Vec<u8>,
    ticket: Vec<u8>,
    release: Option<[u8; 16]>,
}

/// `IPEQ` version 2 adds the release request id (`DESIGN-approvals.md` §4).
const REQUEST_VERSION_RELEASE: u8 = 2;

impl EscrowRequest {
    /// A request for a user vault, answered to `device` if given.
    #[must_use]
    pub fn for_vault(
        principal: Principal,
        vault: VaultId,
        commitment: [u8; 32],
        request: RecoveryRequest,
        device: Option<tang_pqc::Thumbprint>,
    ) -> Self {
        Self {
            principal,
            vault,
            commitment,
            request,
            device,
            session: Vec::new(),
            ticket: Vec::new(),
            release: None,
        }
    }

    /// The same request naming an approved release request.
    #[must_use]
    pub fn with_release(mut self, id: [u8; 16]) -> Self {
        self.release = Some(id);
        self
    }

    /// The approved release request it names, if any.
    #[must_use]
    pub fn release(&self) -> Option<&[u8; 16]> {
        self.release.as_ref()
    }

    /// The same request carrying a re-authentication session token.
    #[must_use]
    pub fn with_session(mut self, token: Vec<u8>) -> Self {
        self.session = token;
        self
    }

    /// The session token, empty without one.
    #[must_use]
    pub fn session(&self) -> &[u8] {
        &self.session
    }

    /// The same request carrying the owner's GSS-API `token`, made with
    /// [`ticket_binding`](Self::ticket_binding) as its channel binding.
    #[must_use]
    pub fn with_ticket(mut self, token: Vec<u8>) -> Self {
        self.ticket = token;
        self
    }

    /// The device the answer is encrypted to.
    #[must_use]
    pub fn device(&self) -> Option<&tang_pqc::Thumbprint> {
        self.device.as_ref()
    }

    /// The owner's GSS-API token, empty without one.
    #[must_use]
    pub fn ticket(&self) -> &[u8] {
        &self.ticket
    }

    /// The channel binding of the token: `H("ipa-ku-enroll/v1 vault
    /// unlock" ‖ the request without its token)`, `H` the recovery KEM's
    /// suite hash (SHA-256 for ML-KEM-768, SHA-384 for ML-KEM-1024),
    /// taken to the 32 bytes every channel binding has.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn ticket_binding(&self) -> Result<[u8; crate::join::CHANNEL_BINDING_LEN]> {
        let bare = Self {
            ticket: Vec::new(),
            ..self.clone()
        };
        let digest = primitives::digest(
            self.request.alg().hash(),
            &[b"ipa-ku-enroll/v1 vault unlock", &bare.to_bytes()],
        )?;
        Ok(crate::join::channel_binding_of(&digest))
    }

    /// The principal.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The vault.
    #[must_use]
    pub fn vault(&self) -> &VaultId {
        &self.vault
    }

    /// The binding's commitment to [`commitment_data`] of the principal and
    /// vault.
    #[must_use]
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    /// The recovery request.
    #[must_use]
    pub fn recovery(&self) -> &RecoveryRequest {
        &self.request
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Version 1 without a release request, as every client sent it.
        let mut w = match self.release {
            None => Writer::new(REQUEST_MAGIC),
            Some(_) => Writer::with_version(REQUEST_MAGIC, REQUEST_VERSION_RELEASE),
        };
        w.str(&self.principal.to_string())
            .fixed(self.vault.as_bytes())
            .fixed(&self.commitment)
            .bytes(&self.request.to_bytes())
            .bytes(self.device.as_ref().map_or(&[][..], |d| d.as_bytes()))
            .bytes(&self.session)
            .bytes(&self.ticket);
        if let Some(id) = &self.release {
            w.fixed(id);
        }
        w.finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let versioned = bytes.get(4) == Some(&REQUEST_VERSION_RELEASE);
        let mut r = if versioned {
            Reader::with_version(
                bytes,
                REQUEST_MAGIC,
                REQUEST_VERSION_RELEASE,
                "escrow request",
            )?
        } else {
            Reader::new(bytes, REQUEST_MAGIC, "escrow request")?
        };
        let principal = r.str()?.parse()?;
        let vault = VaultId::from_bytes(r.fixed()?);
        let commitment = r.fixed()?;
        let request = RecoveryRequest::from_bytes(r.bytes()?)?;
        let device = match r.bytes()? {
            [] => None,
            id => Some(tang_pqc::Thumbprint::from_bytes(
                id.try_into().map_err(|_| Error::Malformed("device id"))?,
            )),
        };
        let session = r.bytes()?.to_vec();
        let ticket = r.bytes()?.to_vec();
        let release = if versioned { Some(r.fixed()?) } else { None };
        r.finish()?;
        Ok(Self {
            principal,
            vault,
            commitment,
            request,
            device,
            session,
            ticket,
            release,
        })
    }
}

#[cfg(test)]
mod tests {
    use tang_pqc::KemAlg;
    use tang_pqc::primitives::sha256;

    use super::*;

    #[test]
    fn machine_vault_ids_follow_the_escrow_kem() {
        // ML-KEM-768 keeps the SHA-256 ids already sealed to; ML-KEM-1024
        // (CNSA 2.0) gives a SHA-384 one, and each id names its own KEM.
        let host: Principal = "host/web1.example.test@EXAMPLE.TEST".parse().unwrap();
        let old = sha256(&[
            b"ipa-ku-enroll/v1 machine vault",
            &[Kind::Keytab.id()],
            host.to_string().as_bytes(),
        ])
        .unwrap();
        let v768 = VaultId::machine(&host, Kind::Keytab, KemAlg::MlKem768).unwrap();
        assert_eq!(v768.as_bytes(), &old[..16]);
        let v1024 = VaultId::machine(&host, Kind::Keytab, KemAlg::MlKem1024).unwrap();
        assert_ne!(v768, v1024);
        assert_eq!(
            v1024.machine_kind(&host, KemAlg::MlKem1024).unwrap(),
            Some(Kind::Keytab)
        );
        assert_eq!(v1024.machine_kind(&host, KemAlg::MlKem768).unwrap(), None);
    }
}
