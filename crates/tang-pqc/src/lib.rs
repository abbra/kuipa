//! Post-quantum Tang/Clevis-style key escrow.
//!
//! A client protects a key so that recovering it needs **both** locally
//! stored metadata (the [`Binding`]) **and** an online exchange with a
//! [`Server`].  The server stores nothing per client and never learns the
//! key.  This is the role of the McCallum-Relyea exchange in Tang, rebuilt
//! from standard post-quantum primitives in OpenSSL:
//!
//! * **ML-KEM** (FIPS 203) replaces the elliptic-curve exchange.
//! * **ML-DSA** (FIPS 204) replaces ES512 for signing advertisements.  The
//!   advertisement is a JWS over a JWK Set, as in Tang, using the RFC 9964
//!   `AKP` key type and RFC 7638 thumbprints.  Server keys can be stored as
//!   seed-form private JWKs, like the files in Tang's key directory.
//!
//! `DESIGN.md` explains how this differs from McCallum-Relyea, in particular
//! that the server sees one of the two key shares and can link repeated
//! recoveries of the same binding.  Network observers cannot: the binding's
//! ciphertext travels sealed to the server.
//!
//! # Example
//!
//! ```
//! use tang_pqc::{
//!     ExchangeKey, ExchangeKeyPair, KemAlg, RecoveryRequest, RecoveryResponse, Server,
//!     SignatureAlg, SignedAdvertisement, SigningKey,
//! };
//!
//! # fn main() -> Result<(), tang_pqc::Error> {
//! // Server setup.
//! let signing_key = SigningKey::generate(SignatureAlg::MlDsa65)?;
//! let trusted = *signing_key.public().thumbprint();   // pinned by clients
//! let server = Server::new(vec![signing_key], vec![ExchangeKeyPair::generate(KemAlg::MlKem768)?])?;
//!
//! // Provisioning: fetch and verify the advertisement, then bind.
//! let adv = SignedAdvertisement::from_json(server.advertisement()?.to_json().as_bytes())?;
//! let (binding, key) = adv.verify(&trusted)?.provision(None)?;
//! let stored = binding.to_bytes();                    // keep next to the ciphertext
//!
//! // Recovery: needs the stored binding *and* the server.  The server's
//! // exchange key (`GET /key/{kid}`) is authenticated by the binding's kid.
//! let binding = tang_pqc::Binding::from_bytes(&stored)?;
//! let wire = server.exchange_key(binding.kid())?.to_jwk_json();
//! let (request, pending) = binding.recovery_request(&ExchangeKey::from_jwk_json(wire.as_bytes())?)?;
//! let response = server.recover(&RecoveryRequest::from_bytes(&request.to_bytes())?)?;
//! let recovered = pending.finish(&RecoveryResponse::from_bytes(&response.to_bytes())?)?;
//!
//! assert_eq!(key.as_ref(), recovered.as_ref());
//! # Ok(())
//! # }
//! ```

mod adv;
mod alg;
pub mod b64;
mod client;
pub mod error;
mod jwk;
mod keys;
mod policy;
pub mod primitives;
pub mod protocol;
mod server;
pub mod wire;

pub use adv::{Advertisement, AdvertisementBuilder, SignedAdvertisement};
pub use alg::{KemAlg, SignatureAlg};
pub use client::{Binding, BindingContext, KEY_LEN, Key, PendingRecovery};
pub use error::{Error, Result};
pub use keys::{ExchangeKey, ExchangeKeyPair, SigningKey, Thumbprint, VerifyingKey};
pub use policy::{Policy, unix_seconds};
pub use protocol::{OpenedRequest, RecoveryRequest, RecoveryResponse};
pub use server::{DEFAULT_ADVERTISEMENT_VALIDITY, Server};
