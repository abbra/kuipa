//! Spending a voucher's salt on its home server (§9).
//!
//! A voucher names the IPA server that owns its single use
//! ([`crate::voucher::Claims::server`]).  A server that receives the join, the
//! redeemer, does not write the spent record itself unless it is that server:
//! it asks the home server over `POST /ipa/ku/peer/spend`, and adds the host
//! only when the home server has recorded the salt.  Every attempt for a
//! salt therefore goes through one directory, whose add of the spent record
//! is the gate, and two servers cannot each accept the same voucher before
//! their directories replicate.
//!
//! The request is authenticated like a peer sync: a GSS-API token for the
//! home server's `ipa-ku` service from the redeemer's `ipa-ku/<fqdn>` key, with
//! a channel binding over every other field.

use tang_pqc::primitives;
use tang_pqc::wire::{Reader, Writer};

use crate::error::{Error, Result};
use crate::server::DirectoryError;

const SPEND_MAGIC: [u8; 4] = *b"IPVS";
const SPEND_VERSION: u8 = 1;
const SPEND_LABEL: &[u8] = b"ipa-ku-enroll/v1 voucher spend";

/// The longest request body: a voucher and a few names.
pub const MAX_SPEND_BYTES: usize = 16 * 1024;

/// What the redeemer asks of the home server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpendOp {
    /// Record the salt as spent for this redeemer and host.
    Spend,
    /// Remove the record the redeemer wrote, because the host it made does
    /// not exist.
    Release,
}

impl SpendOp {
    fn code(self) -> u8 {
        match self {
            Self::Spend => 1,
            Self::Release => 2,
        }
    }
}

/// A request to the home server.
#[derive(Clone, Debug)]
pub struct SpendRequest {
    /// What to do.
    pub op: SpendOp,
    /// The redeemer, the server that took the join.
    pub sender: String,
    /// The home server.
    pub receiver: String,
    /// The host the voucher enrolls.
    pub fqdn: String,
    /// The voucher, in its text form.
    pub voucher: Vec<u8>,
    /// The GSS-API token.
    pub token: Vec<u8>,
}

impl SpendRequest {
    /// The channel binding for the token: a hash of every other field,
    /// SHA-384 taken to the 32 bytes every channel binding has.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn channel_binding(
        op: SpendOp,
        sender: &str,
        receiver: &str,
        fqdn: &str,
        voucher: &[u8],
    ) -> Result<[u8; 32]> {
        let mut w = Writer::with_version(SPEND_MAGIC, SPEND_VERSION);
        w.u8(op.code())
            .str(sender)
            .str(receiver)
            .str(fqdn)
            .bytes(voucher);
        let digest = primitives::sha384(&[SPEND_LABEL, &w.finish()])?;
        Ok(crate::join::channel_binding_of(&digest))
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_version(SPEND_MAGIC, SPEND_VERSION);
        w.u8(self.op.code())
            .str(&self.sender)
            .str(&self.receiver)
            .str(&self.fqdn)
            .bytes(&self.voucher)
            .bytes(&self.token);
        w.finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::with_version(buf, SPEND_MAGIC, SPEND_VERSION, "voucher spend")?;
        let op = match r.u8()? {
            1 => SpendOp::Spend,
            2 => SpendOp::Release,
            _ => return Err(Error::Malformed("voucher spend operation")),
        };
        let request = Self {
            op,
            sender: r.str()?.into(),
            receiver: r.str()?.into(),
            fqdn: r.str()?.into(),
            voucher: r.bytes()?.into(),
            token: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(request)
    }
}

/// Why the home server did not record or release a salt.
#[derive(Debug)]
pub enum SpendError {
    /// The home server answered no: the voucher is spent, not valid, or
    /// not this server's.  Final.
    Refused(DirectoryError),
    /// The home server could not be asked or did not finish: try again
    /// later.  The salt may or may not be recorded.
    Unavailable(DirectoryError),
}

impl std::fmt::Display for SpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(e) => write!(f, "the voucher's home server refused: {e}"),
            Self::Unavailable(e) => write!(f, "the voucher's home server is unavailable: {e}"),
        }
    }
}

impl std::error::Error for SpendError {}

/// Asks a voucher's home server to spend or release its salt.
pub trait VoucherSpender: Send + Sync + std::fmt::Debug {
    /// Record `voucher`'s salt as spent for a join of `fqdn` on this server.
    /// Asking again for the same host succeeds.
    ///
    /// # Errors
    ///
    /// [`SpendError::Refused`] when the salt is spent for another host or
    /// the voucher does not verify at `home`; [`SpendError::Unavailable`]
    /// when `home` could not be reached or did not answer.
    fn spend(&self, home: &str, fqdn: &str, voucher: &[u8]) -> std::result::Result<(), SpendError>;

    /// Remove the record this server wrote for `voucher` and `fqdn`.
    ///
    /// # Errors
    ///
    /// As [`spend`](Self::spend).
    fn release(
        &self,
        home: &str,
        fqdn: &str,
        voucher: &[u8],
    ) -> std::result::Result<(), SpendError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_binding() {
        let r = SpendRequest {
            op: SpendOp::Spend,
            sender: "ipa2.example.test".into(),
            receiver: "ipa1.example.test".into(),
            fqdn: "web1.example.test".into(),
            voucher: b"ipa-ku-voucher1:AAAA".to_vec(),
            token: vec![1, 2, 3],
        };
        let back = SpendRequest::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(back.op, SpendOp::Spend);
        assert_eq!(back.sender, r.sender);
        assert_eq!(back.receiver, r.receiver);
        assert_eq!(back.fqdn, r.fqdn);
        assert_eq!(back.voucher, r.voucher);
        assert_eq!(back.token, r.token);
        assert!(SpendRequest::from_bytes(&r.to_bytes()[..10]).is_err());

        // Every field is in the channel binding, the operation included:
        // a captured spend cannot be replayed as a release.
        let bind = |op, sender: &str, receiver: &str, fqdn: &str, voucher: &[u8]| {
            SpendRequest::channel_binding(op, sender, receiver, fqdn, voucher).unwrap()
        };
        let (from, to, host, voucher) =
            (&r.sender[..], &r.receiver[..], &r.fqdn[..], &r.voucher[..]);
        let base = bind(SpendOp::Spend, from, to, host, voucher);
        assert_ne!(base, bind(SpendOp::Release, from, to, host, voucher));
        assert_ne!(
            base,
            bind(SpendOp::Spend, "ipa3.example.test", to, host, voucher)
        );
        assert_ne!(
            base,
            bind(SpendOp::Spend, from, "ipa3.example.test", host, voucher)
        );
        assert_ne!(
            base,
            bind(SpendOp::Spend, from, to, "web2.example.test", voucher)
        );
        assert_ne!(base, bind(SpendOp::Spend, from, to, host, b"other"));
    }
}
