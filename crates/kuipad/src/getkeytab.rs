//! FreeIPA's keytab extended operations (`freeipa/asn1/ipa.asn1`,
//! `KeytabModule`, explicit tagging).
//!
//! ```text
//! GetKeytabControl ::= CHOICE {
//!     newkeys [0] GKNewKeys, curkeys [1] GKCurrentKeys, reply [2] GKReply }
//! GKNewKeys ::= SEQUENCE {
//!     serviceIdentity [0] OCTET STRING, enctypes [1] SEQUENCE OF Int32,
//!     password [2] OCTET STRING OPTIONAL, salt [3] OCTET STRING OPTIONAL }
//! GKReply ::= SEQUENCE { newkvno Int32, keys SEQUENCE OF KrbKey }
//! KrbKey ::= SEQUENCE { key [0] TypeValuePair, salt [1] TypeValuePair OPTIONAL,
//!                       s2kparams [2] OCTET STRING OPTIONAL }
//! TypeValuePair ::= SEQUENCE { type [0] Int32, value [1] OCTET STRING }
//! ```
//!
//! The server returns the reply in a response control with the request OID.

use native_ossl::util::SecretBuf;
use synta::der::decoder::Decoder;
use synta::der::encoder::Encoder;
use synta::{Encoding, Integer, OctetStringRef, Tag, tag::TAG_SEQUENCE};

use kuipa_enroll::keytab::Enctype;

/// `KEYTAB_GET_OID`: get (and optionally generate) keys.
pub const KEYTAB_GET_OID: &str = "2.16.840.1.113730.3.8.10.5";
/// `JOIN_OID`: the enrollment extended operation (`ipa-join`).
pub const JOIN_OID: &str = "2.16.840.1.113730.3.8.10.3";

const SEQUENCE: Tag = Tag::universal_constructed(TAG_SEQUENCE);

/// Errors decoding or encoding the control.
#[derive(Debug)]
pub struct Asn1Error(String);

impl std::fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "keytab control: {}", self.0)
    }
}

impl std::error::Error for Asn1Error {}

impl From<synta::Error> for Asn1Error {
    fn from(e: synta::Error) -> Self {
        Self(e.to_string())
    }
}

/// One key from a `GKReply`.
pub struct ReplyKey {
    /// Encryption type.
    pub enctype: Enctype,
    /// Key bytes.
    pub key: SecretBuf,
}

/// A decoded `GKReply`.
pub struct Reply {
    /// The new key version number.
    pub kvno: u32,
    /// The keys.
    pub keys: Vec<ReplyKey>,
}

/// Encode `newkeys` for server-side generation (no password): the request
/// `ipa-getkeytab` sends for `-p principal` with the given enctypes.
///
/// # Errors
///
/// An encoding error.
pub fn encode_new_keys(principal: &str, enctypes: &[Enctype]) -> Result<Vec<u8>, Asn1Error> {
    encode(principal, enctypes, None)
}

/// Encode `newkeys` with keys derived from `password` on the server (the
/// realm's salt): the request `ipa-getkeytab -P` sends.
///
/// # Errors
///
/// An encoding error.
pub fn encode_password_keys(
    principal: &str,
    enctypes: &[Enctype],
    password: &[u8],
) -> Result<SecretBuf, Asn1Error> {
    Ok(SecretBuf::new(encode(principal, enctypes, Some(password))?))
}

fn encode(
    principal: &str,
    enctypes: &[Enctype],
    password: Option<&[u8]>,
) -> Result<Vec<u8>, Asn1Error> {
    let mut e = Encoder::new(Encoding::Der);
    e.start_constructed_no_guard(Tag::context_specific_constructed(0))?; // newkeys
    e.start_constructed_no_guard(SEQUENCE)?;
    e.start_constructed_no_guard(Tag::context_specific_constructed(0))?;
    e.encode(&OctetStringRef::new(principal.as_bytes()))?;
    e.end_constructed()?;
    e.start_constructed_no_guard(Tag::context_specific_constructed(1))?;
    e.start_constructed_no_guard(SEQUENCE)?;
    for t in enctypes {
        e.encode(&Integer::from(t.0))?;
    }
    e.end_constructed()?;
    e.end_constructed()?;
    if let Some(password) = password {
        e.start_constructed_no_guard(Tag::context_specific_constructed(2))?;
        e.encode(&OctetStringRef::new(password))?;
        e.end_constructed()?;
    }
    e.end_constructed()?;
    e.end_constructed()?;
    Ok(e.finish()?)
}

fn explicit<'a>(d: &mut Decoder<'a>, n: u32) -> Result<Decoder<'a>, Asn1Error> {
    Ok(d.enter_constructed(Tag::context_specific_constructed(n))?)
}

fn int32(d: &mut Decoder<'_>) -> Result<i32, Asn1Error> {
    Ok(d.decode::<Integer>()?.as_i32()?)
}

/// Decode the `reply` alternative of the response control.
///
/// # Errors
///
/// [`Asn1Error`] for anything but a well-formed reply.
pub fn decode_reply(bytes: &[u8]) -> Result<Reply, Asn1Error> {
    let mut top = Decoder::new(bytes, Encoding::Der);
    let mut choice = explicit(&mut top, 2)?;
    let mut reply = choice.enter_constructed(SEQUENCE)?;
    let kvno = u32::try_from(int32(&mut reply)?).map_err(|_| Asn1Error("negative kvno".into()))?;
    let mut list = reply.enter_constructed(SEQUENCE)?;
    let mut keys = Vec::new();
    while !list.is_empty() {
        let mut krbkey = list.enter_constructed(SEQUENCE)?;
        let mut tagged = explicit(&mut krbkey, 0)?;
        let mut pair = tagged.enter_constructed(SEQUENCE)?;
        let enctype = int32(&mut explicit(&mut pair, 0)?)?;
        let value = explicit(&mut pair, 1)?.decode::<OctetStringRef<'_>>()?;
        // The optional salt and s2kparams are not used for keytabs.
        keys.push(ReplyKey {
            enctype: Enctype(enctype),
            key: SecretBuf::from_slice(value.as_bytes()),
        });
    }
    Ok(Reply { kvno, keys })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_keys_carry_the_password() {
        let der = encode_password_keys("krbtgt/B@A", &[Enctype(18)], b"pw").unwrap();
        let der = der.as_ref();
        assert_eq!(&der[der.len() - 6..], &[0xa2, 0x04, 0x04, 0x02, b'p', b'w']);
        let plain = encode_new_keys("krbtgt/B@A", &[Enctype(18)]).unwrap();
        assert_eq!(der.len(), plain.len() + 6);
    }

    #[test]
    fn new_keys_matches_hand_encoding() {
        let der = encode_new_keys("host/a@R", &[Enctype(18), Enctype(17)]).unwrap();
        let expected: Vec<u8> = [
            &[0xa0, 0x18, 0x30, 0x16][..],
            &[0xa0, 0x0a, 0x04, 0x08],
            b"host/a@R",
            &[0xa1, 0x08, 0x30, 0x06, 0x02, 0x01, 18, 0x02, 0x01, 17],
        ]
        .concat();
        assert_eq!(der, expected);
    }

    #[test]
    fn reply_decodes() {
        // [2] { SEQUENCE { INTEGER 3, SEQUENCE { KrbKey { [0] { SEQUENCE {
        //   [0] { INTEGER 18 }, [1] { OCTET STRING 0x01.. } } } } } } }
        let key = [1u8; 4];
        let pair = [
            &[
                0x30, 0x0d, 0xa0, 0x03, 0x02, 0x01, 18, 0xa1, 0x06, 0x04, 0x04,
            ][..],
            &key,
        ]
        .concat();
        let krbkey = [&[0x30, 0x11, 0xa0, 0x0f][..], &pair].concat();
        let list = [&[0x30, 0x13][..], &krbkey].concat();
        let reply = [&[0x30, 0x18, 0x02, 0x01, 0x03][..], &list].concat();
        let choice = [&[0xa2, 0x1a][..], &reply].concat();
        let r = decode_reply(&choice).unwrap();
        assert_eq!(r.kvno, 3);
        assert_eq!(r.keys.len(), 1);
        assert_eq!(r.keys[0].enctype, Enctype(18));
        assert_eq!(r.keys[0].key.as_ref(), &key);
        assert!(decode_reply(&choice[..choice.len() - 1]).is_err());
    }
}
