//! TLS server authentication against the CA certificates a realm
//! advertises (§10.3), Merkle Tree CAs included.
//!
//! A certificate signed the ordinary way is verified by OpenSSL against the
//! ordinary CAs, as before.  A Merkle Tree certificate
//! (draft-ietf-plants-merkle-tree-certs §6.2) carries an `MTCProof` where
//! the signature would be, which OpenSSL cannot check: it is verified by
//! the §7.2 procedure against the Merkle Tree CA that issued it, the way
//! Akāmu's client does.  That CA's certificate is the whole relying-party
//! configuration (§7.1): its subject is the CA ID, its key the CA
//! cosigner's, and its Merkle Tree CA extension the cosigner's signature
//! algorithm, the serials its logs may use and, by its type, SHA-256 as the
//! log hash.  The CA's own cosignature is required.  There are no trusted
//! subtrees, so a landmark-relative certificate, which carries no
//! cosignature, is refused.
//!
//! The two kinds never mix.  A Merkle Tree CA is not in OpenSSL's store, so
//! its cosigner key, which signs subtrees (§5.4), cannot pass for a key that
//! signs certificates; and the MTC path accepts only a certificate a Merkle
//! Tree CA issued directly, not a chain through one.

use std::sync::Arc;

use native_ossl::x509::X509;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error as TlsError};
use rustls_native_ossl::cert_verifier::{
    CertChainVerifier, OsslChainVerifier, OsslServerCertVerifier,
};
use synta::{Decoder, Encoding, RelativeOid, Tag};
use synta_certificate::{
    Certificate, Extensions, OpensslSignatureVerifier, SignatureVerifier, cert_byte_ranges, oids,
};
use synta_mtc::crypto::{HashAlgorithm, MtcProof, hash_interior, hash_log_entry, is_valid_subtree};
use synta_mtc::integration::tbs_certificate_to_log_entry;
use synta_mtc::types::constants::{
    MTC_MAX_LOG_INDEX, is_mtc_ca_extension_oid, is_mtc_proof_oid, is_rdna_trust_anchor_id_oid,
};
use synta_mtc::types::{MTCCertificationAuthority, MerkleTreeCertEntry};
use synta_x509_verification::certificate::time_to_unix;
use synta_x509_verification::extensions::{decode_extended_key_usage, find_san};
use synta_x509_verification::policy::Subject;
use synta_x509_verification::types::{DNSName, IPAddress};

/// The log hash `id-pe-mtcCertificationAuthority-SHA256` names.
const LOG_HASH: HashAlgorithm = HashAlgorithm::Sha256;

/// The arc trust anchor IDs are relative to (draft-ietf-tls-trust-anchor-ids
/// §3): the private enterprise numbers.
const PEN_ARC: &str = "1.3.6.1.4.1";

/// A verifier for servers whose certificates `ca_certs` (DER) issued:
/// ordinary CAs through OpenSSL, Merkle Tree CAs through their proofs.
///
/// # Errors
///
/// A rustls error if a certificate does not parse, or a Merkle Tree CA's
/// extension, subject or key cannot be read.
pub fn server_verifier(ca_certs: &[Vec<u8>]) -> Result<OsslServerCertVerifier, TlsError> {
    let mut signed = Vec::new();
    let mut mtc = Vec::new();
    for der in ca_certs {
        match MtcCa::from_der(der)? {
            Some(ca) => mtc.push(ca),
            None => signed.push(CertificateDer::from(der.as_slice())),
        }
    }
    let signed = if signed.is_empty() {
        None
    } else {
        Some(OsslChainVerifier::new(&signed)?)
    };
    Ok(
        OsslServerCertVerifier::builder_with_verifier(Arc::new(ChainVerifier { signed, mtc }))
            .build(),
    )
}

fn invalid(e: CertificateError) -> TlsError {
    TlsError::InvalidCertificate(e)
}

fn malformed() -> TlsError {
    invalid(CertificateError::BadEncoding)
}

/// What a relying party needs of a Merkle Tree CA (§7.1), read from its
/// certificate.
#[derive(Debug)]
struct MtcCa {
    /// The certificate's subject, which its certificates name as issuer.
    subject: Vec<u8>,
    /// The CA ID's binary representation: what the CA cosigner's
    /// `cosigner_id` carries.
    id: Vec<u8>,
    /// The CA ID, dotted, relative to [`PEN_ARC`].
    id_text: String,
    /// The CA cosigner's key (`SubjectPublicKeyInfo` DER).
    spki: Vec<u8>,
    /// The CA cosigner's signature algorithm (`AlgorithmIdentifier` DER).
    sig_alg: Vec<u8>,
    min_serial: u64,
    max_serial: u64,
    not_before: i64,
    not_after: i64,
}

impl MtcCa {
    /// The Merkle Tree CA `der` describes, or `None` for any other CA.
    fn from_der(der: &[u8]) -> Result<Option<Self>, TlsError> {
        let cert = Certificate::from_der(der).map_err(|_| malformed())?;
        let tbs = &cert.tbs_certificate;
        let Some(raw) = &tbs.extensions else {
            return Ok(None);
        };
        let extensions = Extensions::from_der(raw.as_bytes()).map_err(|_| malformed())?;
        let Some(ext) = extensions
            .iter()
            .find(|e| is_mtc_ca_extension_oid(e.extn_id.components()))
        else {
            return Ok(None);
        };
        let ca = MTCCertificationAuthority::from_der(ext.extn_value.as_bytes())
            .map_err(|_| malformed())?;
        let serial = |i: &synta::Integer| i.as_u64().map_err(|_| malformed());
        let ranges = cert_byte_ranges(der).ok_or_else(malformed)?;
        let (id, id_text) = trust_anchor_id(tbs.subject.as_bytes())?;
        Ok(Some(Self {
            subject: tbs.subject.as_bytes().to_vec(),
            id,
            id_text,
            spki: der[ranges.subject_public_key_info].to_vec(),
            sig_alg: synta::ToDer::to_der(&ca.sig_alg).map_err(|_| malformed())?,
            min_serial: serial(&ca.min_serial)?,
            max_serial: serial(&ca.max_serial)?,
            not_before: time_to_unix(&tbs.validity.not_before).ok_or_else(malformed)?,
            not_after: time_to_unix(&tbs.validity.not_after).ok_or_else(malformed)?,
        }))
    }

    /// The `CosignedSubtree` the CA cosigner signs for subtree
    /// `[start, end)` of log `log` with hash `hash` (§5.3.1): the timestamp
    /// is zero in a certificate's proof (§6.2).
    fn cosigned_subtree(&self, log: u64, start: u64, end: u64, hash: &[u8]) -> Vec<u8> {
        // Both names are far below 255 bytes: a CA ID is at most 32.
        let name = format!("oid/{PEN_ARC}.{}", self.id_text);
        let origin = format!("{name}.0.{log}");
        let mut msg = b"subtree/v1\n\0".to_vec();
        msg.push(u8::try_from(name.len()).expect("short name"));
        msg.extend_from_slice(name.as_bytes());
        msg.extend_from_slice(&0u64.to_be_bytes());
        msg.push(u8::try_from(origin.len()).expect("short name"));
        msg.extend_from_slice(origin.as_bytes());
        msg.extend_from_slice(&start.to_be_bytes());
        msg.extend_from_slice(&end.to_be_bytes());
        msg.extend_from_slice(hash);
        msg
    }
}

/// The trust anchor ID a Merkle Tree CA's subject is (§5.1): one RDN of
/// one `id-rdna-trustAnchorID` attribute whose value is a RELATIVE-OID.
fn trust_anchor_id(name: &[u8]) -> Result<(Vec<u8>, String), TlsError> {
    use synta::tag::{TAG_RELATIVE_OID, TAG_SEQUENCE, TAG_SET};
    let one = |d: &mut Decoder<'_>, tag: u32| -> Result<Vec<u8>, TlsError> {
        let inner = d
            .enter_constructed(Tag::universal_constructed(tag))
            .map_err(|_| malformed())?;
        let bytes = inner.remaining().to_vec();
        if !d.is_empty() {
            return Err(malformed());
        }
        Ok(bytes)
    };
    let rdns = one(&mut Decoder::new(name, Encoding::Der), TAG_SEQUENCE)?;
    let rdn = one(&mut Decoder::new(&rdns, Encoding::Der), TAG_SET)?;
    let atv = one(&mut Decoder::new(&rdn, Encoding::Der), TAG_SEQUENCE)?;
    let mut d = Decoder::new(&atv, Encoding::Der);
    let oid: synta::ObjectIdentifier = d.decode().map_err(|_| malformed())?;
    if !is_rdna_trust_anchor_id_oid(oid.components())
        || d.read_tag().map_err(|_| malformed())? != Tag::universal(TAG_RELATIVE_OID)
    {
        return Err(malformed());
    }
    let len = d
        .read_length()
        .and_then(|l| l.definite())
        .map_err(|_| malformed())?;
    let id = d.read_bytes(len).map_err(|_| malformed())?.to_vec();
    if !d.is_empty() {
        return Err(malformed());
    }
    let text = RelativeOid::from_content_bytes(&id)
        .map_err(|_| malformed())?
        .to_string();
    Ok((id, text))
}

/// The subtree hash an inclusion proof implies for leaf `index` of
/// `[start, end)` (§7.2 step 10): RFC 9162's fold, with the last node of an
/// odd level carried up, returning the root rather than comparing it, as
/// Akāmu's `evaluate_inclusion_proof` does.
fn subtree_hash(
    leaf: &[u8],
    index: u64,
    start: u64,
    end: u64,
    proof: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let size = LOG_HASH.output_size();
    if start >= end || !is_valid_subtree(start, end) || !(start..end).contains(&index) {
        return Err(invalid(CertificateError::BadSignature));
    }
    if !proof.len().is_multiple_of(size) {
        return Err(malformed());
    }
    let mut siblings = proof.chunks(size);
    let mut level = end - start;
    let mut pos = index - start;
    let mut hash = leaf.to_vec();
    while level > 1 {
        if !(level % 2 == 1 && pos == level - 1) {
            let sibling = siblings
                .next()
                .ok_or(invalid(CertificateError::BadSignature))?;
            hash = if pos.is_multiple_of(2) {
                hash_interior(LOG_HASH, &hash, sibling)
            } else {
                hash_interior(LOG_HASH, sibling, &hash)
            }
            .map_err(|_| malformed())?;
        }
        level = level.div_ceil(2);
        pos /= 2;
    }
    if siblings.next().is_some() {
        return Err(invalid(CertificateError::BadSignature));
    }
    Ok(hash)
}

/// OpenSSL for the ordinary CAs, the §7.2 procedure for the Merkle Tree
/// CAs.
struct ChainVerifier {
    signed: Option<OsslChainVerifier>,
    mtc: Vec<MtcCa>,
}

impl std::fmt::Debug for ChainVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainVerifier")
            .field("mtc", &self.mtc.len())
            .finish_non_exhaustive()
    }
}

impl CertChainVerifier for ChainVerifier {
    fn verify_chain(
        &self,
        end_entity: &X509,
        intermediates: &[X509],
        server_name: Option<&ServerName<'_>>,
        now: UnixTime,
    ) -> Result<(), TlsError> {
        let der = end_entity.to_der().map_err(|_| malformed())?;
        let mut decoder = Decoder::new(&der, Encoding::Der);
        let cert: Certificate<'_> = decoder.decode().map_err(|_| malformed())?;
        if !decoder.is_empty() {
            return Err(malformed());
        }
        if is_mtc_proof_oid(cert.signature_algorithm.algorithm.components()) {
            return self.verify_mtc(&cert, server_name, now);
        }
        match &self.signed {
            Some(openssl) => openssl.verify_chain(end_entity, intermediates, server_name, now),
            None => Err(invalid(CertificateError::UnknownIssuer)),
        }
    }
}

impl ChainVerifier {
    /// The §7.2 procedure, then the checks path validation would make of a
    /// TLS server's certificate: validity, critical extensions, extended
    /// key usage and the name.
    fn verify_mtc(
        &self,
        cert: &Certificate<'_>,
        server_name: Option<&ServerName<'_>>,
        now: UnixTime,
    ) -> Result<(), TlsError> {
        let tbs = &cert.tbs_certificate;
        if tbs.signature.algorithm != cert.signature_algorithm.algorithm
            || tbs.signature.parameters.is_some()
            || cert.signature_algorithm.parameters.is_some()
        {
            return Err(malformed());
        }
        let ca = self
            .mtc
            .iter()
            .find(|ca| ca.subject == tbs.issuer.as_bytes())
            .ok_or(invalid(CertificateError::UnknownIssuer))?;

        let now = i64::try_from(now.as_secs()).map_err(|_| malformed())?;
        let not_before = time_to_unix(&tbs.validity.not_before).ok_or_else(malformed)?;
        let not_after = time_to_unix(&tbs.validity.not_after).ok_or_else(malformed)?;
        if now < not_before.max(ca.not_before) {
            return Err(invalid(CertificateError::NotValidYet));
        }
        if now > not_after.min(ca.not_after) {
            return Err(invalid(CertificateError::Expired));
        }

        // Steps 3–5: the serial is (log << 48) | index, within what the
        // CA's extension allows, and log numbers start at 1.
        let serial = tbs.serial_number.as_u64().map_err(|_| malformed())?;
        let (log, index) = (serial >> 48, serial & MTC_MAX_LOG_INDEX);
        if log == 0 || !(ca.min_serial..=ca.max_serial).contains(&serial) {
            return Err(invalid(CertificateError::ApplicationVerificationFailure));
        }

        // Steps 7–10: the entry this certificate is, hashed as the log hashed
        // it, extensions included, then folded up to its subtree.
        let proof = MtcProof::decode_signature_value(
            cert.signature_value.as_bytes(),
            cert.signature_value.unused_bits(),
        )
        .map_err(|_| malformed())?;
        let entry = tbs_certificate_to_log_entry(tbs, LOG_HASH).map_err(|_| malformed())?;
        let leaf = hash_log_entry(
            LOG_HASH,
            &MerkleTreeCertEntry::TbsCertEntry(entry),
            &proof.extensions,
        )
        .map_err(|_| malformed())?;
        let hash = subtree_hash(&leaf, index, proof.start, proof.end, &proof.inclusion_proof)?;

        // Step 12: the CA cosigner's signature over that subtree.
        let cosignature = proof
            .signatures
            .iter()
            .find(|s| s.cosigner_id == ca.id)
            .ok_or(invalid(CertificateError::BadSignature))?;
        OpensslSignatureVerifier
            .verify_certificate_signature(
                &ca.cosigned_subtree(log, proof.start, proof.end, &hash),
                &ca.sig_alg,
                &cosignature.signature_value,
                &ca.spki,
            )
            .map_err(|_| invalid(CertificateError::BadSignature))?;

        let extensions = match &tbs.extensions {
            Some(raw) => {
                Extensions::from_der(raw.as_bytes())
                    .map_err(|_| malformed())?
                    .0
            }
            None => Vec::new(),
        };
        let understood: [&[u32]; 4] = [
            oids::KEY_USAGE,
            oids::EXTENDED_KEY_USAGE,
            oids::SUBJECT_ALT_NAME,
            oids::BASIC_CONSTRAINTS,
        ];
        for ext in &extensions {
            let id = ext.extn_id.components();
            if ext.critical.is_some_and(|c| c.value()) && !understood.contains(&id) {
                return Err(invalid(CertificateError::UnhandledCriticalExtension));
            }
            if id == oids::EXTENDED_KEY_USAGE {
                let eku = decode_extended_key_usage(ext).ok_or_else(malformed)?;
                if !eku.iter().any(|p| p.components() == oids::KP_SERVER_AUTH) {
                    return Err(invalid(CertificateError::InvalidPurpose));
                }
            }
        }

        let Some(server_name) = server_name else {
            return Ok(());
        };
        let subject = match server_name {
            ServerName::DnsName(name) => {
                Subject::Dns(DNSName::new(name.as_ref()).ok_or_else(malformed)?)
            }
            ServerName::IpAddress(ip) => Subject::Ip(IPAddress(std::net::IpAddr::from(*ip))),
            _ => return Err(TlsError::UnsupportedNameType),
        };
        let names = tbs
            .extensions
            .as_ref()
            .and_then(|raw| find_san(raw.as_bytes()))
            .ok_or(invalid(CertificateError::NotValidForName))?;
        if !subject.matches_san(&names) {
            return Err(invalid(CertificateError::NotValidForName));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::server_verifier;
    use native_ossl::pkey::{KeygenCtx, Pkey, Private};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{CertificateError, Error as TlsError};
    use synta_certificate::{
        CertificateBuilder, KEY_USAGE_KEY_CERT_SIGN, NameBuilder, OpensslCertificateSigner,
        SubjectAlternativeNameBuilder, cert_byte_ranges, encode_basic_constraints,
        encode_key_usage, oids, parse_time,
    };
    use synta_mtc::crypto::MtcProof;

    /// 2027: inside the demo corpus's 2020–2030 and the test CAs' validity.
    const NOW: u64 = 1_800_000_000;

    /// The demo corpus's CA cosigner key (cosigner 32473.1), a published
    /// test vector (`tests/data/README.md`).
    const DEMO_CA_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgthrguld6LZNJw6UMbhyTkML7u3BMcdEyomQIwB+N2o6hRANCAAR6nKeTu+M2OxL7HCjH/i0+lnIx7OE0b3DnXWVue+5TBVDq8aG6KqFq+xprV5ll6QtPJb+TTBp+Kv1IRpDxMpxt";

    fn pem(bytes: &[u8]) -> Vec<u8> {
        synta_certificate::pem_to_der(bytes).remove(0)
    }

    fn demo_ca() -> Vec<u8> {
        pem(include_bytes!("../tests/data/mtc-demo-ca.pem"))
    }

    /// A certificate the demo CA issued for `a.example`, cosigned by the CA
    /// and by an external cosigner.
    fn demo_leaf() -> Vec<u8> {
        pem(include_bytes!("../tests/data/mtc-demo-leaf.pem"))
    }

    fn verify(cas: &[Vec<u8>], leaf: &[u8], name: &str, now: u64) -> Result<(), TlsError> {
        server_verifier(cas)?
            .verify_server_cert(
                &CertificateDer::from(leaf),
                &[],
                &ServerName::try_from(name.to_owned()).unwrap(),
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
            )
            .map(|_| ())
    }

    fn refused(r: Result<(), TlsError>, e: &CertificateError) {
        match r {
            Err(TlsError::InvalidCertificate(got)) => assert_eq!(&got, e),
            other => panic!("expected {e:?}, got {other:?}"),
        }
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n @ 0..0x80 => out.push(u8::try_from(n).unwrap()),
            n @ 0x80..0x100 => out.extend([0x81, u8::try_from(n).unwrap()]),
            n => {
                out.push(0x82);
                out.extend(u16::try_from(n).unwrap().to_be_bytes());
            }
        }
        out.extend_from_slice(content);
        out
    }

    /// `der` with its proof replaced by `proof`.
    fn with_proof(der: &[u8], proof: &MtcProof) -> Vec<u8> {
        let r = cert_byte_ranges(der).unwrap();
        let mut body = der[r.tbs].to_vec();
        body.extend_from_slice(&der[r.signature_algorithm]);
        let mut bits = vec![0];
        bits.extend(proof.encode().unwrap());
        body.extend(tlv(0x03, &bits));
        tlv(0x30, &body)
    }

    fn demo_proof() -> MtcProof {
        let leaf = demo_leaf();
        let cert = synta_certificate::Certificate::from_der(&leaf).unwrap();
        MtcProof::decode_signature_value(
            cert.signature_value.as_bytes(),
            cert.signature_value.unused_bits(),
        )
        .unwrap()
    }

    fn ec_key() -> Pkey<Private> {
        let params = native_ossl::params::ParamBuilder::new()
            .unwrap()
            .set(native_ossl::typed_params::ec::GROUP, c"P-256")
            .unwrap()
            .build()
            .unwrap();
        let mut ctx = KeygenCtx::new(c"EC").unwrap();
        ctx.set_params(&params).unwrap();
        ctx.generate().unwrap()
    }

    /// A certificate for `name`, issued under `issuer` and signed by
    /// `signer`; a CA if `name` is `None`.
    fn issue(
        issuer: &[u8],
        subject_key: &Pkey<Private>,
        name: Option<&str>,
        signer: &Pkey<Private>,
    ) -> Vec<u8> {
        let subject = match name {
            Some(n) => NameBuilder::new().common_name(n).build().unwrap(),
            None => issuer.to_vec(),
        };
        let builder = CertificateBuilder::new()
            .issuer_name(issuer)
            .subject_name(&subject)
            .public_key_der(&subject_key.public_key_to_der().unwrap())
            .serial_number(synta::Integer::from_u64(7))
            .not_valid_before(parse_time("20260101000000Z").unwrap())
            .not_valid_after(parse_time("20360101000000Z").unwrap());
        let builder = match name {
            Some(n) => builder.add_extension_oid(
                oids::SUBJECT_ALT_NAME,
                false,
                &SubjectAlternativeNameBuilder::new()
                    .dns_name(n)
                    .build()
                    .unwrap(),
            ),
            None => builder
                .add_extension_oid(
                    oids::BASIC_CONSTRAINTS,
                    true,
                    &encode_basic_constraints(true, None).unwrap(),
                )
                .add_extension_oid(
                    oids::KEY_USAGE,
                    true,
                    &encode_key_usage(1 << KEY_USAGE_KEY_CERT_SIGN).unwrap(),
                ),
        };
        builder
            .sign(&OpensslCertificateSigner::new(signer, "sha256"))
            .unwrap()
    }

    #[test]
    fn demo_merkle_tree_certificate_verifies() {
        verify(&[demo_ca()], &demo_leaf(), "a.example", NOW).unwrap();
    }

    #[test]
    fn merkle_tree_certificate_must_name_the_server() {
        refused(
            verify(&[demo_ca()], &demo_leaf(), "b.example", NOW),
            &CertificateError::NotValidForName,
        );
    }

    #[test]
    fn merkle_tree_certificate_must_be_valid_now() {
        refused(
            verify(&[demo_ca()], &demo_leaf(), "a.example", 1_950_000_000),
            &CertificateError::Expired,
        );
        refused(
            verify(&[demo_ca()], &demo_leaf(), "a.example", 1_500_000_000),
            &CertificateError::NotValidYet,
        );
    }

    #[test]
    fn merkle_tree_certificate_needs_a_trusted_merkle_tree_ca() {
        let ipa = include_bytes!("../tests/data/ipa-ca.der").to_vec();
        refused(
            verify(&[ipa], &demo_leaf(), "a.example", NOW),
            &CertificateError::UnknownIssuer,
        );
    }

    #[test]
    fn altered_entry_breaks_the_proof() {
        // The last byte of the subject key: the log entry, so the leaf hash,
        // changes, and the CA's cosignature no longer covers it.
        let mut leaf = demo_leaf();
        let spki = cert_byte_ranges(&leaf).unwrap().subject_public_key_info;
        leaf[spki.end - 1] ^= 1;
        refused(
            verify(&[demo_ca()], &leaf, "a.example", NOW),
            &CertificateError::BadSignature,
        );
    }

    #[test]
    fn merkle_tree_certificate_needs_the_ca_cosignature() {
        // Only the external cosigner's signature left: valid, but not the
        // CA's own.
        let mut proof = demo_proof();
        assert_eq!(proof.signatures.len(), 2);
        let ca_id = proof.signatures[0].cosigner_id.clone();
        proof.signatures.retain(|s| s.cosigner_id != ca_id);
        refused(
            verify(
                &[demo_ca()],
                &with_proof(&demo_leaf(), &proof),
                "a.example",
                NOW,
            ),
            &CertificateError::BadSignature,
        );

        // The CA's signature over another subtree.
        let mut proof = demo_proof();
        proof.end += 1;
        assert!(
            verify(
                &[demo_ca()],
                &with_proof(&demo_leaf(), &proof),
                "a.example",
                NOW
            )
            .is_err()
        );
    }

    #[test]
    fn cosigner_key_does_not_sign_certificates() {
        // An ordinary certificate in the Merkle Tree CA's name, signed with
        // its cosigner key: the key signs subtrees, so this is refused
        // whether or not other CAs are trusted.
        let ca = demo_ca();
        let issuer = synta_certificate::Certificate::from_der(&ca)
            .unwrap()
            .tbs_certificate
            .subject
            .as_bytes()
            .to_vec();
        let cosigner = Pkey::<Private>::from_der(
            &synta_certificate::decode_base64(DEMO_CA_KEY.as_bytes()).unwrap(),
        )
        .unwrap();
        let leaf = issue(&issuer, &ec_key(), Some("a.example"), &cosigner);
        refused(
            verify(std::slice::from_ref(&ca), &leaf, "a.example", NOW),
            &CertificateError::UnknownIssuer,
        );
        let ipa = include_bytes!("../tests/data/ipa-ca.der").to_vec();
        assert!(verify(&[ca, ipa], &leaf, "a.example", NOW).is_err());
    }

    #[test]
    fn ordinary_chain_verifies_beside_a_merkle_tree_ca() {
        let ca_key = ec_key();
        let name = NameBuilder::new()
            .organization("EXAMPLE.TEST")
            .common_name("Certificate Authority")
            .build()
            .unwrap();
        let ca = issue(&name, &ca_key, None, &ca_key);
        let leaf = issue(&name, &ec_key(), Some("ipa1.example.test"), &ca_key);
        let cas = [ca, demo_ca()];
        verify(&cas, &leaf, "ipa1.example.test", NOW).unwrap();
        assert!(verify(&cas, &leaf, "ipa2.example.test", NOW).is_err());
    }
}
