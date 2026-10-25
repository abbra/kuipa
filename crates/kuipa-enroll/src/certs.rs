//! The CA certificates a realm advertises (§4.3, §5.5): what a host writes
//! into `ca.crt` and its PKINIT anchors before it has any other way to
//! check them.
//!
//! Trust in them comes from the advertisement, which an anchor-attested
//! server signs, not from the certificates themselves; this module only
//! makes sure that what lands in a trust file is a CA certificate at all.
//! Signatures are left to kinit and TLS, which do path validation, so a
//! certificate is accepted whatever it is signed with, including the two
//! forms that carry no signature to verify:
//!
//! * a Merkle Tree CA (draft-ietf-plants-merkle-tree-certs §5.5), which is
//!   usually an unsigned certificate (RFC 9925) and is recognised by its
//!   critical Merkle Tree CA extension rather than by basic constraints;
//! * a certificate a Merkle Tree CA issued (§6.2), whose `signatureValue`
//!   is an `MTCProof`, which must at least decode.

use synta_certificate::{
    BasicConstraints, Certificate, Extensions, KEY_USAGE_KEY_CERT_SIGN, KeyUsage, key_usage_bit,
    oids,
};
use synta_mtc::builder::parse_mtc_ca_extension;
use synta_mtc::crypto::MtcProof;
use synta_mtc::types::constants::{is_mtc_ca_extension_oid, is_mtc_proof_oid};

/// Why a certificate is not one a host may install as a CA: what
/// [`check_ca`] says, and [`Error::NotCa`](crate::error::Error::NotCa)
/// reports for a list entry.
pub type NotCa = &'static str;

/// Require `der` to be one DER certificate that can act as a CA: basic
/// constraints with `cA` set, or a Merkle Tree CA.  A key usage extension,
/// when a non-MTC CA has one, must allow `keyCertSign`.
///
/// # Errors
///
/// What the certificate is instead, to complete "… is": not a certificate,
/// one followed by other bytes, one whose extensions, proof or unsigned
/// signature are not what they claim, a Merkle Tree CA with a non-critical
/// or malformed extension, or not a CA.
///
/// [`Error::NotCa`]: crate::error::Error::NotCa
pub fn check_ca(der: &[u8]) -> Result<(), NotCa> {
    let mut decoder = synta::Decoder::new(der, synta::Encoding::Der);
    let cert: Certificate<'_> = decoder.decode().map_err(|_| "not a DER certificate")?;
    if !decoder.is_empty() {
        return Err("a certificate followed by other bytes");
    }
    let alg = cert.signature_algorithm.algorithm.components();
    if cert.tbs_certificate.signature.algorithm.components() != alg {
        return Err("a certificate naming two signature algorithms");
    }
    let signature = &cert.signature_value;
    if is_mtc_proof_oid(alg) {
        MtcProof::decode_signature_value(signature.as_bytes(), signature.unused_bits())
            .map_err(|_| "a Merkle Tree certificate whose proof does not decode")?;
    } else if alg == oids::ALG_UNSIGNED && !signature.as_bytes().is_empty() {
        return Err("an unsigned certificate that carries a signature");
    }

    let undecodable = "a certificate whose extensions do not decode";
    let extensions = match &cert.tbs_certificate.extensions {
        Some(raw) => {
            Extensions::from_der(raw.as_bytes())
                .map_err(|_| undecodable)?
                .0
        }
        None => Vec::new(),
    };
    let mut is_ca = false;
    let mut mtc_ca = false;
    let mut cert_sign = true;
    for ext in &extensions {
        let id = ext.extn_id.components();
        let value = ext.extn_value.as_bytes();
        if id == oids::BASIC_CONSTRAINTS {
            let bc = BasicConstraints::from_der(value).map_err(|_| undecodable)?;
            is_ca |= bc.c_a.is_some_and(|c| c.value());
        } else if id == oids::KEY_USAGE {
            let ku = KeyUsage::from_der(value).map_err(|_| undecodable)?;
            cert_sign = key_usage_bit(&ku, KEY_USAGE_KEY_CERT_SIGN);
        } else if is_mtc_ca_extension_oid(id) {
            // §5.5: the extension MUST be critical, so that a relying party
            // unaware of Merkle Tree CAs does not take this for a CA whose
            // key signs certificates.
            if !ext.critical.is_some_and(|c| c.value()) {
                return Err("a Merkle Tree CA whose extension is not critical");
            }
            mtc_ca = true;
        }
    }
    if mtc_ca {
        // The key is a cosigner's, which signs subtrees, not certificates:
        // key usage says nothing about whether this is a CA.
        parse_mtc_ca_extension(der)
            .ok()
            .flatten()
            .ok_or("a Merkle Tree CA whose extension does not decode")?;
        return Ok(());
    }
    if !is_ca {
        return Err("an end-entity certificate, not a CA");
    }
    if !cert_sign {
        return Err("a CA whose key usage does not allow signing certificates");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_ca;
    use synta_certificate::{
        CertificateBuilder, CertificateSigner, KEY_USAGE_DIGITAL_SIGNATURE,
        KEY_USAGE_KEY_CERT_SIGN, NameBuilder, UnsignedCertificateSigner, encode_basic_constraints,
        encode_key_usage, oids, parse_time,
    };
    use synta_mtc::builder::build_mtc_ca_extension;
    use synta_mtc::crypto::MtcProof;
    use synta_mtc::types::constants::ID_ALG_MTC_PROOF;

    /// A CA key: no signature is ever verified, so any key will do.
    fn spki() -> Vec<u8> {
        let params = native_ossl::params::ParamBuilder::new()
            .unwrap()
            .set(native_ossl::typed_params::ec::GROUP, c"P-256")
            .unwrap()
            .build()
            .unwrap();
        let mut ctx = native_ossl::pkey::KeygenCtx::new(c"EC").unwrap();
        ctx.set_params(&params).unwrap();
        ctx.generate().unwrap().public_key_to_der().unwrap()
    }

    /// A signer that writes `alg` and `value` as they are: what the check
    /// sees is the encoding, so no signature needs to be real.
    struct Raw {
        alg: &'static [u32],
        value: Vec<u8>,
    }

    impl CertificateSigner for Raw {
        type Error = std::io::Error;

        fn signature_algorithm_der(&self) -> Result<Vec<u8>, Self::Error> {
            use synta::traits::Encode;
            let alg = synta_certificate::AlgorithmIdentifier {
                algorithm: synta::ObjectIdentifier::new(self.alg).expect("oid"),
                parameters: None,
            };
            let mut enc = synta::Encoder::new(synta::Encoding::Der);
            alg.encode(&mut enc).expect("algorithm identifier");
            Ok(enc.finish().expect("algorithm identifier"))
        }

        fn sign_tbs(&self, _: &[u8]) -> Result<Vec<u8>, Self::Error> {
            Ok(self.value.clone())
        }
    }

    fn builder() -> CertificateBuilder {
        let name = NameBuilder::new().common_name("IPA CA").build().unwrap();
        CertificateBuilder::new()
            .issuer_name(&name)
            .subject_name(&name)
            .public_key_der(&spki())
            .serial_number(synta::Integer::from_u64(1))
            .not_valid_before(parse_time("20260101000000Z").unwrap())
            .not_valid_after(parse_time("20360101000000Z").unwrap())
    }

    fn ca() -> CertificateBuilder {
        builder().add_extension_oid(
            oids::BASIC_CONSTRAINTS,
            true,
            &encode_basic_constraints(true, None).unwrap(),
        )
    }

    fn signed() -> Raw {
        Raw {
            alg: oids::ECDSA_WITH_SHA256,
            value: vec![0x30, 0x00],
        }
    }

    /// The Merkle Tree CA extension for log 1, with the given criticality.
    fn mtc_ca(critical: bool) -> CertificateBuilder {
        let sig_alg = synta_certificate::AlgorithmIdentifier {
            algorithm: synta::ObjectIdentifier::new(oids::ECDSA_WITH_SHA256).unwrap(),
            parameters: None,
        };
        let value = build_mtc_ca_extension(&sig_alg, 1 << 48, (2 << 48) - 1).unwrap();
        builder().add_extension_oid(synta_mtc::builder::MTC_CA_EXTENSION_OID, critical, &value)
    }

    fn proof() -> Vec<u8> {
        MtcProof {
            extensions: Vec::new(),
            start: 0,
            end: 1,
            inclusion_proof: Vec::new(),
            signatures: Vec::new(),
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn signed_ca_passes() {
        check_ca(&ca().sign(&signed()).unwrap()).unwrap();
    }

    #[test]
    fn unsigned_ca_passes() {
        check_ca(&ca().sign(&UnsignedCertificateSigner).unwrap()).unwrap();
    }

    #[test]
    fn unsigned_merkle_tree_ca_passes_without_basic_constraints() {
        let der = mtc_ca(true).sign(&UnsignedCertificateSigner).unwrap();
        check_ca(&der).unwrap();
    }

    #[test]
    fn ca_issued_by_a_merkle_tree_ca_passes() {
        let der = ca()
            .sign(&Raw {
                alg: ID_ALG_MTC_PROOF,
                value: proof(),
            })
            .unwrap();
        check_ca(&der).unwrap();
    }

    /// The MTC CA certificate of the IETF plants WG demo corpus
    /// (`tests/data/README.md`): unsigned, under the experimental OIDs.
    #[test]
    fn demo_merkle_tree_ca_passes() {
        let der = synta_certificate::pem_to_der(include_bytes!("../tests/data/mtc-demo-ca.pem"));
        check_ca(&der[0]).unwrap();
    }

    /// A certificate the demo CA issued: its proof decodes, and it is
    /// refused only for being an end entity.
    #[test]
    fn demo_merkle_tree_certificate_is_an_end_entity() {
        let der = synta_certificate::pem_to_der(include_bytes!("../tests/data/mtc-demo-leaf.pem"));
        assert_eq!(
            check_ca(&der[0]),
            Err("an end-entity certificate, not a CA")
        );
    }

    #[test]
    fn not_a_certificate_is_refused() {
        assert!(check_ca(b"IPA CA certificate (DER)").is_err());
        assert!(check_ca(&[]).is_err());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut der = ca().sign(&signed()).unwrap();
        der.push(0);
        assert!(check_ca(&der).is_err());
    }

    #[test]
    fn end_entity_is_refused() {
        assert!(check_ca(&builder().sign(&signed()).unwrap()).is_err());
        let not_ca = builder()
            .add_extension_oid(
                oids::BASIC_CONSTRAINTS,
                true,
                &encode_basic_constraints(false, None).unwrap(),
            )
            .sign(&signed())
            .unwrap();
        assert!(check_ca(&not_ca).is_err());
    }

    #[test]
    fn ca_that_cannot_sign_certificates_is_refused() {
        let der = ca()
            .add_extension_oid(
                oids::KEY_USAGE,
                true,
                &encode_key_usage(1 << KEY_USAGE_DIGITAL_SIGNATURE).unwrap(),
            )
            .sign(&signed())
            .unwrap();
        assert!(check_ca(&der).is_err());
        let der = ca()
            .add_extension_oid(
                oids::KEY_USAGE,
                true,
                &encode_key_usage(1 << KEY_USAGE_KEY_CERT_SIGN).unwrap(),
            )
            .sign(&signed())
            .unwrap();
        check_ca(&der).unwrap();
    }

    #[test]
    fn non_critical_merkle_tree_ca_extension_is_refused() {
        let der = mtc_ca(false).sign(&UnsignedCertificateSigner).unwrap();
        assert!(check_ca(&der).is_err());
    }

    #[test]
    fn malformed_merkle_tree_ca_extension_is_refused() {
        let der = builder()
            .add_extension_oid(
                synta_mtc::builder::MTC_CA_EXTENSION_OID,
                true,
                &[0x30, 0x00],
            )
            .sign(&UnsignedCertificateSigner)
            .unwrap();
        assert!(check_ca(&der).is_err());
    }

    #[test]
    fn malformed_mtc_proof_is_refused() {
        let der = ca()
            .sign(&Raw {
                alg: ID_ALG_MTC_PROOF,
                value: vec![0xff; 7],
            })
            .unwrap();
        assert!(check_ca(&der).is_err());
    }

    #[test]
    fn unsigned_certificate_with_a_signature_is_refused() {
        let der = ca()
            .sign(&Raw {
                alg: oids::ALG_UNSIGNED,
                value: vec![1, 2, 3],
            })
            .unwrap();
        assert!(check_ca(&der).is_err());
    }
}
