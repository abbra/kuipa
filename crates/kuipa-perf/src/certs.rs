//! Real CA certificates for benchmark fixtures, built with
//! [`synta_certificate`]'s builder over OpenSSL keys.
//!
//! These are ordinary self-signed CA certificates — RFC 5280 extensions and
//! all — which is what an enrollment advertisement's `ca_certs` carries and
//! what a client parses and checks.  Sizes are realistic: EC P-256 around
//! half a kilobyte, RSA-2048 around a kilobyte, ML-DSA-65 around five and a
//! half.

use native_ossl::pkey::{KeygenCtx, Pkey, Private};
use synta_certificate::{
    CertificateBuilder, KeyIdMethod, NameBuilder, OpensslCertificateSigner, OpensslKeyIdHasher,
    encode_authority_key_identifier, encode_basic_constraints, encode_key_usage,
    encode_subject_key_identifier, parse_time,
};

use crate::profile::CaKind;

/// Named-bit positions from RFC 5280 §4.2.1.3, as `encode_key_usage` takes
/// them.
const KEY_CERT_SIGN: u16 = 1 << 5;
const CRL_SIGN: u16 = 1 << 6;

/// A generated certificate and the key that signed it.
pub struct Ca {
    /// The certificate, DER.
    pub der: Vec<u8>,
    /// The key type.
    pub kind: CaKind,
}

/// A deterministic 32-byte ML-DSA seed derived from `label`.
fn seed(label: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for i in 0..4u64 {
        out.extend_from_slice(
            &crate::prng::SplitMix64::hash(label.as_bytes())
                .wrapping_add(i)
                .to_le_bytes(),
        );
    }
    out
}

/// A positive, deterministic serial derived from `label`.
fn serial(label: &str) -> synta::Integer {
    synta::Integer::from_u64(u64::from_le_bytes(seed(label)[..8].try_into().unwrap()) | 1)
}

/// Generate a private key of `kind`.
///
/// ML-DSA takes a fixed seed so fixture certificates are identical run to
/// run; RSA and EC keygen draws from the provider and cannot be seeded, but
/// their output sizes are fixed, which is what the benches measure.
///
/// # Errors
///
/// [`native_ossl::error::ErrorStack`] if OpenSSL cannot generate the key.
pub fn key(kind: CaKind) -> Result<Pkey<Private>, native_ossl::error::ErrorStack> {
    match kind {
        CaKind::Rsa2048 => {
            let params = native_ossl::params::ParamBuilder::new()?
                .set(native_ossl::typed_params::keygen::BITS, &2048u32)?
                .build()?;
            let mut ctx = KeygenCtx::new(c"RSA")?;
            ctx.set_params(&params)?;
            ctx.generate()
        }
        CaKind::EcP256 => {
            let params = native_ossl::params::ParamBuilder::new()?
                .set(native_ossl::typed_params::ec::GROUP, c"P-256")?
                .build()?;
            let mut ctx = KeygenCtx::new(c"EC")?;
            ctx.set_params(&params)?;
            ctx.generate()
        }
        CaKind::MlDsa65 => {
            let params = native_ossl::params::ParamBuilder::new()?
                .set(
                    native_ossl::typed_params::ml_dsa::SEED,
                    seed("kuipa-bench-ca").as_slice(),
                )?
                .build()?;
            let mut ctx = KeygenCtx::new(c"ML-DSA-65")?;
            ctx.set_params(&params)?;
            ctx.generate()
        }
    }
}

/// Build a self-signed CA certificate for `key`.
///
/// # Panics
///
/// If an extension fails to encode: the encoders only fail on malformed
/// input, which the fixed fixture values cannot be.
///
/// # Errors
///
/// A builder or OpenSSL error if the certificate cannot be signed.
pub fn self_signed(key: &Pkey<Private>, kind: CaKind, cn: &str) -> Result<Vec<u8>, String> {
    let spki = key.public_key_to_der().map_err(|e| e.to_string())?;
    let name = NameBuilder::new()
        .common_name(cn)
        .organization("Kuipa Bench")
        .country("FI")
        .build()?;
    let signer = match kind {
        CaKind::Rsa2048 | CaKind::EcP256 => OpensslCertificateSigner::new(key, "sha256"),
        CaKind::MlDsa65 => OpensslCertificateSigner::new(key, ""),
    };
    CertificateBuilder::new()
        .issuer_name(&name)
        .subject_name(&name)
        .public_key_der(&spki)
        .serial_number(serial(cn))
        .not_valid_before(parse_time("20260101000000Z")?)
        .not_valid_after(parse_time("20360101000000Z")?)
        .add_extension_oid(
            synta_certificate::oids::BASIC_CONSTRAINTS,
            true,
            &encode_basic_constraints(true, None).unwrap(),
        )
        .add_extension_oid(
            synta_certificate::oids::KEY_USAGE,
            true,
            &encode_key_usage(KEY_CERT_SIGN | CRL_SIGN).unwrap(),
        )
        .add_extension_oid(
            synta_certificate::oids::SUBJECT_KEY_IDENTIFIER,
            false,
            &encode_subject_key_identifier(&spki, KeyIdMethod::Rfc5280Sha1, &OpensslKeyIdHasher)
                .unwrap(),
        )
        .add_extension_oid(
            synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
            false,
            &encode_authority_key_identifier(&spki, KeyIdMethod::Rfc5280Sha1, &OpensslKeyIdHasher)
                .unwrap(),
        )
        .sign(&signer)
        .map_err(|e| e.to_string())
}

/// Generate a CA key and its self-signed certificate.
///
/// # Errors
///
/// A keygen, encode, or signing error.
pub fn generate(kind: CaKind, cn: &str) -> Result<Ca, String> {
    let key = key(kind).map_err(|e| e.to_string())?;
    Ok(Ca {
        der: self_signed(&key, kind, cn)?,
        kind,
    })
}

/// `count` CA certificates of `kind`, for an advertisement that carries
/// several roots.
///
/// # Errors
///
/// A keygen, encode, or signing error.
pub fn chain(kind: CaKind, count: usize) -> Result<Vec<Vec<u8>>, String> {
    (0..count)
        .map(|i| generate(kind, &format!("Kuipa Bench CA {i}")).map(|ca| ca.der))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{CaKind, generate};

    #[test]
    fn ec_ca_is_a_der_sequence() {
        let ca = generate(CaKind::EcP256, "Kuipa Bench CA").unwrap();
        assert_eq!(ca.der[0], 0x30);
        assert!(
            (300..1200).contains(&ca.der.len()),
            "EC CA len {}",
            ca.der.len()
        );
    }

    #[test]
    fn rsa_ca_is_a_der_sequence() {
        let ca = generate(CaKind::Rsa2048, "Kuipa Bench CA").unwrap();
        assert_eq!(ca.der[0], 0x30);
        assert!(
            (800..1600).contains(&ca.der.len()),
            "RSA CA len {}",
            ca.der.len()
        );
    }

    #[test]
    fn ml_dsa_ca_is_a_der_sequence() {
        let ca = generate(CaKind::MlDsa65, "Kuipa Bench CA").unwrap();
        assert_eq!(ca.der[0], 0x30);
        assert!(ca.der.len() > 4000, "ML-DSA CA len {}", ca.der.len());
    }
}
