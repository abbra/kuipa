//! Test certificates: a self-signed CA and a PKINIT KDC certificate issued
//! by it.  Ported from kurbu5-pkinit's `pkinit-core/src/test_support.rs`.

use std::time::{SystemTime, UNIX_EPOCH};

use native_ossl::pkey::{KeygenCtx, Pkey, Private};
use synta::{GeneralizedTime, Integer, UtcTime};
use synta_certificate::{
    CertificateBuilder, ExtendedKeyUsageBuilder, NameBuilder, SubjectAlternativeNameBuilder, Time,
};

/// id-pkinit-KPKdc (RFC 4556 §3.2.2).
const ID_PKINIT_KPKDC: &[u32] = &[1, 3, 6, 1, 5, 2, 3, 5];

/// A CA and a KDC certificate for a realm, with the KDC's private key.
pub struct KdcChain {
    pub ca_der: Vec<u8>,
    pub kdc_der: Vec<u8>,
    pub kdc_key_pem: Vec<u8>,
}

/// From 90 days ago to 90 days ahead, so tests keep passing as time moves.
fn validity() -> (UtcTime, UtcTime) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let secs = i64::try_from(now.as_secs()).unwrap();
    let period = 90 * 24 * 60 * 60;
    let utc = |s: i64| {
        let gt = GeneralizedTime::from_unix(s).unwrap();
        UtcTime::new(gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second).unwrap()
    };
    (utc(secs - period), utc(secs + period))
}

fn ec_key() -> Pkey<Private> {
    let params = native_ossl::params::ParamBuilder::new()
        .unwrap()
        .set(native_ossl::typed_params::ec::GROUP, c"P-256")
        .unwrap()
        .build()
        .unwrap();
    let mut kgen = KeygenCtx::new(c"EC").unwrap();
    kgen.set_params(&params).unwrap();
    kgen.generate().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn sign_cert(
    issuer_key: &Pkey<Private>,
    subject_name: &[u8],
    issuer_name: &[u8],
    subject_spki: &[u8],
    issuer_spki: &[u8],
    serial: i64,
    ca: bool,
    extra: &[(&[u32], bool, &[u8])],
) -> Vec<u8> {
    let backend = synta_certificate::crypto::BackendPrivateKey::from_pkcs8_der_unchecked(
        issuer_key.to_pkcs8_der().unwrap(),
    );
    let signer = synta_certificate::crypto::PrivateKey::as_signer(&backend, "sha256");
    let ski = synta_certificate::encode_subject_key_identifier(
        subject_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();
    let aki = synta_certificate::encode_authority_key_identifier(
        issuer_spki,
        synta_certificate::KeyIdMethod::Rfc5280Sha1,
        &synta_certificate::OpensslKeyIdHasher,
    )
    .unwrap();
    let (nb, na) = validity();
    let mut builder = CertificateBuilder::new()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key_der(subject_spki)
        .serial_number(Integer::from_i64(serial))
        .not_valid_before(Time::UtcTime(nb))
        .not_valid_after(Time::UtcTime(na))
        .add_extension_oid(synta_certificate::oids::SUBJECT_KEY_IDENTIFIER, false, &ski)
        .add_extension_oid(
            synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
            false,
            &aki,
        );
    if ca {
        let bc = synta_certificate::encode_basic_constraints(true, None).unwrap();
        builder = builder.add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc);
    }
    for (oid, critical, value) in extra {
        builder = builder.add_extension_oid(oid, *critical, value);
    }
    builder.sign(&signer).unwrap()
}

/// An EC P-256 CA and a KDC certificate with the PKINIT KDC EKU and the
/// `krbtgt/REALM@REALM` SAN.
pub fn kdc_chain(realm: &str) -> KdcChain {
    let ca_key = ec_key();
    let ca_spki = ca_key.public_key_to_der().unwrap();
    let ca_name = NameBuilder::new()
        .common_name("kuipa Test CA")
        .build()
        .unwrap();
    let ca_der = sign_cert(
        &ca_key,
        &ca_name,
        &ca_name,
        &ca_spki,
        &ca_spki,
        1,
        true,
        &[],
    );

    let kdc_key = ec_key();
    let kdc_spki = kdc_key.public_key_to_der().unwrap();
    let kdc_name = NameBuilder::new()
        .common_name("kuipa Test KDC")
        .build()
        .unwrap();
    let on = synta_krb5::principal::encode_krb5_san(&format!("krbtgt/{realm}"), realm).unwrap();
    let san = SubjectAlternativeNameBuilder::new()
        .other_name(&on)
        .build()
        .unwrap();
    let eku = ExtendedKeyUsageBuilder::new()
        .add_oid(ID_PKINIT_KPKDC)
        .build()
        .unwrap();
    let kdc_der = sign_cert(
        &ca_key,
        &kdc_name,
        &ca_name,
        &kdc_spki,
        &ca_spki,
        2,
        false,
        &[
            (synta_certificate::oids::SUBJECT_ALT_NAME, false, &san),
            (synta_certificate::oids::EXTENDED_KEY_USAGE, false, &eku),
        ],
    );
    KdcChain {
        ca_der,
        kdc_der,
        kdc_key_pem: kdc_key.to_pem().unwrap(),
    }
}
