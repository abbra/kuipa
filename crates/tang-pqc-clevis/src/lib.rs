//! A Clevis pin and command-line client for post-quantum Tang (`tang-pqc`).
//!
//! `encrypt` fetches the server's advertisement, verifies it against the
//! pinned signing-key thumbprint, provisions a binding, and encrypts the
//! input as a compact JWE (`"alg": "dir"`, `"enc": "A256GCM"`) under the
//! binding's key.  The protected header carries what `decrypt` needs and
//! nothing secret:
//!
//! ```text
//! {"alg":"dir","enc":"A256GCM",
//!  "clevis":{"pin":"tang-pqc","tang-pqc":{"url":…,"thp":…,"binding":…[,"ca":…]}}}
//! ```
//!
//! `decrypt` fetches the binding's exchange key from `URL/key/{kid}` (the
//! binding's `kid` authenticates it), sends a sealed recovery request to
//! `URL/rec/{kid}`, and decrypts.  The header is the JWE's additional
//! authenticated data, so a changed URL, thumbprint or binding fails to
//! decrypt.
//!
//! Configuration (the pin's JSON argument): `url` (the Tang URL, required),
//! `thp` (the signing key to trust, required: `tang-pqc adv URL` lists
//! them), `adv` (an advertisement file instead of fetching one, for offline
//! provisioning), `ca` (a PEM file to verify an `https` server against;
//! without it any certificate is accepted, since the advertisement is
//! verified and the exchange needs no transport security, as in Tang).
//! Other members, such as the `binding` that `clevis luks regen` passes back,
//! are ignored.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use native_ossl::cipher::{AeadDecryptCtx, AeadEncryptCtx, CipherAlg};
use native_ossl::util::SecretBuf;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_native_ossl::cert_verifier::OsslServerCertVerifier;
use serde::Deserialize;
use serde_json::{Value, json};
use tang_pqc::{Binding, ExchangeKey, RecoveryResponse, SignedAdvertisement, Thumbprint, b64};

/// The pin's name, in the JWE header.
pub const PIN: &str = "tang-pqc";

/// Errors.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The pin configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The Tang URL, e.g. `https://ipa1.example.test/ipa/ku/tang`.
    pub url: String,
    /// The pinned signing-key thumbprint.
    pub thp: Option<String>,
    /// An advertisement file to use instead of fetching one.
    pub adv: Option<PathBuf>,
    /// A PEM CA file for `https` URLs.
    pub ca: Option<PathBuf>,
}

impl Config {
    /// Parse the pin's JSON argument.
    ///
    /// # Errors
    ///
    /// Malformed JSON or a missing `url`.
    pub fn parse(json: &str) -> Result<Self, Error> {
        let config: Self =
            serde_json::from_str(json).map_err(|e| format!("bad configuration: {e}"))?;
        if config.url.is_empty() {
            return Err("the configuration needs a \"url\"".into());
        }
        Ok(config)
    }

    fn base(&self) -> &str {
        self.url.trim_end_matches('/')
    }
}

/// Accepts any server certificate, still checking handshake signatures.
#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client(ca: Option<&PathBuf>) -> Result<reqwest::blocking::Client, Error> {
    let _ = rustls_native_ossl::default_provider().install_default();
    let provider = Arc::new(rustls_native_ossl::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous();
    let config = match ca {
        Some(path) => {
            let roots: Vec<CertificateDer<'static>> =
                synta_certificate::pem_to_der(&std::fs::read(path)?)
                    .into_iter()
                    .map(CertificateDer::from)
                    .collect();
            if roots.is_empty() {
                return Err(format!("no certificates in {}", path.display()).into());
            }
            builder.with_custom_certificate_verifier(Arc::new(
                OsslServerCertVerifier::builder(&roots)?.build(),
            ))
        }
        None => builder.with_custom_certificate_verifier(Arc::new(AnyCertificate(provider))),
    };
    Ok(reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .tls_backend_preconfigured(config.with_no_client_auth())
        .build()?)
}

fn get_adv(
    http: &reqwest::blocking::Client,
    url: &str,
) -> Result<Option<SignedAdvertisement>, Error> {
    let response = http.get(url).send()?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response.error_for_status()?;
    Ok(Some(SignedAdvertisement::from_json(&response.bytes()?)?))
}

/// The advertisement at `url` (or from `adv`), not yet verified.
///
/// # Errors
///
/// A network error or a malformed advertisement.
pub fn advertisement(config: &Config) -> Result<SignedAdvertisement, Error> {
    if let Some(file) = &config.adv {
        return Ok(SignedAdvertisement::from_json(&std::fs::read(file)?)?);
    }
    get_adv(
        &client(config.ca.as_ref())?,
        &format!("{}/adv", config.base()),
    )?
    .ok_or_else(|| format!("{}/adv: not found", config.base()).into())
}

/// The signing keys `url` advertises, for choosing `thp`.
///
/// # Errors
///
/// As for [`advertisement`].
pub fn signing_keys(config: &Config) -> Result<Vec<Thumbprint>, Error> {
    Ok(advertisement(config)?.advertised_signing_keys()?)
}

/// Encrypt `plaintext` for `config`: the compact JWE.
///
/// # Errors
///
/// No `thp`, an advertisement that does not verify against it, a network
/// error, or an OpenSSL error.
pub fn encrypt(config: &Config, plaintext: &[u8]) -> Result<String, Error> {
    let advertised = advertisement(config)?;
    let Some(thp) = &config.thp else {
        let keys: Vec<String> = advertised
            .advertised_signing_keys()?
            .iter()
            .map(ToString::to_string)
            .collect();
        return Err(format!(
            "the configuration needs \"thp\": the signing key to trust; {} advertises {}",
            config.url,
            keys.join(", ")
        )
        .into());
    };
    let pinned: Thumbprint = thp.parse().map_err(|_| "\"thp\" is not a thumbprint")?;
    let adv = match advertised.verify(&pinned) {
        Ok(adv) => adv,
        // After a rotation the pinned key is retired: Tang servers sign
        // `adv/{thp}` with it too.
        Err(_) if config.adv.is_none() => get_adv(
            &client(config.ca.as_ref())?,
            &format!("{}/adv/{pinned}", config.base()),
        )?
        .ok_or("the advertisement is not signed by the pinned key")?
        .verify(&pinned)
        .map_err(|_| "the advertisement is not signed by the pinned key")?,
        Err(_) => return Err("the advertisement is not signed by the pinned key".into()),
    };
    let (binding, key) = adv.provision(None)?;
    let mut pin = json!({
        "url": config.url,
        "thp": pinned.to_string(),
        "binding": b64::encode(&binding.to_bytes()),
    });
    if let Some(ca) = &config.ca {
        pin["ca"] = ca.display().to_string().into();
    }
    let header = json!({
        "alg": "dir",
        "enc": "A256GCM",
        "clevis": { "pin": PIN, PIN: pin },
    });
    let protected = b64::encode(header.to_string().as_bytes());
    let mut iv = [0u8; IV_LEN];
    native_ossl::rand::Rand::fill(&mut iv)?;
    let alg = CipherAlg::fetch(c"AES-256-GCM", None)?;
    let mut ctx = AeadEncryptCtx::new(&alg, key.as_ref(), &iv, None)?;
    ctx.set_aad(protected.as_bytes())?;
    let mut ciphertext = vec![0u8; plaintext.len()];
    let n = ctx.update(plaintext, &mut ciphertext)?;
    let n = n + ctx.finalize(&mut ciphertext[n..])?;
    ciphertext.truncate(n);
    let mut tag = [0u8; TAG_LEN];
    ctx.tag(&mut tag)?;
    Ok(format!(
        "{protected}..{}.{}.{}",
        b64::encode(&iv),
        b64::encode(&ciphertext),
        b64::encode(&tag)
    ))
}

/// A parsed tang-pqc JWE: the pin's part of the header, the header's
/// encoded form (the AAD), and the encrypted parts.
struct Jwe {
    protected: String,
    url: String,
    ca: Option<PathBuf>,
    binding: Binding,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

fn parse(jwe: &str) -> Result<Jwe, Error> {
    let malformed = || -> Error { "not a tang-pqc JWE".into() };
    let parts: Vec<&str> = jwe.trim().split('.').collect();
    let [protected, key, iv, ciphertext, tag] = parts[..] else {
        return Err(malformed());
    };
    if !key.is_empty() {
        return Err(malformed());
    }
    let header: Value = serde_json::from_slice(&b64::decode(protected)?)?;
    if header["alg"] != "dir" || header["enc"] != "A256GCM" || header["clevis"]["pin"] != PIN {
        return Err(malformed());
    }
    let pin = &header["clevis"][PIN];
    let url = pin["url"].as_str().ok_or_else(malformed)?.to_owned();
    let binding = Binding::from_bytes(&b64::decode(
        pin["binding"].as_str().ok_or_else(malformed)?,
    )?)?;
    let ca = pin["ca"].as_str().map(PathBuf::from);
    Ok(Jwe {
        protected: protected.to_owned(),
        url,
        ca,
        binding,
        iv: b64::decode(iv)?,
        ciphertext: b64::decode(ciphertext)?,
        tag: b64::decode(tag)?,
    })
}

/// Decrypt a JWE made by [`encrypt`], recovering its key from the server.
///
/// # Errors
///
/// Not a tang-pqc JWE, a server that cannot recover the key, or a JWE that
/// does not authenticate.
pub fn decrypt(jwe: &str) -> Result<SecretBuf, Error> {
    let jwe = parse(jwe)?;
    let (iv, ciphertext, tag) = (&jwe.iv, &jwe.ciphertext, &jwe.tag);
    if iv.len() != IV_LEN || tag.len() != TAG_LEN {
        return Err("not a tang-pqc JWE".into());
    }
    let http = client(jwe.ca.as_ref())?;
    let base = jwe.url.trim_end_matches('/');
    let kid = jwe.binding.kid();
    let key = http
        .get(format!("{base}/key/{kid}"))
        .send()?
        .error_for_status()?;
    let exchange_key = ExchangeKey::from_jwk_json(&key.bytes()?)?;
    let (request, pending) = jwe.binding.recovery_request(&exchange_key)?;
    let response = http
        .post(format!("{base}/rec/{kid}"))
        .header("content-type", "application/vnd.tang-pqc.rec-req")
        .body(request.to_bytes())
        .send()?
        .error_for_status()?;
    let key = pending.finish(&RecoveryResponse::from_bytes(&response.bytes()?)?)?;
    let alg = CipherAlg::fetch(c"AES-256-GCM", None)?;
    let mut ctx = AeadDecryptCtx::new(&alg, key.as_ref(), iv, None)?;
    ctx.set_aad(jwe.protected.as_bytes())?;
    let mut out = SecretBuf::with_len(ciphertext.len());
    let n = ctx.update(ciphertext, out.as_mut_slice())?;
    ctx.set_tag(tag)?;
    ctx.finalize(&mut out.as_mut_slice()[n..])
        .map_err(|_| "the JWE does not authenticate")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration() {
        let c = Config::parse(r#"{"url":"http://t/","thp":"x","binding":"ignored"}"#).unwrap();
        assert_eq!(c.base(), "http://t");
        assert!(Config::parse(r#"{"thp":"x"}"#).is_err());
        assert!(Config::parse(r#"{"url":""}"#).is_err());
    }

    #[test]
    fn foreign_jwes_are_refused() {
        assert!(decrypt("a.b.c").is_err());
        let header = b64::encode(br#"{"alg":"dir","enc":"A256GCM","clevis":{"pin":"tang"}}"#);
        assert!(decrypt(&format!("{header}..AAAA.AAAA.AAAA")).is_err());
    }
}
