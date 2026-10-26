//! Trusts with other IPA realms (§17.4), on the daemon side.
//!
//! * [`establish`]: run by `kuipad establish-trust` on a server of
//!   realm A with B's invitation: verify B's advertisement with the
//!   invitation's anchor, send the trust request, and record the trust.
//! * [`refresh`]: periodically, verify every recorded partner's
//!   advertisement with the anchors on record, update its description
//!   (B vouches for its own anchors and servers), and publish the trusted
//!   realms in this server's advertisement.
//!
//! Servers are named by FQDN; `endpoints` (the `peer_endpoints`
//! configuration) maps a name to another URL.
//!
//! TLS: the first request to a partner accepts any certificate, as a host
//! does on first contact, since the advertisement authenticates the
//! partner; the trust request then goes over TLS verified against the CA
//! the advertisement lists.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use kuipa_enroll::EnrollServer;
use kuipa_enroll::delegation::HeadPin;
use kuipa_enroll::realm::{TrustedRealm, VerifiedRealm};
use kuipa_enroll::server::Directory;
use kuipa_enroll::trust::{self, Established, Invitation, TrustResponse};
use native_ossl::util::SecretBuf;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tang_pqc::{Policy, SignedAdvertisement, Thumbprint};

/// Errors.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Accepts any server certificate, still checking handshake signatures.
#[derive(Debug)]
struct FirstContact(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for FirstContact {
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

/// A client that verifies TLS against `ca` (DER), or accepts any
/// certificate without one.
fn client(ca: Option<&[Vec<u8>]>) -> Result<reqwest::Client, Error> {
    let _ = rustls_native_ossl::default_provider().install_default();
    let provider = Arc::new(rustls_native_ossl::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous();
    let config = match ca {
        Some(certs) => builder
            .with_custom_certificate_verifier(Arc::new(kuipa_enroll::tls::server_verifier(certs)?)),
        None => builder.with_custom_certificate_verifier(Arc::new(FirstContact(provider))),
    };
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .tls_backend_preconfigured(config.with_no_client_auth())
        .build()?)
}

/// Where `server` is: its URL from `endpoints`, else `https://<server>`.
fn url<'a>(server: &'a str, endpoints: &'a BTreeMap<String, String>) -> &'a str {
    endpoints.get(server).map_or(server, String::as_str)
}

/// `…/ipa/ku/` for a URL or a host name.
fn base(target: &str) -> String {
    if target.contains("://") {
        format!("{}/ipa/ku/", target.trim_end_matches('/'))
    } else {
        format!("https://{target}/ipa/ku/")
    }
}

/// Fetch and verify `server`'s advertisement as realm `realm` with
/// `anchors`.
///
/// # Errors
///
/// Network errors or a failed verification.
pub async fn advertisement(
    server: &str,
    endpoints: &BTreeMap<String, String>,
    realm: &str,
    anchors: &[Thumbprint],
) -> Result<VerifiedRealm, Error> {
    let query: Vec<String> = anchors.iter().map(|a| format!("anchor={a}")).collect();
    let url = format!("{}adv?{}", base(url(server, endpoints)), query.join("&"));
    let response = client(None)?.get(url).send().await?.error_for_status()?;
    let adv = SignedAdvertisement::from_json(&response.bytes().await?)?;
    Ok(VerifiedRealm::verify(
        &adv,
        realm,
        anchors,
        &Policy::from_system()?,
        SystemTime::now(),
    )?)
}

/// Establish a trust with the realm that issued `invitation`, through the
/// first of its `servers` that verifies, as `server` (this realm's server).
/// The trust is recorded in `directory`; if the directory cannot record
/// trusts, the caller gets the secret to record it otherwise.
///
/// # Errors
///
/// No usable server, a refused request, or a bad response.
pub async fn establish(
    server: &EnrollServer,
    invitation: &Invitation,
    servers: &[String],
    endpoints: &BTreeMap<String, String>,
    directory: &(dyn Directory + Send + Sync),
) -> Result<(Established, bool), Error> {
    let mut failures = Vec::new();
    for s in servers {
        let adv =
            match advertisement(s, endpoints, invitation.realm(), &[*invitation.anchor()]).await {
                Ok(adv) => adv,
                Err(e) => {
                    failures.push(format!("{s}: {e}"));
                    continue;
                }
            };
        let (request, pending) = trust::request(
            &adv,
            invitation,
            &server.as_partner(),
            &server.delegation(),
            &server.keys().signing,
        )?;
        let target = url(s, endpoints);
        let tls = (!target.contains("://") || target.starts_with("https://"))
            .then(|| adv.info().ca_certs.as_slice());
        let url = format!("{}trust/{}", base(target), request.kid());
        let response = client(tls)?
            .post(url)
            .header("content-type", "application/vnd.ipa-ku.trust")
            .body(request.to_bytes())
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(
                format!("{s} refused the trust request (HTTP {})", response.status()).into(),
            );
        }
        let established = pending.finish(&TrustResponse::from_bytes(&response.bytes().await?)?)?;
        let recorded =
            match directory.record_trust(&established.partner, established.secret.as_ref()) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("kuipad: cannot record the trust here ({e})");
                    false
                }
            };
        return Ok((established, recorded));
    }
    Err(format!(
        "no usable server of {}: {}",
        invitation.realm(),
        failures.join("; ")
    )
    .into())
}

/// The trust secret as `trust-add --trust_secret` takes it.
#[must_use]
pub fn secret_text(established: &Established) -> SecretBuf {
    trust::secret_text(&established.secret)
}

/// The advertised heads backed by a signature: those also in `proved`,
/// the heads an advertisement's delegation signed (§4.9,
/// DESIGN-claim-logs.md §4).  An advertised head with no proof behind
/// it is the server's assertion, not a pin a host may trust.
fn back_heads(advertised: &[HeadPin], proved: &[HeadPin]) -> Vec<HeadPin> {
    advertised
        .iter()
        .filter(|h| proved.contains(h))
        .copied()
        .collect()
}

/// Refresh every recorded partner from its verified advertisement, and
/// publish `configured` plus the recorded partners.  A partner that cannot
/// be verified keeps its last description.
pub async fn refresh(
    server: &EnrollServer,
    directory: &Arc<dyn Directory + Send + Sync>,
    configured: &[TrustedRealm],
    endpoints: &BTreeMap<String, String>,
) {
    let dir = directory.clone();
    let recorded = match tokio::task::spawn_blocking(move || dir.trusted_realms()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            eprintln!("kuipad: trusts: cannot read the trusted realms: {e}");
            Vec::new()
        }
        Err(e) => {
            eprintln!("kuipad: trusts: {e}");
            Vec::new()
        }
    };
    let mut published: Vec<TrustedRealm> = configured.to_vec();
    for partner in recorded {
        let mut current = partner.clone();
        for s in &partner.servers {
            match advertisement(s, endpoints, &partner.realm, &partner.anchors).await {
                Ok(adv) => {
                    let info = adv.info();
                    // Pin only heads a signature proves: first the
                    // heads this advertisement itself signed; for a
                    // head it does not, that anchor's own
                    // advertisement — verified against exactly that
                    // anchor — must prove it (§4.9).
                    let mut heads = back_heads(&info.heads, adv.proved_heads());
                    let mut missing: Vec<Thumbprint> = Vec::new();
                    for h in info.heads.iter().filter(|h| !heads.contains(h)) {
                        if !missing.contains(&h.anchor) {
                            missing.push(h.anchor);
                        }
                    }
                    for anchor in missing {
                        match advertisement(s, endpoints, &partner.realm, &[anchor]).await {
                            Ok(own) => {
                                for h in back_heads(&info.heads, own.proved_heads()) {
                                    if !heads.contains(&h) {
                                        heads.push(h);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "kuipad: trusts: {} via {s}: head of {anchor}: {e}",
                                    partner.realm
                                );
                            }
                        }
                    }
                    let unbacked = info.heads.iter().filter(|h| !heads.contains(h)).count();
                    if unbacked > 0 {
                        eprintln!(
                            "kuipad: trusts: {}: unbacked heads not pinned ({unbacked})",
                            partner.realm
                        );
                    }
                    current = TrustedRealm {
                        realm: partner.realm.clone(),
                        domain: info.domain.clone(),
                        servers: info.servers.clone(),
                        anchors: info.anchors.clone(),
                        // The partner's signature-backed heads for
                        // those anchors — what a host of this realm
                        // pins for it (DESIGN-claim-logs.md §3).
                        heads,
                        // The KDC proxies it advertises for itself.
                        kdc_proxy: info.kdc_proxy.clone(),
                    };
                    break;
                }
                Err(e) => eprintln!("kuipad: trusts: {} via {s}: {e}", partner.realm),
            }
        }
        let own = server.as_partner();
        if current != partner && current.validate_for(&own.realm, &own.anchors).is_ok() {
            let dir = directory.clone();
            let update = current.clone();
            match tokio::task::spawn_blocking(move || dir.update_trust(&update)).await {
                Ok(Ok(())) => eprintln!("kuipad: trusts: refreshed {}", current.realm),
                Ok(Err(e)) => eprintln!("kuipad: trusts: {}: {e}", current.realm),
                Err(e) => eprintln!("kuipad: trusts: {e}"),
            }
        } else {
            current = partner;
        }
        if !published
            .iter()
            .any(|t| t.realm.eq_ignore_ascii_case(&current.realm))
        {
            published.push(current);
        }
    }
    server.publish_trusts(published);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(anchor: u8, size: u64, root: u8) -> HeadPin {
        HeadPin {
            anchor: Thumbprint::from_bytes([anchor; 32]),
            size,
            root: kuipa_enroll::merkle::Hash::from_slice(&[root; 32]).unwrap(),
        }
    }

    #[test]
    fn only_proved_heads_are_backed() {
        let proved = head(1, 12, 7);
        let asserted = head(1, 13, 8);
        assert_eq!(back_heads(&[proved, asserted], &[proved]), [proved]);
        // An advertisement that proves nothing backs no head: every
        // advertised head is only the server's assertion.
        assert_eq!(back_heads(&[proved], &[]).len(), 0);
    }
}
