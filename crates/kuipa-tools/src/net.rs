//! HTTP transport: `reqwest` over rustls with the `rustls-native-ossl`
//! provider (OpenSSL, FIPS-capable).
//!
//! The protocol does not rely on TLS (§10.3).  On first contact the client
//! has no CA yet, so TLS only hides the host name from passive observers;
//! after enrollment it verifies against the installed IPA CA, which may be
//! a Merkle Tree CA ([`kuipa_enroll::tls`]).
//!
//! Errors are classified for the failover rules of §4.6.

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tang_pqc::b64;

/// How to authenticate the server's TLS certificate.
#[derive(Clone, Debug)]
pub enum Trust {
    /// First contact: any certificate (the protocol authenticates the
    /// server through the realm anchor instead).
    FirstContact,
    /// The IPA CA chain (DER), Merkle Tree CAs included.
    Ca(Vec<Vec<u8>>),
}

/// A transport error, classified for failover.
#[derive(Debug)]
pub enum NetError {
    /// Nothing reached the server's protocol handler (connection refused,
    /// DNS failure, `503`): safe to try another server.
    Unreachable(String),
    /// The request may have been processed (timeout, connection dropped
    /// after sending): retry the same server only.
    Unknown(String),
    /// The server refused (`403`).
    Refused,
    /// Anything else.
    Other(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(e) => write!(f, "server unreachable: {e}"),
            Self::Unknown(e) => write!(f, "outcome unknown: {e}"),
            Self::Refused => f.write_str("the server refused the request"),
            Self::Other(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for NetError {}

/// Accepts any server certificate, but still checks handshake signatures.
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

/// Make `rustls-native-ossl` the process-wide rustls provider, so nothing
/// in the dependency tree falls back to another one.
fn install_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls_native_ossl::default_provider().install_default();
    });
}

fn tls_config(trust: &Trust) -> Result<rustls::ClientConfig, NetError> {
    let provider = Arc::new(rustls_native_ossl::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| NetError::Other(format!("TLS versions: {e}")))?
        .dangerous();
    let config = match trust {
        Trust::FirstContact => {
            builder.with_custom_certificate_verifier(Arc::new(FirstContact(provider)))
        }
        Trust::Ca(certs) => {
            let verifier = kuipa_enroll::tls::server_verifier(certs)
                .map_err(|e| NetError::Other(format!("IPA CA: {e}")))?;
            builder.with_custom_certificate_verifier(Arc::new(verifier))
        }
    };
    Ok(config.with_no_client_auth())
}

/// Where advertisements are kept between runs, if anywhere: see
/// [`cache_advertisements_in`].
static ADVERTISEMENT_CACHE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Keep fetched advertisements in `dir`, and ask servers for them
/// conditionally (`If-None-Match`): an unchanged advertisement then costs
/// a `304 Not Modified` instead of 25-30 KB.  What a cache answers is the
/// bytes a server served before, and every caller verifies them again,
/// as of now, exactly as fresh ones; the cache saves the transfer, never
/// a check.  Set once, by the `kuipa` command; tests and other tools
/// fetch every time.
pub fn cache_advertisements_in(dir: std::path::PathBuf) {
    let _ = ADVERTISEMENT_CACHE.set(dir);
}

thread_local! {
    /// The advertisement cache for the current thread only, ahead of
    /// [`cache_advertisements_in`]: see [`set_thread_advertisement_cache`].
    static THREAD_ADVERTISEMENT_CACHE: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Keep advertisements in `dir` for the current thread only, as
/// [`cache_advertisements_in`] does for the whole process: for tests that
/// run in parallel.
#[doc(hidden)]
pub fn set_thread_advertisement_cache(dir: Option<std::path::PathBuf>) {
    THREAD_ADVERTISEMENT_CACHE.with_borrow_mut(|d| *d = dir);
}

/// Where this thread keeps advertisements, if anywhere.
fn advertisement_cache() -> Option<std::path::PathBuf> {
    THREAD_ADVERTISEMENT_CACHE
        .with_borrow(Clone::clone)
        .or_else(|| ADVERTISEMENT_CACHE.get().cloned())
}

/// The cached advertisement for `url`: its tag and its bytes.
fn cached_advertisement(dir: &std::path::Path, url: &str) -> Option<(String, Vec<u8>)> {
    let bytes = std::fs::read(dir.join(cache_name(url))).ok()?;
    let at = bytes.iter().position(|b| *b == b'\n')?;
    let tag = std::str::from_utf8(&bytes[..at]).ok()?.to_owned();
    Some((tag, bytes[at + 1..].to_vec()))
}

/// Keep `body`, tagged `tag`, as the advertisement for `url`: the tag on
/// the first line, the bytes after it.  Best effort: a cache that cannot
/// be written only costs the next fetch.
fn cache_advertisement(dir: &std::path::Path, url: &str, tag: &str, body: &[u8]) {
    if tag.contains('\n') || std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let mut record = Vec::with_capacity(tag.len() + 1 + body.len());
    record.extend_from_slice(tag.as_bytes());
    record.push(b'\n');
    record.extend_from_slice(body);
    let path = dir.join(cache_name(url));
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &record).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// A cache file's name: the hex SHA-256 of the URL it answers, so each
/// server and each choice of pins and heads has its own.
fn cache_name(url: &str) -> String {
    use std::fmt::Write as _;

    tang_pqc::primitives::sha256(&[url.as_bytes()])
        .map(|h| {
            h.iter().fold(String::new(), |mut hex, b| {
                let _ = write!(hex, "{b:02x}");
                hex
            })
        })
        .unwrap_or_default()
}

thread_local! {
    /// Endpoint overrides for the current thread only, ahead of
    /// `KUIPA_ENDPOINTS`: see [`set_thread_endpoint`].
    static THREAD_ENDPOINTS: std::cell::RefCell<Vec<(String, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Most bytes read from one response.  Real answers are small: an
/// advertisement or a page of the anchor log is a few KiB.  A server (or,
/// on first contact before the CA is known, a network attacker) that
/// sends more is broken or hostile, and buffering it whole serves only to
/// exhaust the client's memory.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Reach `server` at `target` (as for [`Endpoint::new`]) from the current
/// thread, as `KUIPA_ENDPOINTS` does for the whole process.  For tests that
/// run in parallel: each maps the server names of its deployment to its
/// own test servers, which the environment cannot do safely.
#[doc(hidden)]
pub fn set_thread_endpoint(server: &str, target: &str) {
    THREAD_ENDPOINTS.with_borrow_mut(|map| {
        map.retain(|(name, _)| name != server);
        map.push((server.to_owned(), target.to_owned()));
    });
}

/// Forget every endpoint this thread mapped (see
/// [`set_thread_endpoint`]): a test that replaces the bindings of
/// shared server names ends with this, so a later test on the same
/// thread starts from its own.
#[doc(hidden)]
pub fn clear_thread_endpoints() {
    THREAD_ENDPOINTS.with_borrow_mut(Vec::clear);
}

/// Where to reach `server` instead of `https://<server>/`: from
/// [`set_thread_endpoint`], else `KUIPA_ENDPOINTS` (`fqdn=target,…`, target
/// as for [`Endpoint::new`]), for talking to a daemon's socket directly, or
/// to test servers.
fn endpoint_override(server: &str) -> Option<String> {
    if let Some(target) = THREAD_ENDPOINTS.with_borrow(|map| {
        map.iter()
            .find(|(name, _)| name == server)
            .map(|(_, target)| target.clone())
    }) {
        return Some(target);
    }
    let map = std::env::var("KUIPA_ENDPOINTS").ok()?;
    map.split(',')
        .filter_map(|e| e.split_once('='))
        .find(|(name, _)| name.trim() == server)
        .map(|(_, target)| target.trim().to_owned())
}

/// Is `server` reached over TLS (an FQDN or an `https://` URL)?
#[must_use]
pub fn uses_tls(server: &str) -> bool {
    server.starts_with("https://") || !(server.contains("://") || server.starts_with("unix:"))
}

/// One server's `/ipa/ku/` endpoint.
pub struct Endpoint {
    client: reqwest::blocking::Client,
    base: String,
    name: String,
}

impl Endpoint {
    /// Connect to `server`: an FQDN (`https://<fqdn>/ipa/ku/`), a URL
    /// (used as the base, for tests), or `unix:/path` (plain HTTP over a
    /// Unix socket, talking to the daemon directly).
    ///
    /// # Errors
    ///
    /// [`NetError::Other`] if the client cannot be built.
    pub fn new(server: &str, trust: &Trust) -> Result<Self, NetError> {
        let name = server;
        let server = endpoint_override(server).unwrap_or_else(|| server.to_owned());
        let server = server.as_str();
        let mut builder = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60));
        let base = if let Some(path) = server.strip_prefix("unix:") {
            builder = builder.unix_socket(path);
            "http://localhost/ipa/ku/".to_owned()
        } else if server.contains("://") {
            format!("{}/ipa/ku/", server.trim_end_matches('/'))
        } else {
            format!("https://{server}/ipa/ku/")
        };
        // Plain HTTP (tests, the daemon's own socket) never uses the TLS
        // configuration, so it need not hold a usable CA.
        let trust = if base.starts_with("https://") {
            trust
        } else {
            &Trust::FirstContact
        };
        install_provider();
        tracing::trace!(
            server = name,
            %base,
            tls = match (base.starts_with("https://"), trust) {
                (false, _) => "none",
                (true, Trust::FirstContact) => "first contact: any certificate",
                (true, Trust::Ca(_)) => "verified against the IPA CA",
            },
            "endpoint"
        );
        builder = builder.tls_backend_preconfigured(tls_config(trust)?);
        let client = builder
            .build()
            .map_err(|e| NetError::Other(e.to_string()))?;
        Ok(Self {
            client,
            base,
            name: name.to_owned(),
        })
    }

    /// The server as given.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    fn classify(e: &reqwest::Error) -> NetError {
        if e.is_connect() || e.is_builder() {
            NetError::Unreachable(e.to_string())
        } else {
            NetError::Unknown(e.to_string())
        }
    }

    /// Send `request` and classify the answer, tracing both ends.
    fn send(
        &self,
        method: &str,
        url: &str,
        request: reqwest::blocking::RequestBuilder,
        sent: usize,
    ) -> Result<Vec<u8>, NetError> {
        tracing::debug!(server = %self.name, "{method} {url} ({sent} bytes)");
        let start = Instant::now();
        let result = request
            .send()
            .map_err(|e| Self::classify(&e))
            .and_then(Self::finish);
        let ms = start.elapsed().as_millis();
        match &result {
            Ok(body) => {
                tracing::debug!(server = %self.name, "200 OK: {} bytes in {ms} ms", body.len());
            }
            Err(e) => tracing::debug!(server = %self.name, "{method} failed after {ms} ms: {e}"),
        }
        result
    }

    fn finish(response: reqwest::blocking::Response) -> Result<Vec<u8>, NetError> {
        match response.status() {
            StatusCode::OK => {
                let len = response.content_length();
                if len.is_some_and(|n| usize::try_from(n).is_ok_and(|n| n > MAX_RESPONSE_BYTES)) {
                    return Err(NetError::Unreachable(format!(
                        "response larger than {} MiB",
                        MAX_RESPONSE_BYTES / 1024 / 1024
                    )));
                }
                let body = response
                    .bytes()
                    .map_err(|e| NetError::Unknown(e.to_string()))?;
                if body.len() > MAX_RESPONSE_BYTES {
                    return Err(NetError::Unreachable(
                        "response grew past the size limit while reading".into(),
                    ));
                }
                Ok(body.to_vec())
            }
            StatusCode::FORBIDDEN => Err(NetError::Refused),
            // Rate limited before anything was processed: like an
            // unreachable server, another one may be tried.
            StatusCode::TOO_MANY_REQUESTS => {
                Err(NetError::Unreachable("rate limited (HTTP 429)".into()))
            }
            StatusCode::SERVICE_UNAVAILABLE | StatusCode::BAD_GATEWAY | StatusCode::NOT_FOUND => {
                Err(NetError::Unreachable(format!("HTTP {}", response.status())))
            }
            s => Err(NetError::Other(format!("unexpected HTTP {s}"))),
        }
    }

    /// `GET adv`, asking for a delegation signature by one of `anchors`
    /// (the pinned ones, in order of preference; at most 16 are sent).
    ///
    /// # Errors
    ///
    /// A classified [`NetError`].
    pub fn advertisement(
        &self,
        anchors: &[tang_pqc::Thumbprint],
    ) -> Result<tang_pqc::SignedAdvertisement, NetError> {
        self.advertisement_with_heads(anchors, &[])
    }

    /// `GET adv`, also naming the pinned vouch heads (§4.9): the server
    /// answers a delegation the client can check without any signature,
    /// when it can.
    ///
    /// # Errors
    ///
    /// A classified [`NetError`].
    pub fn advertisement_with_heads(
        &self,
        anchors: &[tang_pqc::Thumbprint],
        heads: &[kuipa_enroll::delegation::HeadPin],
    ) -> Result<tang_pqc::SignedAdvertisement, NetError> {
        let query: Vec<String> = anchors
            .iter()
            .take(16)
            .map(|a| format!("anchor={a}"))
            .collect();
        let query: Vec<String> = query
            .into_iter()
            .chain(
                heads
                    .iter()
                    .take(16)
                    .map(|h| format!("head={}.{}.{}", h.anchor, h.size, b64::encode(&h.root))),
            )
            .collect();
        let url = if query.is_empty() {
            format!("{}adv", self.base)
        } else {
            format!("{}adv?{}", self.base, query.join("&"))
        };
        let body = match advertisement_cache() {
            Some(dir) => self.fetch_cached(&dir, &url)?,
            None => self.send("GET", &url, self.client.get(&url), 0)?,
        };
        tang_pqc::SignedAdvertisement::from_json(&body)
            .map_err(|e| NetError::Unreachable(e.to_string()))
    }

    /// `GET url` through the cache in `dir`: conditionally when a copy is
    /// kept, and keeping what a `200` answers with its tag.
    fn fetch_cached(&self, dir: &std::path::Path, url: &str) -> Result<Vec<u8>, NetError> {
        let kept = cached_advertisement(dir, url);
        let mut request = self.client.get(url);
        if let Some((tag, _)) = &kept {
            request = request.header(reqwest::header::IF_NONE_MATCH, tag);
        }
        tracing::debug!(server = %self.name, "GET {url} (0 bytes)");
        let start = Instant::now();
        let response = request.send().map_err(|e| Self::classify(&e));
        let ms = start.elapsed().as_millis();
        let response = match response {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(server = %self.name, "GET failed after {ms} ms: {e}");
                return Err(e);
            }
        };
        if response.status() == StatusCode::NOT_MODIFIED
            && let Some((_, body)) = kept
        {
            tracing::debug!(
                server = %self.name,
                "304 Not Modified: 0 bytes in {ms} ms; the kept {} bytes, verified as fresh ones",
                body.len()
            );
            return Ok(body);
        }
        let tag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = Self::finish(response);
        match &body {
            Ok(body) => {
                tracing::debug!(server = %self.name, "200 OK: {} bytes in {ms} ms", body.len());
                if let Some(tag) = tag {
                    cache_advertisement(dir, url, &tag, body);
                }
            }
            Err(e) => tracing::debug!(server = %self.name, "GET failed after {ms} ms: {e}"),
        }
        body
    }

    /// The realm's anchor log: entries with sequence greater than
    /// `from`, oldest first (§4.8).
    ///
    /// # Errors
    ///
    /// A classified [`NetError`].
    pub fn anchor_log(&self, from: u64) -> Result<Vec<kuipa_enroll::epoch::SignedEpoch>, NetError> {
        #[derive(serde::Deserialize)]
        struct Log {
            entries: Vec<kuipa_enroll::epoch::SignedEpoch>,
        }
        let url = format!("{}anchor-log?from={from}", self.base);
        let body = self.send("GET", &url, self.client.get(&url), 0)?;
        Ok(serde_json::from_slice::<Log>(&body)
            .map_err(|e| NetError::Other(format!("anchor log: {e}")))?
            .entries)
    }

    /// One anchor's claim log (§4.9.5): the leaves after `from`, with
    /// the head they lead to and its signed vouch
    /// (DESIGN-claim-logs.md §4).
    ///
    /// # Errors
    ///
    /// A classified [`NetError`].
    pub fn claim_log(
        &self,
        anchor: &tang_pqc::Thumbprint,
        from: u64,
    ) -> Result<kuipa_enroll::server::ClaimLogPage, NetError> {
        let url = format!("{}claim-log/{anchor}?from={from}", self.base);
        let body = self.send("GET", &url, self.client.get(&url), 0)?;
        serde_json::from_slice(&body).map_err(|e| NetError::Other(format!("claim log: {e}")))
    }

    /// `GET tlog/{log}/head`: the server's signed head, **unverified**;
    /// none while its log is empty.
    ///
    /// # Errors
    ///
    /// A classified [`NetError`], or a malformed head.
    pub fn tlog_head(
        &self,
        log: &kuipa_enroll::tlog::LogId,
    ) -> Result<Option<kuipa_enroll::tlog::SignedHead>, NetError> {
        let url = format!("{}tlog/{log}/head", self.base);
        match self.send("GET", &url, self.client.get(&url), 0) {
            Ok(body) => kuipa_enroll::tlog::SignedHead::from_bytes(&body)
                .map(Some)
                .map_err(|e| NetError::Other(format!("tlog head: {e}"))),
            // `send` reports a 404 as unreachable, for failover; here it
            // means the log is still empty.
            Err(NetError::Unreachable(m)) if m.starts_with("HTTP 404") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `GET tlog/{log}/leaves?from=<from>`: one page of the server's
    /// leaves, oldest first.
    ///
    /// # Errors
    ///
    /// A classified [`NetError`], or a malformed leaf.
    pub fn tlog_leaves(
        &self,
        log: &kuipa_enroll::tlog::LogId,
        from: u64,
    ) -> Result<Vec<kuipa_enroll::tlog::Leaf>, NetError> {
        let url = format!("{}tlog/{log}/leaves?from={from}", self.base);
        let body = self.send("GET", &url, self.client.get(&url), 0)?;
        let malformed = || NetError::Other("tlog leaves: malformed page".into());
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| malformed())?;
        value["leaves"]
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .map(|l| {
                l.as_str()
                    .and_then(|l| b64::decode(l).ok())
                    .and_then(|l| kuipa_enroll::tlog::Leaf::from_bytes(&l).ok())
                    .ok_or_else(malformed)
            })
            .collect()
    }

    /// `GET tlog/{log}/consistency?from=<old>&size=<size>`: the proof
    /// that the server's log at `old` leaves is a prefix of its log at
    /// `size` (DESIGN-tlog.md §5).
    ///
    /// # Errors
    ///
    /// A classified [`NetError`], or a malformed proof.
    pub fn tlog_consistency(
        &self,
        log: &kuipa_enroll::tlog::LogId,
        old: u64,
        size: u64,
    ) -> Result<Vec<kuipa_enroll::merkle::Hash>, NetError> {
        let url = format!("{}tlog/{log}/consistency?from={old}&size={size}", self.base);
        let body = self.send("GET", &url, self.client.get(&url), 0)?;
        let malformed = || NetError::Other("tlog consistency: malformed proof".into());
        let value: serde_json::Value = serde_json::from_slice(&body).map_err(|_| malformed())?;
        value["proof"]
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .map(|h| {
                h.as_str()
                    .and_then(|h| b64::decode(h).ok())
                    .and_then(|h| kuipa_enroll::merkle::Hash::from_slice(&h).ok())
                    .ok_or_else(malformed)
            })
            .collect()
    }

    /// `GET adv?<query>` as given, for a replica serving the origin's
    /// public answers byte for byte (DESIGN-claim-logs.md §6): the
    /// query string is the caller's, built by the same means as
    /// [`Self::advertisement_with_heads`] builds its own.
    ///
    /// # Errors
    ///
    /// A classified [`NetError`].
    pub fn advertisement_query(&self, query: &str) -> Result<Vec<u8>, NetError> {
        let url = format!("{}adv?{query}", self.base);
        self.send("GET", &url, self.client.get(&url), 0)
    }

    /// `POST <path>` with a binary body.
    ///
    /// # Errors
    ///
    /// A classified [`NetError`].
    pub fn post(&self, path: &str, body: Vec<u8>) -> Result<Vec<u8>, NetError> {
        let url = format!("{}{path}", self.base);
        let sent = body.len();
        let request = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(body);
        self.send("POST", &url, request, sent)
    }
}
