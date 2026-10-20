//! The user-level tasks behind `kuipa` commands (§10.1).  Each one runs
//! every protocol step it needs; none exposes a step on its own.

use std::collections::BTreeMap;
use std::fs;
use std::time::SystemTime;

use kuipa_enroll::bundle::{Bundle, Opener};
use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use kuipa_enroll::epoch::verify_chain;
use kuipa_enroll::escrow::{EscrowRequest, Kind, RegisterParams, Sealed, Sealer};
use kuipa_enroll::join::{
    AuthType, KERBEROS_BINDING_LEN, KerberosBinding, Operation, PendingJoin, Prepared, Request,
    Response, kerberos_prf_input,
};
use kuipa_enroll::keytab::{Enctype, Keytab, Principal};
use kuipa_enroll::payload::Enrollment;
use kuipa_enroll::realm::{Deployment, TrustedRealm, VerifiedRealm, krb5_realm_section};
use kuipa_gssapi::GssClientCred;
use native_ossl::util::SecretBuf;
use serde_json::{Value, json};
use tang_pqc::{ExchangeKeyPair, Policy, RecoveryResponse, Thumbprint, unix_seconds};

use crate::net::{Endpoint, NetError, Trust};
use crate::paths::{self, Contents, Error, Holder, Paths, Protected, State};

/// The anchor epoch watermark (§4.8): sequence number and head hash.
type Epoch = (u64, [u8; 32]);

/// How an online join is authorised.
pub enum Auth {
    /// The OTP from the enrollment string, which is also a temporary
    /// Kerberos key of `host/<fqdn>` (§5.3): the host gets a ticket with it
    /// and rekeys itself, so the realm's Kerberos keys authenticate the
    /// server as well as the anchor.
    Otp(Secret),
    /// The OTP, checked by an LDAP bind on the server: for hosts whose OTP
    /// sets no Kerberos key.  Only the anchor authenticates the server, and
    /// the server learns the OTP.
    LdapOtp(Secret),
    /// A user's password (password, password+OTP or RADIUS users): the host
    /// gets a ticket with it in an armoured exchange with the realm's KDC
    /// and joins with Kerberos; the password never leaves the host.
    Password {
        /// The user principal.
        principal: String,
        /// The password (with an OTP appended where the user needs one).
        password: Secret,
    },
    /// An enrollment voucher (§9), with the ephemeral key (JWK) it is bound
    /// to, if it is bound.
    Voucher {
        /// The voucher's text form.
        voucher: Secret,
        /// The bound ephemeral key.
        ephemeral: Option<Secret>,
    },
    /// The caller's existing Kerberos ticket (`KRB5CCNAME`), e.g. after
    /// an armoured `kinit` for external-IdP or passkey users with the
    /// configuration from [`realm_info`].
    Ccache,
}

/// A failure the caller should report with a specific exit status.
#[derive(Debug)]
pub enum Outcome {
    /// Try again later (no server reachable, replication pending).
    RetryLater(String),
    /// An administrator must act.
    NeedsAdmin(String),
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RetryLater(m) | Self::NeedsAdmin(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Outcome {}

pub(crate) fn now() -> SystemTime {
    SystemTime::now()
}

/// The host's FQDN from the kernel.
///
/// # Errors
///
/// I/O errors.
pub fn hostname() -> Result<String, Error> {
    Ok(fs::read_to_string("/proc/sys/kernel/hostname")?
        .trim()
        .to_owned())
}

pub(crate) fn ca_trust(paths: &Paths) -> Result<Trust, Error> {
    let certs = synta_certificate::pem_to_der(&fs::read(paths.ca())?);
    if certs.is_empty() {
        return Err(format!("no certificates in {}", paths.ca().display()).into());
    }
    Ok(Trust::Ca(certs))
}

/// Refuse `adv`, fetched from `server`, unless it describes `deployment`
/// (§4.6): reported as needing an administrator.
fn check_deployment(
    server: &str,
    adv: &VerifiedRealm,
    deployment: &Deployment,
) -> Result<(), Error> {
    adv.check_deployment(deployment).map_err(|e| {
        tracing::debug!(server = %server, "advertisement refused: {e}");
        Outcome::NeedsAdmin(format!("{server}: {e}")).into()
    })
}

/// The number of distinct pinned anchors that must be able to prove a
/// realm's claim when the client knows at least that many (§4.4). A thief
/// holding a single stolen anchor can vouch for itself and nothing else:
/// a client that knows two of a realm's anchors refuses it.
const MIN_PROVING_ANCHORS: usize = 2;

/// Fetch and verify one server's advertisement.
pub(crate) fn verified(
    server: &str,
    trust: &Trust,
    realm: &str,
    anchors: &[Thumbprint],
    known: Option<Epoch>,
) -> Result<(Endpoint, VerifiedRealm, Option<Epoch>), String> {
    let endpoint = Endpoint::new(server, trust).map_err(|e| e.to_string())?;
    let mut pins: Vec<Thumbprint> = anchors.to_vec();
    pins.sort_unstable();
    pins.dedup();
    let adv = endpoint.advertisement(&pins).map_err(|e| e.to_string())?;
    let advertisement = VerifiedRealm::verify(&adv, realm, &pins, &Policy::default(), now())
        .map_err(|e| {
            tracing::debug!(server = %server, "advertisement rejected: {e}");
            format!("advertisement: {e}")
        })?;
    trace_advertisement(server, &advertisement);
    for (old, new) in advertisement.succeeded() {
        tracing::debug!(server = %server, "pinned anchor {old} was rotated: succeeded by {new}");
    }
    let mut quorum = false;
    // §4.4: with two or more anchors known, ask each remaining one for
    // its own proof of the claim. Proofs reaching the same final anchor
    // (a rotated one and its successor) count once. A realm whose
    // anchors exchanged answers two; a claim vouched by a single key,
    // stolen or not, answers one.
    if pins.len() >= MIN_PROVING_ANCHORS {
        let mut proven = vec![*advertisement.anchor()];
        for a in &pins {
            if proven.len() >= MIN_PROVING_ANCHORS {
                break;
            }
            if proven.contains(a) {
                continue;
            }
            match endpoint
                .advertisement(std::slice::from_ref(a))
                .map_err(|e| e.to_string())
                .and_then(|adv| {
                    VerifiedRealm::verify(
                        &adv,
                        realm,
                        std::slice::from_ref(a),
                        &Policy::default(),
                        now(),
                    )
                    .map_err(|e| e.to_string())
                }) {
                Ok(proof) => {
                    let by = *proof.anchor();
                    if proof.server() != advertisement.server()
                        || proof.signer() != advertisement.signer()
                        || proof.delegation_expires() != advertisement.delegation_expires()
                    {
                        // §4.4: a proof counts only for the claim it is
                        // a proof of: the same server, the same key, the
                        // same delegation — anything else proves a
                        // different claim.
                        tracing::debug!(server = %server, "pinned anchor {a} proved a different claim");
                    } else if proven.contains(&by) {
                        tracing::debug!(server = %server, "pinned anchor {a} proves the claim through {by}, already counted");
                    } else {
                        proven.push(by);
                        tracing::debug!(server = %server, "claim also proven by pinned anchor {a}");
                    }
                }
                Err(e) => {
                    tracing::debug!(server = %server, "pinned anchor {a} does not prove the claim: {e}");
                }
            }
        }
        if proven.len() < MIN_PROVING_ANCHORS {
            return Err(format!(
                "its claim is proven by {} of the {} anchors known here; the realm's anchors must vouch for it by two distinct ones, run kuipa check",
                proven.len(),
                pins.len(),
            ));
        }
        quorum = true;
    }
    // §4.8: the anchor log must continue what this host knows.
    let advanced = watermark_after(&advertisement, &endpoint, realm, anchors, known, quorum)?;
    Ok((endpoint, advertisement, advanced))
}

/// §4.8: a host that has seen this realm's anchors before must see the
/// anchor log continue what it knows: one anchor is enough to notice a
/// server left behind on a stolen or frozen anchor key.
fn watermark_after(
    advertisement: &VerifiedRealm,
    endpoint: &Endpoint,
    realm: &str,
    anchors: &[Thumbprint],
    known: Option<Epoch>,
    quorum: bool,
) -> Result<Option<Epoch>, String> {
    let Some((seq, hash)) = known else {
        // The first sighting through a proved quorum (§4.4) is a safe
        // watermark: from here on a frozen server fails below.
        return Ok(if quorum { advertisement.epoch() } else { None });
    };
    match advertisement.epoch() {
        None => {
            return Err(format!(
                "reports no anchor epoch log, but this host has seen the realm at sequence {seq}: this server's kuipad is too old, or its anchor exchange is not running",
            ));
        }
        Some((theirs, _)) if theirs < seq => {
            return Err(format!(
                "its anchor log stops at sequence {theirs}, behind the {seq} this host verified: the anchor key may have been replaced and this server left behind",
            ));
        }
        Some((theirs, theirs_head)) if theirs == seq && theirs_head != hash => {
            return Err(format!(
                "its anchor log at sequence {theirs} differs from the one this host verified: the two have forked, run kuipa check",
            ));
        }
        Some((theirs, theirs_head)) if theirs > seq => {
            // §4.8: follow the log page by page — a server answers at
            // most `MAX_EPOCH_FETCH` entries — until reaching the head
            // the advertisement claims.
            let mut reached = (seq, hash);
            while reached.0 < theirs {
                let entries = endpoint.anchor_log(reached.0).map_err(|e| e.to_string())?;
                reached =
                    verify_chain(&entries, realm, anchors, Some(reached), &Policy::default())?;
            }
            if reached != (theirs, theirs_head) {
                return Err(format!(
                    "its anchor log at sequence {theirs} commits to an entry its advertisement does not name: the two have forked",
                ));
            }
            return Ok(Some(reached));
        }
        Some(_) => {}
    }
    Ok(None)
}

fn trace_advertisement(server: &str, adv: &VerifiedRealm) {
    let info = adv.info();
    let days = adv.delegation_expires().saturating_sub(unix_seconds(now())) / 86400;
    let vouch_days = adv.vouched_until().saturating_sub(unix_seconds(now())) / 86400;
    tracing::debug!(
        server = %server,
        "advertisement verified: {} of {}, signed by {}, delegation by anchor {} (claim: {days} days left, vouch: {vouch_days} days left)",
        adv.server(),
        info.realm,
        adv.signer(),
        adv.anchor(),
    );
    let kid = |k: Result<&tang_pqc::ExchangeKey, _>| {
        k.map_or_else(|_| "-".into(), |k| k.kid().to_string())
    };
    tracing::trace!(
        server = %server,
        domain = %info.domain,
        servers = ?info.servers,
        join_key = %kid(adv.join_key()),
        escrow_key = %kid(adv.escrow_key()),
        ca_certs = info.ca_certs.len(),
        pkinit_anchors = info.pkinit_anchors.len(),
        anchors = ?info.anchors.iter().map(ToString::to_string).collect::<Vec<_>>(),
        trusts = ?info.trusts.iter().map(|t| t.realm.as_str()).collect::<Vec<_>>(),
        "advertisement contents"
    );
}

fn trace_enrollment(server: &str, e: &Enrollment) {
    let mut enctypes: Vec<i32> = e.keytab.entries().iter().map(|k| k.enctype.0).collect();
    enctypes.dedup();
    tracing::debug!(
        server = %server,
        "received keys for {} (kvno {}, enctypes {enctypes:?}), {} CA certificate(s), {} anchor(s), issuer {}",
        e.keytab.principal(),
        e.keytab.kvno().unwrap_or_default(),
        e.ca_certs.len(),
        e.anchors.len(),
        e.config.issuer,
    );
    tracing::trace!(
        server = %server,
        realm = %e.config.realm,
        domain = %e.config.domain,
        servers = ?e.config.servers,
        pkinit_anchors = e.pkinit_anchors.len(),
        "enrollment contents"
    );
}

/// Make a one-message Kerberos token for `target` (`ipa-ku@<server>`, or
/// the principal `ipa-ku/<server>@REALM`) bound to `cb`, and the binding
/// its context derives: only the real `ipa-ku/<server>` derives it too, so
/// the response is authenticated by the realm's Kerberos keys as well as by
/// the anchor (§5.1).
pub(crate) fn gss_token(
    cred: &GssClientCred,
    target: &str,
    cb: &[u8; 32],
) -> Result<(Vec<u8>, KerberosBinding), Error> {
    let (token, derived) = kuipa_gssapi::init_bound(
        cred,
        target,
        cb,
        &kerberos_prf_input(cb),
        KERBEROS_BINDING_LEN,
    )?;
    let binding = KerberosBinding::new(&derived)?;
    tracing::debug!(
        "GSS-API token for {target}, bound to the exchange ({} bytes)",
        token.len()
    );
    Ok((token, binding))
}

fn path_for(op: Operation, request: &Request) -> String {
    format!("{}/{}", op.path(), request.kid())
}

/// Run one exchange against the first usable server of `deployment`,
/// following §4.6: fail over only while nothing can have been processed;
/// after an unknown outcome retry the same server once, then stop.  A
/// server whose verified advertisement describes another deployment stops
/// the exchange before anything is sent: that is an attack or a
/// misconfiguration, and failing over would hide it.
fn exchange(
    deployment: &Deployment,
    trust: &Trust,
    realm: &str,
    anchors: &[Thumbprint],
    known: Option<(u64, [u8; 32])>,
    op: Operation,
    build: impl FnMut(&VerifiedRealm) -> Result<(Request, PendingJoin), Error>,
) -> Result<(Enrollment, VerifiedRealm), Error> {
    exchange_with(
        deployment,
        trust,
        realm,
        anchors,
        known,
        op,
        build,
        |pending, response, adv| {
            let enrollment = pending.finish(response, adv)?;
            trace_enrollment(adv.server(), &enrollment);
            Ok(enrollment)
        },
    )
}

/// As [`exchange`], for any operation: `finish` opens the response.
#[allow(clippy::too_many_arguments)]
pub(crate) fn exchange_with<T>(
    deployment: &Deployment,
    trust: &Trust,
    realm: &str,
    anchors: &[Thumbprint],
    known: Option<(u64, [u8; 32])>,
    op: Operation,
    mut build: impl FnMut(&VerifiedRealm) -> Result<(Request, PendingJoin), Error>,
    finish: impl Fn(PendingJoin, &Response, &VerifiedRealm) -> Result<T, Error>,
) -> Result<(T, VerifiedRealm), Error> {
    let mut skipped = Vec::new();
    for server in &deployment.servers {
        let (endpoint, adv, _) = match verified(server, trust, realm, anchors, known) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(server = %server, "skipped, trying the next server: {e}");
                skipped.push(format!("{server}: {e}"));
                continue;
            }
        };
        check_deployment(server, &adv, deployment)?;
        // Once the advertisement verified, its CA authenticates TLS too.
        let endpoint = if matches!(trust, Trust::FirstContact) && crate::net::uses_tls(server) {
            tracing::debug!(server = %server, "TLS from now on verified against the advertised IPA CA");
            match Endpoint::new(server, &Trust::Ca(adv.info().ca_certs.clone())) {
                Ok(e) => e,
                Err(e) => {
                    skipped.push(format!("{server}: {e}"));
                    continue;
                }
            }
        } else {
            endpoint
        };
        let mut unknown = None;
        for attempt in 0..2 {
            let (request, pending) = build(&adv)?;
            tracing::debug!(
                server = %server,
                "{op:?} request for {} in {} with {:?} authentication, to join key {}{}",
                request.fqdn(),
                request.realm(),
                request.auth_type(),
                request.kid(),
                if attempt > 0 { " (retry)" } else { "" },
            );
            match endpoint.post(&path_for(op, &request), request.to_bytes()) {
                Ok(body) => {
                    let out = finish(pending, &Response::from_bytes(&body)?, &adv)?;
                    return Ok((out, adv));
                }
                Err(NetError::Unreachable(e)) if attempt == 0 => {
                    tracing::debug!(server = %server, "not processed, trying the next server: {e}");
                    skipped.push(format!("{server}: {e}"));
                    break;
                }
                Err(NetError::Refused) => {
                    return Err(Outcome::NeedsAdmin(format!("{server} refused the request")).into());
                }
                Err(e @ (NetError::Unknown(_) | NetError::Unreachable(_))) => {
                    tracing::debug!(
                        server = %server,
                        "outcome unknown ({e}); only this server may be retried"
                    );
                    unknown = Some(e);
                }
                Err(e) => return Err(e.into()),
            }
        }
        if let Some(e) = unknown {
            return Err(Outcome::NeedsAdmin(format!(
                "{op:?} outcome unknown on {server} ({e}); do not retry elsewhere — issue a new OTP or voucher"
            ))
            .into());
        }
    }
    Err(Outcome::RetryLater(format!("no usable server: {}", skipped.join("; "))).into())
}

/// Merge `new` keys with the previous kvno of `old`, as `ipa-getkeytab`
/// does, so tickets issued under the old key stay usable.
fn merge_previous(mut new: Keytab, old: Option<Keytab>) -> Result<Keytab, Error> {
    if let Some(mut old) = old
        && old.principal() == new.principal()
        && let Some(prev) = old.kvno()
    {
        old.retain_kvno(|v| v == prev);
        new.merge(old)?;
    }
    Ok(new)
}

/// Install an enrollment's identity: keytab, CA chain, anchors and state.
fn install(paths: &Paths, enrollment: &Enrollment, fqdn: &str) -> Result<(), Error> {
    paths::write_file(&paths.keytab(), enrollment.keytab.to_mit()?.as_ref(), 0o600)?;
    paths::write_pem(&paths.ca(), &enrollment.ca_certs)?;
    paths::write_anchors_epoch(paths, &enrollment.anchors, payload_epoch(enrollment))?;
    let config = &enrollment.config;
    let mut servers = vec![config.issuer.clone()];
    servers.extend(
        config
            .servers
            .iter()
            .filter(|s| **s != config.issuer)
            .cloned(),
    );
    paths::write_pem(&paths.pkinit_anchors(), &enrollment.pkinit_anchors)?;
    let kdcs: Vec<&str> = servers.iter().map(String::as_str).collect();
    let anchors_file = paths.pkinit_anchors();
    let conf = kuipa_enroll::realm::krb5_conf(
        &config.realm,
        &config.domain,
        &kdcs,
        anchors_file.to_str().ok_or("non-UTF-8 path")?,
    );
    paths::write_file(&paths.krb5_conf(), conf.as_bytes(), 0o644)?;
    State {
        realm: config.realm.clone(),
        fqdn: fqdn.into(),
        servers,
        holder: Holder::None,
        // Other protected keytabs and files outlive a re-enrollment.
        protected: State::load(paths).map(|s| s.protected).unwrap_or_default(),
    }
    .store(paths)
}

fn summary(enrollment: &Enrollment) -> Value {
    json!({
        "realm": enrollment.config.realm,
        "principal": enrollment.keytab.principal().to_string(),
        "kvno": enrollment.keytab.kvno(),
        "issuer": enrollment.config.issuer,
        "servers": enrollment.config.servers,
        "domain": enrollment.config.domain,
        "basedn": enrollment.config.basedn,
    })
}

/// With `KUIPA_KDC=<target>` (tests, local use), `conf` with that one KDC
/// instead of the advertised ones.
fn kdc_override(conf: &str) -> String {
    let Some(kdc) = std::env::var("KUIPA_KDC").ok().filter(|k| !k.is_empty()) else {
        return conf.to_owned();
    };
    let mut done = false;
    conf.lines()
        .filter_map(|l| {
            let t = l.trim_start();
            if t.starts_with("master_kdc =") || t.starts_with("admin_server =") {
                return None;
            }
            if !t.starts_with("kdc =") {
                return Some(l.to_owned());
            }
            (!std::mem::replace(&mut done, true)).then(|| format!("        kdc = {kdc}"))
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// The server's `kuipa` principal, with its realm.
fn service_principal(adv: &VerifiedRealm) -> String {
    format!("ipa-ku/{}@{}", adv.server(), adv.info().realm)
}

/// A credential with a ticket for the `kuipa` service of the server that
/// `adv` describes, got as `principal` with `password` in an AS exchange
/// armoured by anonymous PKINIT, with the PKINIT anchors from the verified
/// advertisement and only its KDCs that are in `deployment` (§4.6, §5.4).  Nothing but the ticket outlives
/// this call: the configuration is written to a private directory that is
/// removed again.
///
/// # Errors
///
/// I/O errors, or the KDC refused (no anonymous PKINIT or FAST, a wrong
/// password): reported as needing an administrator.
fn armoured_ticket(
    adv: &VerifiedRealm,
    deployment: &Deployment,
    principal: &str,
    password: &[u8],
) -> Result<GssClientCred, Error> {
    use std::os::unix::fs::DirBuilderExt;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "kuipa-kinit-{}-{}-{seq}",
        std::process::id(),
        unix_seconds(now())
    ));
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let result = (|| {
        let anchors = dir.join("pkinit-anchors.pem");
        paths::write_pem(&anchors, &adv.info().pkinit_anchors)?;
        let config = dir.join("krb5.conf");
        let conf =
            kdc_override(&adv.krb5_conf(anchors.to_str().ok_or("non-UTF-8 path")?, deployment));
        paths::write_file(&config, conf.as_bytes(), 0o600)?;
        let ccache = format!("MEMORY:kuipa-{}-{seq}", std::process::id());
        let service = service_principal(adv);
        tracing::debug!("armoured AS exchange as {principal} for {service}");
        kuipa_gssapi::password_ticket(&config, principal, password, &service, &ccache).map_err(
            |e| -> Error {
                Outcome::NeedsAdmin(format!("Kerberos refused {principal}: {e}")).into()
            },
        )?;
        Ok(GssClientCred::from_named_ccache(&ccache)?)
    })();
    let _ = fs::remove_dir_all(&dir);
    result
}

/// Refuse an enrollment string past its expiry (§4.4).
///
/// # Errors
///
/// The string has expired.
pub fn check_string(string: &EnrollmentString) -> Result<(), Error> {
    let now = unix_seconds(now());
    string.check_valid(now).map_err(|_| {
        let days = now.saturating_sub(string.exp()) / 86400;
        format!(
            "the enrollment string expired {days} day(s) ago (at {}); ask for a new one",
            string.exp()
        )
        .into()
    })
}

/// `kuipa enroll` (online): join `realm` through the first usable server
/// of `deployment` whose advertisement verifies against `anchors` (the
/// enrollment string's, or those pre-provisioned in `/etc/ipa/ku-anchors`
/// — with two or more, its claim proven by two distinct ones, §4.4) and
/// describes `deployment`.
///
/// # Errors
///
/// [`Outcome`] for retry/administrator cases, or any other error.
pub fn enroll_online(
    paths: &Paths,
    realm: &str,
    anchors: &[Thumbprint],
    auth: &Auth,
    fqdn: &str,
    deployment: &Deployment,
) -> Result<Value, Error> {
    if deployment.servers.is_empty() {
        return Err("no server given (--server)".into());
    }
    if anchors.is_empty() {
        return Err("no anchor to verify the realm with".into());
    }
    let ambient = match auth {
        Auth::Ccache => Some(GssClientCred::ambient()?),
        _ => None,
    };
    // With the OTP as a Kerberos key, the host authenticates as itself and
    // rekeys: the rekey replaces that key with real ones.
    let op = match auth {
        Auth::Otp(_) => Operation::Rekey,
        _ => Operation::Join,
    };
    let (enrollment, _) = exchange(
        deployment,
        &Trust::FirstContact,
        realm,
        anchors,
        None,
        op,
        |adv| {
            // A ticket and the name to address the server by.
            let kerberos = match auth {
                Auth::Ccache => ambient
                    .as_ref()
                    .map(|_| (None, format!("ipa-ku@{}", adv.server()))),
                Auth::Otp(otp) => Some((
                    Some(armoured_ticket(
                        adv,
                        deployment,
                        &Principal::host(fqdn, realm).to_string(),
                        otp.as_bytes(),
                    )?),
                    service_principal(adv),
                )),
                Auth::Password {
                    principal,
                    password,
                } => {
                    let principal = if principal.contains('@') {
                        principal.clone()
                    } else {
                        format!("{principal}@{realm}")
                    };
                    Some((
                        Some(armoured_ticket(
                            adv,
                            deployment,
                            &principal,
                            password.as_bytes(),
                        )?),
                        service_principal(adv),
                    ))
                }
                Auth::LdapOtp(_) | Auth::Voucher { .. } => None,
            };
            let auth_type = match auth {
                Auth::LdapOtp(_) => AuthType::Otp,
                Auth::Voucher { .. } => AuthType::Voucher,
                Auth::Otp(_) | Auth::Password { .. } | Auth::Ccache => AuthType::Kerberos,
            };
            let mut p = Prepared::new(adv, op, fqdn, auth_type, &Enctype::DEFAULT)?;
            if let Auth::Voucher {
                ephemeral: Some(key),
                ..
            } = auth
            {
                p = p.with_ephemeral(tang_pqc::ExchangeKeyPair::from_jwk(key.as_bytes())?)?;
            }
            let authenticator = match (auth, kerberos) {
                (Auth::LdapOtp(otp), _) => native_ossl::util::SecretBuf::from_slice(otp.as_bytes()),
                (Auth::Voucher { voucher, .. }, _) => {
                    native_ossl::util::SecretBuf::from_slice(voucher.as_bytes())
                }
                (_, Some((own, target))) => {
                    let cred = own.as_ref().or(ambient.as_ref()).ok_or("no credential")?;
                    let (token, binding) = gss_token(cred, &target, &p.channel_binding()?)?;
                    p = p.with_kerberos(binding);
                    native_ossl::util::SecretBuf::new(token)
                }
                (_, None) => unreachable!("every Kerberos authenticator has a ticket"),
            };
            Ok(p.seal(authenticator.as_ref(), &[], &[])?)
        },
    )?;
    install(paths, &enrollment, fqdn)?;
    Ok(summary(&enrollment))
}

/// `kuipa prepare`: create the mode A machine key (idempotent).
///
/// # Errors
///
/// I/O or key generation errors.
pub fn prepare(paths: &Paths, replace: bool, fqdn: &str) -> Result<Value, Error> {
    let key = match fs::read(paths.recipient()) {
        Ok(jwk) if !replace => ExchangeKeyPair::from_jwk(&jwk)?,
        _ => {
            let key = ExchangeKeyPair::generate_preferred()?;
            paths::write_file(&paths.recipient(), key.to_jwk()?.as_ref(), 0o600)?;
            key
        }
    };
    paths::write_file(
        &paths.recipient_public(),
        key.public().to_jwk_json().as_bytes(),
        0o644,
    )?;
    let public = paths.recipient_public();
    Ok(json!({
        "thumbprint": key.public().kid().to_string(),
        "public_key": public,
        "admin_command": format!(
            "ipa host-add {fqdn} --pq-stage --pq-recipient={}", public.display()
        ),
    }))
}

/// `kuipa enroll --bundle`: enroll offline from a staged bundle.
///
/// # Errors
///
/// Verification, recipient or I/O errors.
pub fn enroll_bundle(
    paths: &Paths,
    bundle: &[u8],
    string: Option<&EnrollmentString>,
    insecure_signed_only: bool,
    expected_fqdn: Option<&str>,
) -> Result<Value, Error> {
    let anchors = match string {
        Some(s) => {
            check_string(s)?;
            vec![*s.anchor()]
        }
        None => paths::read_anchors(paths)?,
    };
    let verified = Bundle::from_bytes(bundle)?.verify(&anchors, &Policy::default())?;
    let fqdn = verified.bundle().fqdn().to_owned();
    tracing::debug!(
        "bundle verified: {:?} for {fqdn} from {}, valid until {}",
        verified.bundle().mode(),
        verified.server(),
        verified.bundle().not_after()
    );
    if expected_fqdn.is_some_and(|f| f != fqdn) {
        return Err(format!("bundle is for {fqdn}").into());
    }
    if verified.bundle().not_after() < unix_seconds(now()) {
        return Err(Outcome::NeedsAdmin(format!(
            "bundle for {fqdn} expired; stage the host again"
        ))
        .into());
    }
    let machine_key = fs::read(paths.recipient())
        .ok()
        .map(|j| ExchangeKeyPair::from_jwk(&j))
        .transpose()?;
    let opener = match (
        verified.bundle().mode(),
        string.and_then(EnrollmentString::secret),
        &machine_key,
    ) {
        (kuipa_enroll::bundle::Mode::MachineKey, _, Some(k)) => Opener::MachineKey(k),
        (kuipa_enroll::bundle::Mode::Secret, Some(s), _) => Opener::Secret(s.as_bytes()),
        (kuipa_enroll::bundle::Mode::SignedOnly, _, _) if insecure_signed_only => {
            Opener::InsecureSignedOnly
        }
        (mode, _, _) => {
            return Err(format!("cannot open a {mode:?} bundle with what was given").into());
        }
    };
    let enrollment = verified.open(opener)?;
    install(paths, &enrollment, &fqdn)?;
    paths::remove(&paths.recipient())?;
    paths::remove(&paths.recipient_public())?;
    let pending = json!({
        "fqdn": fqdn,
        "not_after": verified.bundle().not_after(),
        "steps": ["rotate-keys", "kinit", "ca-certs", "dns-update", "ssh-keys", "host-certificate", "time-sync", "automount"],
    });
    paths::write_file(&paths.pending(), pending.to_string().as_bytes(), 0o600)?;
    Ok(json!({ "enrollment": summary(&enrollment), "pending": pending }))
}

fn live_keytab(paths: &Paths, state: &State) -> std::path::PathBuf {
    match state.holder {
        Holder::None => paths.keytab(),
        Holder::File => paths.run_keytab(),
    }
}

/// The anchor epoch watermark sealed into an enrollment payload (§4.8),
/// if the issuing server recorded one.
fn payload_epoch(enrollment: &Enrollment) -> Option<Epoch> {
    (enrollment.epoch_seq != 0).then_some((enrollment.epoch_seq, enrollment.epoch_head))
}

/// Advertisements of every server of the realm that answers and describes
/// the stored deployment, for sealing.
pub(crate) fn all_servers(
    state: &State,
    trust: &Trust,
    anchors: &[Thumbprint],
) -> Vec<VerifiedRealm> {
    let deployment = Deployment::servers(&state.servers);
    state
        .servers
        .iter()
        .filter_map(|s| {
            verified(s, trust, &state.realm, anchors, None)
                .ok()
                .map(|(_, v, _)| v)
                .filter(|v| check_deployment(s, v, &deployment).is_ok())
        })
        .collect()
}

/// `kuipa rotate-keys`: new host keys with forward secrecy; reseals and
/// re-registers when protection is on.  Also used by `complete` and
/// `protect`.
///
/// # Errors
///
/// [`Outcome`] or any other error.
pub fn rotate_keys(paths: &Paths, protect: Option<Holder>) -> Result<Value, Error> {
    let mut state = State::load(paths)?;
    let holder = protect.unwrap_or(state.holder);
    let anchors = paths::read_anchors(paths)?;
    let known = paths::read_epoch_from(&paths.anchors())?;
    let trust = ca_trust(paths)?;
    let principal = Principal::host(&state.fqdn, &state.realm);
    let keytab_path = live_keytab(paths, &state);
    let old = fs::read(&keytab_path)
        .ok()
        .map(|b| Keytab::from_mit(&b))
        .transpose()?;
    let cred = GssClientCred::from_keytab_initiate(
        keytab_path.to_str().ok_or("non-UTF-8 keytab path")?,
        &principal.to_string(),
    )?;

    let (sealer, registrations) = if holder == Holder::None {
        (None, Vec::new())
    } else {
        let servers = all_servers(&state, &trust, &anchors);
        let refs: Vec<_> = servers.iter().collect();
        let (sealer, registered) = Sealer::prepare(&principal, Kind::Keytab, &refs)?;
        tracing::debug!(
            "sealing to the escrow keys of {:?}; {} binding(s) to register with the rekey",
            servers
                .iter()
                .map(VerifiedRealm::server)
                .collect::<Vec<_>>(),
            registered.len()
        );
        (
            Some(sealer),
            registered.into_iter().map(|r| r.binding).collect(),
        )
    };

    let (enrollment, _) = exchange(
        &Deployment::servers(&state.servers),
        &trust,
        &state.realm,
        &anchors,
        known,
        Operation::Rekey,
        |adv| {
            let p = Prepared::new(
                adv,
                Operation::Rekey,
                &state.fqdn,
                AuthType::Kerberos,
                &Enctype::DEFAULT,
            )?;
            let target = format!("ipa-ku@{}", adv.server());
            let (token, binding) = gss_token(&cred, &target, &p.channel_binding()?)?;
            Ok(p.with_kerberos(binding).seal(&token, &registrations, &[])?)
        },
    )?;
    let epoch = payload_epoch(&enrollment).or(known);
    let keytab = merge_previous(enrollment.keytab, old)?;
    match sealer {
        Some(sealer) => {
            paths::write_file(&paths.run_keytab(), keytab.to_mit()?.as_ref(), 0o600)?;
            paths::write_file(&paths.sealed(), &sealer.seal(&keytab)?.to_bytes(), 0o600)?;
        }
        None => paths::write_file(&paths.keytab(), keytab.to_mit()?.as_ref(), 0o600)?,
    }
    paths::write_anchors_epoch(paths, &enrollment.anchors, epoch)?;
    let mut servers = vec![enrollment.config.issuer.clone()];
    servers.extend(
        state
            .servers
            .iter()
            .filter(|s| **s != enrollment.config.issuer)
            .cloned(),
    );
    state.servers = servers;
    state.holder = holder;
    state.store(paths)?;
    Ok(
        json!({ "principal": principal.to_string(), "kvno": keytab.kvno(), "issuer": enrollment.config.issuer }),
    )
}

/// `kuipa complete`: finish an offline enrollment (first contact, §8.5).
///
/// # Errors
///
/// [`Outcome::RetryLater`] while no server is reachable, or any error.
pub fn complete(paths: &Paths) -> Result<Value, Error> {
    let pending: Value = serde_json::from_slice(
        &fs::read(paths.pending())
            .map_err(|_| "nothing to complete (no pending offline enrollment)")?,
    )?;
    let rotated = match rotate_keys(paths, None) {
        Ok(v) => v,
        Err(e) => match e.downcast::<Outcome>() {
            Ok(o) => return Err(o),
            // Staged keys not replicated yet look like a GSS failure: retry.
            Err(e) => return Err(Outcome::RetryLater(format!("first contact failed: {e}")).into()),
        },
    };
    paths::remove(&paths.pending())?;
    let deferred: Vec<_> = pending["steps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| *s != "rotate-keys")
        .cloned()
        .collect();
    Ok(json!({ "rotated": rotated, "remaining_for_ipa_client_install": deferred }))
}

/// Send escrow recovery requests to the servers a sealed object names.
fn recover(trust: &Trust) -> impl FnMut(&str, &EscrowRequest) -> Option<RecoveryResponse> + '_ {
    move |server, request| {
        tracing::debug!(
            server = %server,
            "escrow recovery for {} with escrow key {}",
            request.principal(),
            request.recovery().kid()
        );
        let endpoint = Endpoint::new(server, trust).ok()?;
        let body = endpoint
            .post(
                &format!("rec/{}", request.recovery().kid()),
                request.to_bytes(),
            )
            .ok()?;
        RecoveryResponse::from_bytes(&body).ok()
    }
}

/// Unseal the sealed host keytab through any server.
///
/// # Errors
///
/// [`Outcome::RetryLater`] if no server could unseal it.
pub fn unseal(paths: &Paths) -> Result<Keytab, Error> {
    let sealed = Sealed::from_bytes(&fs::read(paths.sealed())?)?;
    let trust = ca_trust(paths)?;
    sealed
        .unseal(recover(&trust))
        .map_err(|_| Outcome::RetryLater("no server could unseal the keytab".into()).into())
}

/// Unseal any sealed keytab or file through any server: a keytab comes
/// back as it was sealed, checked to be its principal's.
///
/// # Errors
///
/// [`Outcome::RetryLater`] if no server could unseal it, or a malformed
/// file.
pub fn unseal_file(paths: &Paths, sealed: &std::path::Path) -> Result<SecretBuf, Error> {
    let what = sealed.display().to_string();
    let sealed = Sealed::from_bytes(&fs::read(sealed)?)?;
    let trust = ca_trust(paths)?;
    let retry =
        |_| -> Error { Outcome::RetryLater(format!("no server could unseal {what}")).into() };
    match sealed.kind() {
        Kind::Keytab => sealed.unseal_mit(recover(&trust)).map_err(retry),
        Kind::File => sealed.unseal_contents(recover(&trust)).map_err(retry),
    }
}

/// Write the unsealed copy of `item` with the original file's mode and
/// ownership.
fn write_copy(paths: &Paths, item: &Protected, contents: &[u8]) -> Result<(), Error> {
    let copy = paths.run_copy(&item.path);
    paths::write_file(&copy, contents, item.mode)?;
    std::os::unix::fs::chown(&copy, Some(item.uid), Some(item.gid))?;
    Ok(())
}

/// `kuipa-unseal --all` (boot): the host keytab if it is protected, and
/// the unsealed copy of every other protected keytab and file.  Each one
/// is tried even when another fails.
///
/// # Errors
///
/// [`Outcome::RetryLater`] if any could not be unsealed for want of a
/// server, or the first other error.
pub fn unseal_all(paths: &Paths) -> Result<Value, Error> {
    let state = State::load(paths)?;
    let mut written = Vec::new();
    let mut failed = Vec::new();
    let mut retry = false;
    let mut note = |what: String, e: Error| {
        retry |= e
            .downcast_ref::<Outcome>()
            .is_some_and(|o| matches!(o, Outcome::RetryLater(_)));
        failed.push(format!("{what}: {e}"));
    };
    if state.holder == Holder::File {
        match unseal(paths)
            .and_then(|k| paths::write_file(&paths.run_keytab(), k.to_mit()?.as_ref(), 0o600))
        {
            Ok(()) => written.push(paths.run_keytab().display().to_string()),
            Err(e) => note(paths.keytab().display().to_string(), e),
        }
    }
    for item in &state.protected {
        match unseal_file(paths, &paths::sealed_for(&item.path))
            .and_then(|c| write_copy(paths, item, c.as_ref()))
        {
            Ok(()) => written.push(paths.run_copy(&item.path).display().to_string()),
            Err(e) => note(item.path.display().to_string(), e),
        }
    }
    if failed.is_empty() {
        Ok(json!({ "written": written }))
    } else if retry {
        Err(Outcome::RetryLater(failed.join("; ")).into())
    } else {
        Err(failed.join("; ").into())
    }
}

/// What `kuipa protect` and `unprotect` act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// The host keytab (file mode, §7.3).
    Host,
    /// Another keytab, a service's or a user's, sealed for its own
    /// principal (§7.5).
    Keytab(std::path::PathBuf),
    /// Any file, sealed for the principal of `keytab` (default: the host
    /// keytab), whose keys authenticate its registrations (§7.5).
    File {
        /// The file.
        path: std::path::PathBuf,
        /// The keytab of the principal to seal it for.
        keytab: Option<std::path::PathBuf>,
    },
}

/// `kuipa protect`: seal the host keytab (file mode, §7.3), or any other
/// keytab or file (§7.5).
///
/// # Errors
///
/// Any error; the plaintext stays until a test unseal succeeded.
pub fn protect(paths: &Paths, target: &Target) -> Result<Value, Error> {
    match target {
        Target::Host => protect_host(paths),
        Target::Keytab(path) => protect_other(paths, Contents::Keytab, path, None),
        Target::File { path, keytab } => {
            protect_other(paths, Contents::File, path, keytab.as_deref())
        }
    }
}

fn protect_host(paths: &Paths) -> Result<Value, Error> {
    let state = State::load(paths)?;
    if state.holder != Holder::None {
        return Err("keytab protection is already on".into());
    }
    let rotated = rotate_keys(paths, Some(Holder::File))?;
    // Test-unseal before the plaintext keytab goes away.
    let unsealed = unseal(paths)?;
    let current = Keytab::from_mit(&fs::read(paths.run_keytab())?)?;
    if unsealed.kvno() != current.kvno() {
        return Err("test unseal returned other keys; keeping the plaintext keytab".into());
    }
    paths::remove(&paths.keytab())?;
    std::os::unix::fs::symlink(paths.run_keytab(), paths.keytab())?;
    Ok(json!({ "holder": "file", "rotated": rotated, "sealed": paths.sealed() }))
}

/// Which binding set holds what `contents` names.
fn kind_of(contents: Contents) -> Kind {
    match contents {
        Contents::Keytab => Kind::Keytab,
        Contents::File => Kind::File,
    }
}

/// The bindings of the seal in `sealed`, to retire; none if it is gone or
/// unreadable.
fn sealed_bindings(sealed: &std::path::Path) -> Result<Vec<[u8; 32]>, Error> {
    Ok(fs::read(sealed)
        .ok()
        .and_then(|b| Sealed::from_bytes(&b).ok())
        .map(|s| s.bindings())
        .transpose()?
        .unwrap_or_default())
}

/// `path` made absolute without resolving symlinks: a protected path is
/// one.
fn absolute(path: &std::path::Path) -> Result<std::path::PathBuf, Error> {
    Ok(std::path::absolute(path)?)
}

/// Is `path` the host keytab (or, once protected, its unsealed copy)?
fn is_host_keytab(paths: &Paths, path: &std::path::Path) -> bool {
    let same = |a: &std::path::Path, b: &std::path::Path| {
        a == b || fs::canonicalize(a).is_ok_and(|a| fs::canonicalize(b).is_ok_and(|b| a == b))
    };
    same(path, &paths.keytab()) || same(path, &paths.run_keytab())
}

/// Register `bindings` for `params.principal`, authenticated by the keys
/// in `keytab` (§7.5).  Returns the server that registered them.
fn register(
    paths: &Paths,
    state: &State,
    keytab: &std::path::Path,
    params: &RegisterParams,
    bindings: &[[u8; 32]],
) -> Result<String, Error> {
    let anchors = paths::read_anchors(paths)?;
    let known = paths::read_epoch_from(&paths.anchors())?;
    let trust = ca_trust(paths)?;
    let cred = GssClientCred::from_keytab_initiate(
        keytab.to_str().ok_or("non-UTF-8 keytab path")?,
        &params.principal.to_string(),
    )?;
    let extra = params.to_bytes()?;
    tracing::debug!(
        "registering {} {:?} binding(s) for {}, retiring {}",
        bindings.len(),
        params.kind,
        params.principal,
        params.retire.len()
    );
    let ((), adv) = exchange_with(
        &Deployment::servers(&state.servers),
        &trust,
        &state.realm,
        &anchors,
        known,
        Operation::Register,
        |adv| {
            let p = Prepared::new(
                adv,
                Operation::Register,
                &state.fqdn,
                AuthType::Kerberos,
                &Enctype::DEFAULT,
            )?;
            let target = format!("ipa-ku@{}", adv.server());
            let (token, binding) = gss_token(&cred, &target, &p.channel_binding()?)?;
            Ok(p.with_kerberos(binding).seal(&token, bindings, &extra)?)
        },
        |pending, response, adv| Ok(pending.finish_register(response, adv, params)?),
    )?;
    Ok(adv.server().to_owned())
}

/// Seal `path` (a keytab, or a file for the principal of `keytab`),
/// register its bindings, test-unseal it, and only then replace it with a
/// symlink to its unsealed copy.  Protecting it again reseals what is
/// there now (after `ipa-getkeytab` wrote new keys, or the file changed)
/// and retires the previous seal.
fn protect_other(
    paths: &Paths,
    contents: Contents,
    path: &std::path::Path,
    keytab: Option<&std::path::Path>,
) -> Result<Value, Error> {
    let mut state = State::load(paths)?;
    let path = absolute(path)?;
    if is_host_keytab(paths, &path) {
        return Err(
            "that is the host keytab: run `kuipa protect` without --keytab or --file".into(),
        );
    }
    let existing = state.protected.iter().position(|p| p.path == path);
    if let Some(i) = existing
        && state.protected[i].contents != contents
    {
        return Err(format!(
            "{} is already protected as a {:?}",
            path.display(),
            state.protected[i].contents
        )
        .into());
    }
    // Through the symlink when already protected: the unsealed copy.
    let plain = SecretBuf::new(fs::read(&path)?);
    let owner_keytab = match (contents, existing, keytab) {
        (Contents::Keytab, _, _) => path.clone(),
        (Contents::File, Some(i), None) => state.protected[i].keytab.clone(),
        (Contents::File, _, Some(k)) => absolute(k)?,
        (Contents::File, None, None) => paths.keytab(),
    };
    let principal = Keytab::from_mit(&fs::read(&owner_keytab)?)?
        .principal()
        .clone();
    if principal.realm() != state.realm {
        return Err(format!("{principal} is not of this host's realm {}", state.realm).into());
    }
    let sealed_path = paths::sealed_for(&path);
    let retire = match (contents, existing) {
        (Contents::File, Some(_)) => sealed_bindings(&sealed_path)?,
        _ => Vec::new(),
    };

    let anchors = paths::read_anchors(paths)?;
    let trust = ca_trust(paths)?;
    let servers = all_servers(&state, &trust, &anchors);
    let refs: Vec<_> = servers.iter().collect();
    let (sealer, registrations) = Sealer::prepare(&principal, kind_of(contents), &refs)?;
    let bindings: Vec<_> = registrations.iter().map(|r| r.binding).collect();
    let params = RegisterParams {
        principal: principal.clone(),
        kind: kind_of(contents),
        retire,
    };
    let registrar = register(paths, &state, &owner_keytab, &params, &bindings)?;
    let seal = match contents {
        Contents::Keytab => sealer.seal_mit(plain.as_ref())?,
        Contents::File => sealer.seal_file(plain.as_ref())?,
    };
    paths::write_file(&sealed_path, &seal.to_bytes(), 0o600)?;

    // Test-unseal before the plaintext goes away.
    let unsealed = unseal_file(paths, &sealed_path)?;
    if unsealed.as_ref() != plain.as_ref() {
        return Err(format!(
            "test unseal returned something else; keeping {} as it is",
            path.display()
        )
        .into());
    }
    let item = if let Some(i) = existing {
        state.protected[i].clone()
    } else {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&path)?;
        let (mode, uid, gid) = (meta.mode() & 0o7777, meta.uid(), meta.gid());
        let (principal, keytab) = (principal.to_string(), owner_keytab);
        let path = path.clone();
        Protected {
            contents,
            path,
            principal,
            keytab,
            mode,
            uid,
            gid,
        }
    };
    write_copy(paths, &item, plain.as_ref())?;
    if existing.is_none() {
        paths::remove(&path)?;
        std::os::unix::fs::symlink(paths.run_copy(&path), &path)?;
        state.protected.push(item);
        state.store(paths)?;
    }
    Ok(json!({
        "contents": contents,
        "path": path,
        "principal": principal.to_string(),
        "sealed": sealed_path,
        "unsealed_copy": paths.run_copy(&path),
        "servers": seal.servers(),
        "registered_by": registrar,
        "resealed": existing.is_some(),
    }))
}

/// `kuipa unprotect`: back to a plain host keytab, or another keytab or
/// file back in place, its bindings retired.
///
/// # Errors
///
/// Any error.
pub fn unprotect(paths: &Paths, target: &Target) -> Result<Value, Error> {
    match target {
        Target::Host => unprotect_host(paths),
        Target::Keytab(path) | Target::File { path, .. } => unprotect_other(paths, path),
    }
}

fn unprotect_host(paths: &Paths) -> Result<Value, Error> {
    let mut state = State::load(paths)?;
    if state.holder == Holder::None {
        return Err("keytab protection is not on".into());
    }
    let keytab = match fs::read(paths.run_keytab()) {
        Ok(b) => Keytab::from_mit(&b)?,
        Err(_) => unseal(paths)?,
    };
    paths::write_file(&paths.keytab(), keytab.to_mit()?.as_ref(), 0o600)?;
    paths::remove(&paths.sealed())?;
    paths::remove(&paths.run_keytab())?;
    state.holder = Holder::None;
    state.store(paths)?;
    Ok(json!({ "holder": "none" }))
}

fn unprotect_other(paths: &Paths, path: &std::path::Path) -> Result<Value, Error> {
    let mut state = State::load(paths)?;
    let path = absolute(path)?;
    let i = state
        .protected
        .iter()
        .position(|p| p.path == path)
        .ok_or_else(|| format!("{} is not protected by kuipa", path.display()))?;
    let item = state.protected[i].clone();
    let sealed_path = paths::sealed_for(&path);
    let copy = paths.run_copy(&path);
    let plain = match fs::read(&copy) {
        Ok(b) => SecretBuf::new(b),
        Err(_) => unseal_file(paths, &sealed_path)?,
    };
    // Back in place first: the keytab authenticates the retirement.
    paths::write_file(&path, plain.as_ref(), item.mode)?;
    std::os::unix::fs::chown(&path, Some(item.uid), Some(item.gid))?;
    let keytab = if item.contents == Contents::Keytab {
        path.clone()
    } else {
        item.keytab.clone()
    };
    let params = RegisterParams {
        principal: item.principal.parse()?,
        kind: kind_of(item.contents),
        retire: match item.contents {
            Contents::Keytab => Vec::new(),
            Contents::File => sealed_bindings(&sealed_path)?,
        },
    };
    // Retiring needs a server; the plain file is back either way.
    let retired = register(paths, &state, &keytab, &params, &[]).map_err(|e| e.to_string());
    paths::remove(&sealed_path)?;
    paths::remove(&copy)?;
    state.protected.remove(i);
    state.store(paths)?;
    Ok(json!({
        "contents": item.contents,
        "path": path,
        "principal": item.principal,
        "retired": retired.is_ok(),
        "retire_error": retired.err(),
    }))
}

/// `kuipa status`: local state only.
///
/// # Errors
///
/// I/O errors.
pub fn status(paths: &Paths) -> Result<Value, Error> {
    let Ok(state) = State::load(paths) else {
        return Ok(json!({ "enrolled": false, "prepared": paths.recipient().exists() }));
    };
    let keytab = fs::read(live_keytab(paths, &state))
        .ok()
        .and_then(|b| Keytab::from_mit(&b).ok());
    let pending: Option<Value> = fs::read(paths.pending())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    Ok(json!({
        "enrolled": true,
        "realm": state.realm,
        "principal": Principal::host(&state.fqdn, &state.realm).to_string(),
        "kvno": keytab.as_ref().and_then(Keytab::kvno),
        "servers": state.servers,
        "anchors": paths::read_anchors(paths).unwrap_or_default().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "trusted_realms": paths.trusted_realms(),
        "protection": state.holder,
        "protected": state.protected.iter().map(|p| json!({
            "contents": p.contents,
            "path": p.path,
            "principal": p.principal,
            "sealed": paths::sealed_for(&p.path),
        })).collect::<Vec<_>>(),
        "pending": pending,
        "policy": {
            "ml_kem_768": tang_pqc::KemAlg::MlKem768.allowed_by_system().unwrap_or(false),
            "ml_kem_1024": tang_pqc::KemAlg::MlKem1024.allowed_by_system().unwrap_or(false),
        },
    }))
}

/// `kuipa check`: would this host work right now?  Reports problems with
/// the action that fixes them.
///
/// # Errors
///
/// Only for a host that is not enrolled; problems are reported in the
/// result.
pub fn check(paths: &Paths, only: Option<&str>) -> Result<Value, Error> {
    let state = State::load(paths)?;
    let anchors = paths::read_anchors(paths)?;
    let known = paths::read_epoch_from(&paths.anchors())?;
    let trust = ca_trust(paths)?;
    let principal = Principal::host(&state.fqdn, &state.realm).to_string();
    let keytab_path = live_keytab(paths, &state);
    let mut problems = Vec::new();
    let mut servers = Vec::new();
    let mut advanced = None;
    for server in state
        .servers
        .iter()
        .filter(|s| only.is_none_or(|o| o == s.as_str()))
    {
        match verified(server, &trust, &state.realm, &anchors, known).and_then(
            |(e, adv, advance)| {
                adv.check_deployment(&Deployment::servers(&state.servers))
                    .map(|()| (e, adv, advance))
                    .map_err(|e| e.to_string())
            },
        ) {
            Ok((_, adv, advance)) => {
                advanced = advance;
                let days = adv.delegation_expires().saturating_sub(unix_seconds(now())) / 86400;
                let vouch_hours = adv.vouched_until().saturating_sub(unix_seconds(now())) / 3600;
                if days < 14 {
                    problems.push(format!("{server}: its claim expires in {days} days: the server renews it itself, so check its anchor exchange"));
                }
                if vouch_hours < 48 {
                    problems.push(format!("{server}: the anchor's vouch expires in {vouch_hours} hours: anchors vouch again at half life, so check that server's anchor exchange"));
                }
                // Pins are only rewritten from Kerberos-bound responses (§4.7).
                let rotated: Vec<String> = adv
                    .succeeded()
                    .iter()
                    .map(|(old, new)| format!("{old} -> {new}"))
                    .collect();
                if !rotated.is_empty() {
                    problems.push(format!(
                        "{server}: verified only through the succession of rotated anchors ({}): run `kuipa rotate-keys` to refresh the pinned anchors",
                        rotated.join(", ")
                    ));
                }
                servers.push(json!({ "server": server, "ok": true, "delegation_days_left": days, "vouch_hours_left": vouch_hours, "rotated_anchors": rotated }));
            }
            Err(e) => {
                problems.push(format!("{server}: {e}"));
                servers.push(json!({ "server": server, "ok": false, "error": e }));
            }
        }
    }

    // Pins stay as they were (they are only rewritten from Kerberos-bound
    // responses, §4.7); only the verified watermark moves.
    if let Some((seq, head)) = advanced {
        let pins = paths::read_anchor_pins(&paths.anchors())?;
        paths::write_anchor_pins(
            &paths.anchors(),
            "kuipa realm anchors",
            &pins,
            Some((seq, head)),
        )?;
    }
    let kinit = keytab_path
        .to_str()
        .ok_or("non-UTF-8 keytab path")
        .map_err(Error::from)
        .and_then(|p| GssClientCred::from_keytab_initiate(p, &principal).map_err(Error::from));
    if let Err(e) = &kinit {
        problems.push(format!(
            "cannot get a ticket with the host keys ({e}): run `kuipa rotate-keys` or re-enroll"
        ));
    }
    if state.holder != Holder::None
        && let Err(e) = unseal(paths)
    {
        problems.push(format!(
            "{e}: run `kuipa protect` again once servers are reachable"
        ));
    }
    for item in &state.protected {
        if let Err(e) = unseal_file(paths, &paths::sealed_for(&item.path)) {
            let flag = match item.contents {
                Contents::Keytab => "--keytab",
                Contents::File => "--file",
            };
            problems.push(format!(
                "{}: {e}: run `kuipa protect {flag} {}` again once servers are reachable",
                item.path.display(),
                item.path.display()
            ));
        }
    }
    Ok(
        json!({ "ok": problems.is_empty(), "servers": servers, "kinit": kinit.is_ok(), "problems": problems }),
    )
}
/// `kuipa advertisement`: what each server of `deployment` advertises,
/// verified against `anchors` as enrollment verifies (§4.4, §4.6), the
/// anchor log behind the head the advertisement names: the landmark chain
/// (§4.8), and a per-key index of the same facts — for every anchor or
/// signing key these servers name, what it belongs to and where it appears.
/// Reads and verifies; writes nothing.  Like `enroll` before the first
/// enrollment, the transport is trust-on-first-use: what is believed comes
/// from the anchors, not the server certificate.
#[must_use]
pub fn advertisements(realm: &str, anchors: &[Thumbprint], deployment: &Deployment) -> Value {
    let trust = Trust::FirstContact;
    let mut servers = Vec::new();
    for server in &deployment.servers {
        let detail =
            match verified(server, &trust, realm, anchors, None).and_then(|(endpoint, adv, _)| {
                adv.check_deployment(deployment)
                    .map(|()| (endpoint, adv))
                    .map_err(|e| e.to_string())
            }) {
                Ok((endpoint, adv)) => {
                    advertisement_detail(server, &endpoint, &adv, realm, anchors)
                }
                Err(e) => Err(e),
            };
        match detail {
            Ok(value) => servers.push(value),
            Err(e) => servers.push(json!({ "server": server, "ok": false, "error": e })),
        }
    }
    // Inverse index of the same verified facts, keyed by thumbprint: one
    // entry per key this deployment names, so `grep <thumbprint>` answers
    // where it belongs without reading every server block.  Derived from
    // the details above — the log is not fetched twice, and a landmark
    // head is a tree hash, never an anchor key, so heads stay in each
    // server's log lines.
    let index = anchor_index(&servers, anchors);
    json!({
        "ok": servers.iter().all(|s| s["ok"] == Value::Bool(true)),
        "servers": servers,
        "pinned": anchors.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "anchors": index,
    })
}

/// Where each key named by the verified advertisements belongs.
#[derive(Default)]
struct AnchorRoles {
    /// Pinned on this host.
    pinned: bool,
    /// Servers whose claim its vouch proves (§4.2).
    proves: Vec<String>,
    /// Servers that name it as a current anchor of their realm (§4.6).
    current_of: Vec<String>,
    /// `server` names it as the key that signs its advertisements.
    signer_of: Vec<String>,
    /// Realms whose anchors it is, as vouched for here (§17).
    trust_of: Vec<String>,
    /// Anchor-log entries it is current in (§4.8).
    log_sequences: Vec<u64>,
    /// `old -> new`: another anchor replaces it (§4.7).
    replaced_by: Vec<String>,
    /// `old -> new`: it replaces another anchor.
    replaces: Vec<String>,
}

impl AnchorRoles {
    /// JSON form, keyed by the thumbprint so `grep <thumbprint>` finds the
    /// whole record on one line.  Each list is sorted and deduplicated:
    /// several servers of one deployment name the same anchor.
    fn into_json(self, key: &str) -> Value {
        fn unique(mut names: Vec<String>) -> Vec<String> {
            names.sort();
            names.dedup();
            names
        }
        let mut sequences = self.log_sequences;
        sequences.sort_unstable();
        sequences.dedup();
        json!({
            "key": key,
            "pinned": self.pinned,
            "proves": unique(self.proves),
            "current_of": unique(self.current_of),
            "signer_of": unique(self.signer_of),
            "trust_of": unique(self.trust_of),
            "log_sequences": sequences,
            "replaces": unique(self.replaces),
            "replaced_by": unique(self.replaced_by),
        })
    }
}

/// Build the per-key index from the per-server details already built:
/// nothing is refetched, and every fact here came from an advertisement
/// that verified against `anchors`.  A landmark head is a tree hash over
/// an epoch entry (§4.8), not a key, so heads are not indexed — they stay
/// in each server's log lines.
fn anchor_index(servers: &[Value], anchors: &[Thumbprint]) -> Vec<Value> {
    fn items(v: &Value) -> &[Value] {
        v.as_array().map_or(&[][..], Vec::as_slice)
    }
    fn text(v: &Value) -> &str {
        v.as_str().unwrap_or_default()
    }
    // One entry per key, created on first mention.  A closure would have
    // to return a borrow of `roles` that outlives its own body, so this is
    // a plain function.
    fn note<'a>(roles: &'a mut BTreeMap<String, AnchorRoles>, key: &str) -> &'a mut AnchorRoles {
        roles.entry(key.to_string()).or_default()
    }
    let mut roles: BTreeMap<String, AnchorRoles> = BTreeMap::new();
    let pinned: Vec<String> = anchors.iter().map(ToString::to_string).collect();
    for server in servers.iter().filter(|s| s["ok"] == Value::Bool(true)) {
        let name = text(&server["server"]);
        note(&mut roles, text(&server["proven_by"]))
            .proves
            .push(name.into());
        note(&mut roles, text(&server["signer"]))
            .signer_of
            .push(name.into());
        for key in items(&server["anchors"]) {
            note(&mut roles, text(key)).current_of.push(name.into());
        }
        for t in items(&server["trusts"]) {
            let realm = text(&t["realm"]);
            for key in items(&t["anchors"]) {
                note(&mut roles, text(key)).trust_of.push(realm.into());
            }
        }
        // `old -> new`, the form the details render successions in (§4.7):
        // a claim is proven only through the chain the advertisement names.
        for s in items(&server["rotated_anchors"]) {
            if let Some((old, new)) = text(s).split_once(" -> ") {
                note(&mut roles, old).replaced_by.push(new.into());
                note(&mut roles, new).replaces.push(old.into());
            }
        }
        for entry in items(&server["landmarks"]) {
            let seq = entry["seq"].as_u64().unwrap_or_default();
            for key in items(&entry["anchors"]) {
                note(&mut roles, text(key)).log_sequences.push(seq);
            }
        }
    }
    // Whether this host pins the key is a fact about this host, which no
    // advertisement can tell us.
    for anchor in &pinned {
        note(&mut roles, anchor).pinned = true;
    }
    roles
        .into_iter()
        .map(|(key, roles)| roles.into_json(&key))
        .collect()
}

/// One server's verified advertisement as the user can see it.
fn advertisement_detail(
    server: &str,
    endpoint: &Endpoint,
    adv: &VerifiedRealm,
    realm: &str,
    anchors: &[Thumbprint],
) -> Result<Value, String> {
    let landmarks = landmark_chain(endpoint, adv, realm, anchors)?;
    let info = adv.info();
    let now = unix_seconds(now());
    let kid = |k: Result<&tang_pqc::ExchangeKey, _>| {
        k.map_or_else(|_| "-".into(), |k| k.kid().to_string())
    };
    Ok(json!({
        "server": server,
        "ok": true,
        "realm": info.realm,
        "domain": info.domain,
        "kdcs": info.servers,
        "signer": adv.signer().to_string(),
        "proven_by": adv.anchor().to_string(),
        "delegation_days_left": adv.delegation_expires().saturating_sub(now) / 86400,
        "vouch_hours_left": adv.vouched_until().saturating_sub(now) / 3600,
        "rotated_anchors": adv
            .succeeded()
            .iter()
            .map(|(old, new)| format!("{old} -> {new}"))
            .collect::<Vec<_>>(),
        "join_key": kid(adv.join_key()),
        "escrow_key": kid(adv.escrow_key()),
        "ca_certs": info.ca_certs.len(),
        "pkinit_anchors": info.pkinit_anchors.len(),
        "anchors": info
            .anchors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "trusts": info
            .trusts
            .iter()
            .map(|t| json!({
                "realm": t.realm,
                // §17: the anchors the advertising realm vouches for; without
                // them an anchor in the picture has no realm.
                "anchors": t.anchors.iter().map(ToString::to_string).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        // §4.8: the head the advertisement names, in the `epoch` line's
        // `<seq> <hash>` form.
        "anchor_log_head": adv
            .epoch()
            .map_or_else(String::new, |(seq, head)| format!("{seq} {}", Thumbprint::from_bytes(head))),
        "landmarks": landmarks,
    }))
}

/// Fetch and verify the whole anchor log behind the advertised head,
/// page by page from the first entry (§4.8): every entry is a landmark —
/// the realm's anchors and successions at that sequence, committed by its
/// head to the one before it. Verified from `anchors` alone, the way a
/// fetched continuation is verified in §4.8; a log that does not end at
/// the advertised head is a fork or a server left behind.
fn landmark_chain(
    endpoint: &Endpoint,
    adv: &VerifiedRealm,
    realm: &str,
    anchors: &[Thumbprint],
) -> Result<Vec<Value>, String> {
    let Some((head_seq, head)) = adv.epoch() else {
        return Ok(Vec::new());
    };
    let policy = Policy::default();
    let mut out = Vec::new();
    let mut reached: Option<(u64, [u8; 32])> = None;
    while reached != Some((head_seq, head)) {
        let page = endpoint
            .anchor_log(reached.map_or(0, |(seq, _)| seq))
            .map_err(|e| e.to_string())?;
        if page.is_empty() {
            return Err(format!(
                "its anchor log ends at sequence {}, not the {head_seq} its advertisement names",
                reached.map_or(0, |(seq, _)| seq),
            ));
        }
        reached = Some(verify_chain(&page, realm, anchors, reached, &policy)?);
        for signed in &page {
            let epoch = signed
                .statement()
                .map_err(|_| "the anchor log is malformed".to_string())?;
            out.push(json!({
                "seq": epoch.seq(),
                "head": Thumbprint::from_bytes(
                    epoch.head().map_err(|_| "cannot hash the anchor log".to_string())?,
                )
                .to_string(),
                "prev": Thumbprint::from_bytes(epoch.prev()).to_string(),
                "anchors": epoch
                    .anchors()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                "successions": epoch
                    .successions()
                    .iter()
                    .map(|s| {
                        let st = s.statement().map_err(
                            |_| "a succession in the anchor log is malformed".to_string(),
                        )?;
                        Ok(format!("{} -> {}", st.old, st.new))
                    })
                    .collect::<Result<Vec<_>, String>>()?,
            }));
        }
    }
    Ok(out)
}

/// `kuipa realm-info`: verify the realm through the first usable server
/// and write what Kerberos needs before enrollment into `dir`: a
/// `krb5.conf`, the PKINIT anchors and the IPA CA.  `ipa-client-install`
/// uses it to `kinit -n` (anonymous PKINIT armour) and then `kinit -T` an
/// administrator with an external IdP or a passkey, before
/// `kuipa enroll --use-ccache`.
///
/// # Errors
///
/// [`Outcome::RetryLater`] if no server verifies,
/// [`Outcome::NeedsAdmin`] if one describes another deployment than
/// `deployment` (its KDCs are narrowed to `deployment` too), or I/O
/// errors.
pub fn realm_info(
    realm: &str,
    anchors: &[Thumbprint],
    deployment: &Deployment,
    dir: &std::path::Path,
) -> Result<Value, Error> {
    let mut skipped = Vec::new();
    for server in &deployment.servers {
        match verified(server, &Trust::FirstContact, realm, anchors, None) {
            Ok((_, adv, _)) => {
                check_deployment(server, &adv, deployment)?;
                let anchors_file = dir.join("pkinit-anchors.pem");
                let conf =
                    adv.krb5_conf(anchors_file.to_str().ok_or("non-UTF-8 path")?, deployment);
                paths::write_pem(&anchors_file, &adv.info().pkinit_anchors)?;
                paths::write_pem(&dir.join("ca.crt"), &adv.info().ca_certs)?;
                paths::write_file(&dir.join("krb5.conf"), conf.as_bytes(), 0o644)?;
                return Ok(json!({
                    "realm": adv.info().realm,
                    "domain": adv.info().domain,
                    "server": adv.server(),
                    "servers": adv.info().servers,
                    "krb5_conf": dir.join("krb5.conf"),
                    "pkinit_anchors": anchors_file,
                    "ca": dir.join("ca.crt"),
                }));
            }
            Err(e) => skipped.push(format!("{server}: {e}")),
        }
    }
    Err(Outcome::RetryLater(format!("no usable server: {}", skipped.join("; "))).into())
}

/// Write a trusted realm's files from its verified advertisement.  The
/// anchors file goes last: it marks the realm as installed.
fn install_trust(
    paths: &Paths,
    own_realm: &str,
    t: &TrustedRealm,
    adv: &VerifiedRealm,
) -> Result<(), Error> {
    let dir = paths.trust_dir(&t.realm);
    let pkinit = dir.join("pkinit-anchors.pem");
    paths::write_pem(&pkinit, &adv.info().pkinit_anchors)?;
    paths::write_pem(&dir.join("ca.crt"), &adv.info().ca_certs)?;
    let mut kdcs = vec![adv.server()];
    kdcs.extend(adv.info().servers.iter().map(String::as_str));
    let conf = format!(
        "# Generated by kuipa: {} as trusted by {own_realm}, from its verified advertisement.\n{}",
        t.realm,
        krb5_realm_section(
            &t.realm,
            &adv.info().domain,
            &kdcs,
            pkinit.to_str().ok_or("non-UTF-8 path")?
        )
    );
    paths::write_file(&paths.trust_krb5_conf(&t.realm), conf.as_bytes(), 0o644)?;
    paths::write_anchors_to(
        &paths.trust_anchors(&t.realm),
        &format!(
            "kuipa anchors of {}, vouched for by {own_realm}; used for {} only",
            t.realm, t.realm
        ),
        &t.anchors,
    )
}

/// Remove a trusted realm's files, the anchors file last.
fn remove_trust(paths: &Paths, realm: &str) -> Result<(), Error> {
    let dir = paths.trust_dir(realm);
    for p in [
        paths.trust_krb5_conf(realm),
        dir.join("pkinit-anchors.pem"),
        dir.join("ca.crt"),
    ] {
        paths::remove(&p)?;
    }
    let _ = fs::remove_dir(&dir);
    paths::remove(&paths.trust_anchors(realm))
}

/// `kuipa trusted-realms`: make this host's trusted realms match what its
/// own realm advertises (§17).  For each listed realm, fetch that realm's
/// advertisement, verify it with the anchors the own realm vouches for, and
/// install its anchors, PKINIT anchors, CA and `krb5.conf.d` snippet, all
/// for that realm only.  Realms no longer listed are removed.  A realm that
/// cannot be verified keeps its last verified files.
///
/// # Errors
///
/// [`Outcome::RetryLater`] if no own server verifies, or if a listed realm
/// could not be refreshed (after applying everything else); I/O errors.
pub fn trusted_realms(paths: &Paths) -> Result<Value, Error> {
    let state = State::load(paths)?;
    let anchors = paths::read_anchors(paths)?;
    let trust = ca_trust(paths)?;
    let mut skipped = Vec::new();
    let own = state
        .servers
        .iter()
        .find_map(
            |s| match verified(s, &trust, &state.realm, &anchors, None) {
                Ok((_, v, _)) => Some(v),
                Err(e) => {
                    skipped.push(format!("{s}: {e}"));
                    None
                }
            },
        )
        .ok_or_else(|| {
            Outcome::RetryLater(format!(
                "no usable server of {}: {}",
                state.realm,
                skipped.join("; ")
            ))
        })?;
    let listed = own.info().trusts.clone();
    tracing::debug!(
        "{} lists trusted realms {:?}; installed here: {:?}",
        state.realm,
        listed.iter().map(|t| t.realm.as_str()).collect::<Vec<_>>(),
        paths.trusted_realms()
    );
    let mut realms = Vec::new();
    let mut failed = Vec::new();
    for t in &listed {
        let installed = paths.trust_anchors(&t.realm).exists();
        let mut errors = Vec::new();
        if t.anchors.iter().any(|a| anchors.contains(a)) {
            errors.push("shares an anchor with this host's realm".to_owned());
        }
        let adv = if errors.is_empty() {
            t.servers.iter().find_map(|s| {
                match verified(s, &Trust::FirstContact, &t.realm, &t.anchors, None) {
                    Ok((_, v, _)) => Some(v),
                    Err(e) => {
                        errors.push(format!("{s}: {e}"));
                        None
                    }
                }
            })
        } else {
            None
        };
        if let Some(adv) = adv {
            tracing::debug!(
                "installing {}: {} PKINIT anchor(s), {} CA certificate(s), KDCs {:?}",
                t.realm,
                adv.info().pkinit_anchors.len(),
                adv.info().ca_certs.len(),
                adv.info().servers
            );
            install_trust(paths, &state.realm, t, &adv)?;
            realms.push(json!({
                "realm": t.realm,
                "status": if installed { "refreshed" } else { "installed" },
                "server": adv.server(),
                "krb5_conf": paths.trust_krb5_conf(&t.realm),
            }));
        } else {
            failed.push(format!("{}: {}", t.realm, errors.join("; ")));
            realms.push(json!({
                "realm": t.realm,
                "status": if installed { "kept" } else { "not installed" },
                "error": errors.join("; "),
            }));
        }
    }
    for realm in paths.trusted_realms() {
        if !listed.iter().any(|t| t.realm == realm) {
            remove_trust(paths, &realm)?;
            realms.push(json!({ "realm": realm, "status": "removed" }));
        }
    }
    if failed.is_empty() {
        Ok(json!({ "realm": state.realm, "trusted_realms": realms }))
    } else {
        Err(Outcome::RetryLater(format!(
            "trusted realms not refreshed (their last verified files are kept): {}",
            failed.join("; ")
        ))
        .into())
    }
}

/// `kuipa leave`: remove what kuipa installed besides the keytab
/// (`ipa-client-install --uninstall` unenrolls and removes that).
///
/// # Errors
///
/// I/O errors.
pub fn leave(paths: &Paths) -> Result<Value, Error> {
    if let Ok(state) = State::load(paths)
        && state.holder == Holder::File
    {
        // Leave a plain keytab behind for `ipa-join --unenroll`.
        if let Ok(b) = fs::read(paths.run_keytab()) {
            paths::write_file(&paths.keytab(), &b, 0o600)?;
        }
    }
    // Other protected keytabs and files go back in place too; their
    // bindings stay registered until the entries go or are cleared.
    if let Ok(state) = State::load(paths) {
        for item in &state.protected {
            let copy = paths.run_copy(&item.path);
            if let Ok(b) = fs::read(&copy) {
                paths::write_file(&item.path, &b, item.mode)?;
                std::os::unix::fs::chown(&item.path, Some(item.uid), Some(item.gid))?;
            }
            paths::remove(&paths::sealed_for(&item.path))?;
            paths::remove(&copy)?;
        }
    }
    for realm in paths.trusted_realms() {
        remove_trust(paths, &realm)?;
    }
    for p in [
        paths.krb5_conf(),
        paths.pkinit_anchors(),
        paths.sealed(),
        paths.run_keytab(),
        paths.anchors(),
        paths.recipient(),
        paths.recipient_public(),
        paths.pending(),
        paths.state(),
        paths.public_state(),
    ] {
        paths::remove(&p)?;
    }
    Ok(json!({ "left": true }))
}
