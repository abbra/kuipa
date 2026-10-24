//! `kuipa sign`: Kerberos-bound signing statements (`DESIGN-sign.md`).
//!
//! Signing runs as whoever holds the ticket — a user, or a CI runner
//! after `kinit -k` — and asks one of the realm's servers to state that
//! the ticket's principal signed the files' digests; each file gets a
//! `<file>.kusig` bundle.  Verifying is offline: the host's pinned
//! anchors and realm, nothing else.

use std::path::{Path, PathBuf};

use kuipa_enroll::join::{AuthType, Operation, Prepared};
use kuipa_enroll::keytab::Enctype;
use kuipa_enroll::realm::Deployment;
use kuipa_enroll::sign::{Bundle, Digest, DigestAlg, Request};
use kuipa_gssapi::GssClientCred;
use serde_json::{Value, json};

use crate::flows;
use crate::paths::{self, Error, Paths, PublicState};

/// The bundle file for `file`: `<file>.kusig`.
#[must_use]
pub fn bundle_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".kusig");
    PathBuf::from(name)
}

/// `kuipa sign blob`: one statement for `files` for `purpose`, by the
/// principal of the ticket in `ccache` (else the default ccache), and a
/// bundle beside each file.
///
/// # Errors
///
/// An unreadable file, a refusal (the realm's policy, no transparency
/// log), or any other error.
pub fn sign_files(
    host: &Paths,
    ccache: Option<&str>,
    purpose: &str,
    files: &[PathBuf],
) -> Result<Value, Error> {
    let mut digests = Vec::with_capacity(files.len());
    for f in files {
        let data = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
        digests.push(Digest::of(DigestAlg::Sha256, &data)?);
    }
    let asked = Request {
        purpose: purpose.to_owned(),
        digests,
    };
    let bundles = request(host, ccache, &asked)?;
    let mut written = Vec::new();
    for (file, bundle) in files.iter().zip(&bundles) {
        let out = bundle_path(file);
        paths::write_file(&out, &bundle.to_bytes(), 0o644)?;
        written.push(json!({ "file": file, "signature": out }));
    }
    let first = bundles.first().ok_or("the server answered no bundle")?;
    let public = PublicState::load(host)?;
    let v = first.verify(
        &std::fs::read(&files[0])?,
        &public.realm,
        &paths::read_anchors(host)?,
        &tang_pqc::Policy::from_system()?,
    )?;
    Ok(json!({
        "purpose": purpose,
        "principal": v.principal.to_string(),
        "server": v.server,
        "time": v.iat,
        "log": v.log.to_string(),
        "index": v.index,
        "signed": written,
    }))
}

/// Ask a server of the realm to state `asked`, and return the checked
/// bundles, in request order.
///
/// # Errors
///
/// A refusal or any other error.
pub fn request(host: &Paths, ccache: Option<&str>, asked: &Request) -> Result<Vec<Bundle>, Error> {
    let public = PublicState::load(host)?;
    let (anchors, heads, retired, frozen) = paths::pinned_windows(&host.anchors())?;
    let known = paths::read_epoch_from(&host.anchors())?;
    let trust = flows::ca_trust(host)?;
    let cred = match ccache {
        Some(name) => GssClientCred::from_named_ccache(name)?,
        None => GssClientCred::ambient()?,
    };
    let extra = asked.to_bytes()?;
    let (bundles, _) = flows::exchange_with(
        &Deployment::servers(&public.servers),
        &trust,
        &public.realm,
        &anchors,
        &heads,
        &retired,
        &frozen,
        known,
        Operation::Sign,
        |adv| {
            let p = Prepared::new(
                adv,
                Operation::Sign,
                &public.fqdn,
                AuthType::Kerberos,
                &Enctype::DEFAULT,
            )?;
            let target = format!("ipa-ku@{}", adv.server());
            let (token, binding) = flows::gss_token(&cred, &target, &p.channel_binding()?)?;
            Ok(p.with_kerberos(binding).seal(&token, &[], &extra)?)
        },
        |pending, response, adv| Ok(pending.finish_sign(response, adv, asked)?),
    )?;
    Ok(bundles)
}

/// `kuipa sign verify`: check `file` against its bundle (`signature`,
/// else `<file>.kusig`) offline, with this host's pinned anchors; and
/// when given, that the signer is `signer` and the purpose `purpose`.
/// `ok` is false for a mismatch of either.
///
/// # Errors
///
/// An unreadable file or bundle, or a bundle that does not verify.
pub fn verify_file(
    host: &Paths,
    file: &Path,
    signature: Option<&Path>,
    signer: Option<&str>,
    purpose: Option<&str>,
) -> Result<Value, Error> {
    let sig = signature.map_or_else(|| bundle_path(file), Path::to_path_buf);
    let bundle =
        Bundle::from_bytes(&std::fs::read(&sig).map_err(|e| format!("{}: {e}", sig.display()))?)?;
    let public = PublicState::load(host)?;
    let v = bundle.verify(
        &std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?,
        &public.realm,
        &paths::read_anchors(host)?,
        &tang_pqc::Policy::from_system()?,
    )?;
    let principal = v.principal.to_string();
    let signer_ok = signer.is_none_or(|s| principal == s || principal.split('@').next() == Some(s));
    let purpose_ok = purpose.is_none_or(|p| p == v.purpose);
    Ok(json!({
        "ok": signer_ok && purpose_ok,
        "file": file,
        "principal": principal,
        "purpose": v.purpose,
        "server": v.server,
        "time": v.iat,
        "log": v.log.to_string(),
        "index": v.index,
        "signer_matches": signer_ok,
        "purpose_matches": purpose_ok,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles_sit_beside_their_files() {
        assert_eq!(
            bundle_path(Path::new("/tmp/release-1.0.tar")),
            PathBuf::from("/tmp/release-1.0.tar.kusig")
        );
    }
}
