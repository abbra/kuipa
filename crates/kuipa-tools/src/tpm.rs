//! The TPM factor (§7.1): secrets kept as `systemd-creds` credentials, so
//! that they open only on this host's TPM.  The credential's name is
//! embedded and checked at decryption.

use std::io::Write;
use std::process::{Command, Stdio};

use kuipa_enroll::escrow::TpmShare;
use native_ossl::rand::Rand;
use native_ossl::util::SecretBuf;

use crate::paths::Error;

/// Credential name of a sealed object's TPM share.
pub(crate) const SHARE: &str = "kuipa-share";
/// Credential name of the offline-enrollment machine key.
pub(crate) const RECIPIENT: &str = "kuipa-recipient";
/// Credential name of a user seal's TPM device key.
pub(crate) const DEVICE: &str = "kuipa-device";

/// Whose TPM key wraps the credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The host's: `systemd-creds` with the TPM and optionally PCRs.  Root.
    System,
    /// The invoking user's, through systemd's per-user credential service.
    User,
}

/// Run `systemd-creds` with `args`, `input` on its stdin.
fn creds(scope: Scope, verb: &str, args: &[String], input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut cmd = Command::new("systemd-creds");
    if scope == Scope::User {
        cmd.arg("--user");
    }
    let mut child = cmd
        .arg(verb)
        .args(args)
        .args(["-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                "systemd-creds not found: the TPM factor needs systemd's systemd-creds".to_owned()
            }
            _ => format!("systemd-creds {verb}: {e}"),
        })?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    // A failing child may close its stdin first; its exit status says why.
    let _ = stdin.write_all(input);
    drop(stdin);
    let out = child
        .wait_with_output()
        .map_err(|e| format!("systemd-creds {verb}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemd-creds {verb}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(out.stdout)
}

/// Keep `plain` as a credential named `name`.  `pcrs` is the PCR list for
/// [`Scope::System`] (empty: none) and must be empty for [`Scope::User`].
///
/// # Errors
///
/// No usable TPM 2.0, no `systemd-creds`, or its failure.
pub(crate) fn encrypt(scope: Scope, name: &str, pcrs: &str, plain: &[u8]) -> Result<Vec<u8>, Error> {
    let args = match scope {
        // `tpm2` alone: a host without a TPM must fail, not fall back to
        // the host key.
        Scope::System => vec![
            "--with-key=tpm2".to_owned(),
            format!("--name={name}"),
            format!("--tpm2-pcrs={pcrs}"),
        ],
        Scope::User => {
            debug_assert_eq!(pcrs, "");
            // The user scope picks its own key and would fall back to the
            // host key alone.
            let has = Command::new("systemd-analyze")
                .arg("has-tpm2")
                .output()
                .map_err(|e| format!("systemd-analyze has-tpm2: {e}"))?;
            if !has.status.success() {
                let first = String::from_utf8_lossy(&has.stdout);
                return Err(format!(
                    "this host has no usable TPM 2.0 (systemd-analyze has-tpm2: {})",
                    first.lines().next().unwrap_or("")
                )
                .into());
            }
            vec![format!("--name={name}")]
        }
    };
    creds(scope, "encrypt", &args, plain)
}

/// Open a credential [`encrypt`] made.
///
/// # Errors
///
/// A different TPM, scope or name, no `systemd-creds`, or its failure.
pub(crate) fn decrypt(scope: Scope, name: &str, credential: &[u8]) -> Result<SecretBuf, Error> {
    let args = [format!("--name={name}"), "--newline=no".to_owned()];
    Ok(SecretBuf::from_slice(&creds(
        scope, "decrypt", &args, credential,
    )?))
}

/// A fresh 32-byte share and its TPM-bound copy, bound to `pcrs`.
///
/// # Errors
///
/// As for [`encrypt`].
pub(crate) fn new_share(pcrs: &str) -> Result<(SecretBuf, TpmShare), Error> {
    let mut share = SecretBuf::with_len(32);
    Rand::fill_private(share.as_mut_slice())?;
    let credential = encrypt(Scope::System, SHARE, pcrs, share.as_ref())?.into();
    Ok((
        share,
        TpmShare {
            pcrs: pcrs.to_owned(),
            credential,
        },
    ))
}

/// The share of `t`, as this host's TPM opens it.
///
/// # Errors
///
/// As for [`decrypt`].
pub(crate) fn open_share(t: &TpmShare) -> Result<SecretBuf, Error> {
    decrypt(Scope::System, SHARE, &t.credential)
}
