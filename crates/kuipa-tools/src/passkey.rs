//! Passkeys on this host (§7.6.5): the assertions of the passkey factor,
//! made over a request's challenge from one of the user's IPA passkeys,
//! and device keys wrapped by a passkey's `hmac-secret` output.
//!
//! kuipa talks to the authenticator through libfido2, as SSSD's
//! `passkey_child` does: classical passkeys (ES256, ES384, EdDSA, RS256)
//! and post-quantum ones (ML-DSA-44/65/87, with a libfido2 built with
//! ML-DSA) alike.

use std::io::IsTerminal;

#[cfg(feature = "soft-fido2")]
pub mod soft;

use kuipa_fido2::{Assertion, AssertionRequest, Credential, CredentialRequest, Device};

use crate::paths::Error;

/// The authenticators an assertion or a credential comes from: the FIDO2
/// keys attached to this host ([`Fido2`]), or a software one in tests.
pub trait Authenticator {
    /// An assertion from whichever authenticator holds one of
    /// `req.allow`, the user verified with `pin` when given.
    ///
    /// # Errors
    ///
    /// No authenticator, none holding the credential, a wrong PIN, or
    /// another FIDO2 error.
    fn assert(&self, req: &AssertionRequest<'_>, pin: Option<&str>) -> Result<Assertion, Error>;

    /// A new credential with `hmac-secret`, on the first authenticator.
    ///
    /// # Errors
    ///
    /// No authenticator, or a FIDO2 error.
    fn make_credential(
        &self,
        req: &CredentialRequest<'_>,
        pin: Option<&str>,
    ) -> Result<Credential, Error>;
}

/// The FIDO2 authenticators attached to this host.
pub struct Fido2;

/// The authenticator `kuipa` uses: the security keys attached to this
/// host, or, built with the `soft-fido2` feature, the software key kept in
/// the file `$KUIPA_SOFT_FIDO2` names (the playground's).
///
/// # Errors
///
/// `$KUIPA_SOFT_FIDO2` set in a build without the feature, or a file that
/// is not a software key.
pub fn from_env() -> Result<Box<dyn Authenticator>, Error> {
    match std::env::var_os("KUIPA_SOFT_FIDO2") {
        None => Ok(Box::new(Fido2)),
        #[cfg(feature = "soft-fido2")]
        Some(path) => Ok(Box::new(soft::SoftFido2::open(std::path::Path::new(&path))?)),
        #[cfg(not(feature = "soft-fido2"))]
        Some(_) => Err(
            "$KUIPA_SOFT_FIDO2 is set, but this kuipa was built without its software security key (the soft-fido2 feature)"
                .into(),
        ),
    }
}

/// Ask for a touch, where someone can see it.
fn touch() {
    if std::io::stderr().is_terminal() {
        eprintln!("Touch your security key.");
    }
}

fn attached() -> Result<Vec<kuipa_fido2::DeviceInfo>, Error> {
    let found = kuipa_fido2::devices()?;
    if found.is_empty() {
        return Err("no FIDO2 security key is attached".into());
    }
    Ok(found)
}

impl Authenticator for Fido2 {
    fn assert(&self, req: &AssertionRequest<'_>, pin: Option<&str>) -> Result<Assertion, Error> {
        let mut last = None;
        for info in attached()? {
            touch();
            match Device::open(&info.path).and_then(|d| d.get_assertion(req, pin)) {
                Ok(a) => return Ok(a),
                // Another key may hold it.
                Err(e) if e.is_no_credentials() => last = Some(e),
                Err(e) if e.is_pin() => {
                    return Err(format!("{}: {e} (give the key's PIN)", info.product).into());
                }
                Err(e) => return Err(format!("{}: {e}", info.product).into()),
            }
        }
        Err(match last {
            Some(e) => format!("no attached security key holds the passkey: {e}").into(),
            None => "no FIDO2 security key answered".into(),
        })
    }

    fn make_credential(
        &self,
        req: &CredentialRequest<'_>,
        pin: Option<&str>,
    ) -> Result<Credential, Error> {
        let info = attached()?.swap_remove(0);
        touch();
        Device::open(&info.path)
            .and_then(|d| d.make_credential(req, pin))
            .map_err(|e| format!("{}: {e}", info.product).into())
    }
}

/// The PIN in `secret`: none when empty.
///
/// # Errors
///
/// A PIN that is not UTF-8.
pub fn pin_of(secret: &[u8]) -> Result<Option<&str>, Error> {
    if secret.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        std::str::from_utf8(secret).map_err(|_| "the security key's PIN is not UTF-8")?,
    ))
}

/// Algorithms for a device's credential, the post-quantum ones first as
/// FreeIPA offers them: only its `hmac-secret` is used, so any will do.
pub const DEVICE_ALGORITHMS: &[i32] = &[
    kuipa_fido2::cose::MLDSA65,
    kuipa_fido2::cose::MLDSA44,
    kuipa_fido2::cose::MLDSA87,
    kuipa_fido2::cose::ES256,
    kuipa_fido2::cose::EDDSA,
    kuipa_fido2::cose::ES384,
    kuipa_fido2::cose::RS256,
];
