//! Device keys on PKCS#11 tokens (§7.6.2): an ML-KEM key generated on the
//! token (`CKM_ML_KEM`), never extractable, used through OpenSSL's
//! pkcs11-provider by its `pkcs11:` URI (RFC 7512).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kuipa_enroll::vault::DeviceKey;
use native_ossl::lib_ctx::{LibCtx, Provider};
use native_ossl::store::{Store, StoreObject};
use native_ossl::util::SecretBuf;
use tang_pqc::{ExchangeKey, ExchangeKeyPair, Thumbprint};

use crate::paths::Error;

/// Where Fedora and RHEL install OpenSSL's pkcs11-provider; overridden by
/// `$KUIPA_PKCS11_PROVIDER`.
const PROVIDER: &str = "/usr/lib64/ossl-modules/pkcs11.so";

/// The provider module to load.
fn provider_module() -> PathBuf {
    std::env::var_os("KUIPA_PKCS11_PROVIDER").map_or_else(|| PathBuf::from(PROVIDER), PathBuf::from)
}

/// An ML-KEM private key held by a token, with the OpenSSL context and
/// provider that reach it kept alive as long as it is.
pub struct TokenKey {
    pair: ExchangeKeyPair,
    _provider: Provider,
    _ctx: Arc<LibCtx>,
}

impl TokenKey {
    /// Open the key at `uri` through `module` (the token's PKCS#11
    /// library), logging in with `pin`.  The provider configuration is
    /// written to `scratch` (a private directory) and removed again.
    ///
    /// # Errors
    ///
    /// The provider, the token or the key cannot be reached, or the key is
    /// not ML-KEM-768 or ML-KEM-1024.
    pub fn open(module: &Path, uri: &str, pin: &[u8], scratch: &Path) -> Result<Self, Error> {
        let ctx = Arc::new(LibCtx::new()?);
        let conf = scratch.join(format!("pkcs11-{}.cnf", std::process::id()));
        std::fs::create_dir_all(scratch)?;
        crate::paths::write_file(
            &conf,
            format!(
                "openssl_conf = openssl_init\n\
                 [openssl_init]\n\
                 providers = provider_sect\n\
                 [provider_sect]\n\
                 default = default_sect\n\
                 pkcs11 = pkcs11_sect\n\
                 [default_sect]\n\
                 activate = 1\n\
                 [pkcs11_sect]\n\
                 module = {}\n\
                 pkcs11-module-path = {}\n\
                 activate = 1\n",
                provider_module().display(),
                module.display()
            )
            .as_bytes(),
            0o600,
        )?;
        let loaded = ctx.load_config(&conf);
        let _ = std::fs::remove_file(&conf);
        loaded?;
        let provider = ctx.load_provider(c"pkcs11")?;
        let pin = std::str::from_utf8(pin).map_err(|_| "the PIN is not UTF-8")?;
        let with_pin = format!(
            "{uri}{}pin-value={}",
            if uri.contains('?') { "&" } else { "?" },
            percent_encode(pin)
        );
        let mut store = Store::open_in(&ctx, &with_pin)?;
        let pkey = loop {
            match store.load()? {
                Some(StoreObject::Pkey(k)) => break k,
                Some(_) => {}
                None => return Err(format!("no private key at {uri}").into()),
            }
        };
        Ok(Self {
            pair: ExchangeKeyPair::from_pkey(pkey)?,
            _provider: provider,
            _ctx: ctx,
        })
    }

    /// The public key.
    #[must_use]
    pub fn public(&self) -> &ExchangeKey {
        self.pair.public()
    }
}

impl DeviceKey for TokenKey {
    fn id(&self) -> Thumbprint {
        *self.pair.public().kid()
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> kuipa_enroll::Result<SecretBuf> {
        Ok(self.pair.decapsulate(ciphertext)?)
    }
}

/// Percent-encode `s` for a PKCS#11 URI query value.
fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A kryoptic token with an ML-KEM-768 key, made with pkcs11-tool; `None`
    /// when the tools are not installed.
    fn token(dir: &Path) -> Option<PathBuf> {
        let module = PathBuf::from("/usr/lib64/pkcs11/libkryoptic_pkcs11.so");
        if !module.exists() || !Path::new(PROVIDER).exists() {
            return None;
        }
        std::fs::create_dir_all(dir).unwrap();
        let conf = dir.join("kryoptic.conf");
        std::fs::write(
            &conf,
            format!(
                "[[slots]]\nslot = 42\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n",
                dir.join("token.sql").display()
            ),
        )
        .unwrap();
        let tool = |args: &[&str]| {
            std::process::Command::new("pkcs11-tool")
                .env("KRYOPTIC_CONF", &conf)
                .arg("--module")
                .arg(&module)
                .args(args)
                .output()
                .ok()
                .filter(|o| o.status.success())
        };
        tool(&["--init-token", "--label", "kuipa", "--so-pin", "12345678"])?;
        tool(&[
            "--token-label",
            "kuipa",
            "--login",
            "--so-pin",
            "12345678",
            "--init-pin",
            "--pin",
            "1234",
        ])?;
        tool(&[
            "--token-label",
            "kuipa",
            "--login",
            "--pin",
            "1234",
            "--keypairgen",
            "--key-type",
            "ML-KEM-768",
            "--label",
            "dev",
            "--id",
            "01",
        ])?;
        // SAFETY: tests in this module run on their own; the variable only
        // points kryoptic at this token.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var("KRYOPTIC_CONF", &conf);
        }
        Some(module)
    }

    #[test]
    fn a_token_key_decapsulates_on_the_token() {
        let dir = std::env::temp_dir().join(format!("kuipa-p11-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let Some(module) = token(&dir) else {
            return;
        };
        // A wrong PIN, before anything logged in: the key's handle loads,
        // but the token refuses to use it.  (Once logged in, a token stays
        // logged in for the process; kuipa opens one key per run.)
        let wrong = TokenKey::open(&module, "pkcs11:token=kuipa;object=dev", b"9999", &dir);
        if let Ok(k) = wrong {
            let (ct, _) = k.public().encapsulate().unwrap();
            assert!(k.decapsulate(&ct).is_err(), "a wrong PIN decapsulated");
        }
        let key = TokenKey::open(&module, "pkcs11:token=kuipa;object=dev", b"1234", &dir).unwrap();
        let (ct, secret) = key.public().encapsulate().unwrap();
        assert_eq!(key.decapsulate(&ct).unwrap().as_ref(), secret.as_ref());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
