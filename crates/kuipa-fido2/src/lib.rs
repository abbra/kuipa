//! libfido2 bindings for kuipa's passkeys (DESIGN.md §7.6.5): the client
//! talks to the authenticator at the CTAP level, as SSSD's `passkey_child`
//! does, so the challenge is a raw `clientDataHash` and there is no
//! `clientDataJSON`.
//!
//! Only what kuipa needs is bound: listing authenticators, assertions
//! (with `hmac-secret` for passkey-wrapped device keys) and credentials.
//! The algorithms are whatever the installed libfido2 supports: ES256,
//! ES384, EdDSA, RS256, and ML-DSA-44/65/87 when it is built with ML-DSA.
//!
//! ```rust,no_run
//! use kuipa_fido2::{AssertionRequest, Device};
//!
//! for info in kuipa_fido2::devices()? {
//!     let dev = Device::open(&info.path)?;
//!     let a = dev.get_assertion(
//!         &AssertionRequest {
//!             rp_id: "example.test",
//!             client_data_hash: &[0; 32],
//!             allow: &[],
//!             user_verification: true,
//!             hmac_salt: None,
//!         },
//!         Some("1234"),
//!     )?;
//!     println!("{} bytes of signature", a.signature.len());
//! }
//! # Ok::<(), kuipa_fido2::Error>(())
//! ```

use std::ffi::{CStr, CString, c_char, c_int, c_uchar};
use std::sync::Once;

use native_ossl::util::SecretBuf;

/// COSE algorithm identifiers, as `fido/param.h` names them.
pub mod cose {
    /// ECDSA with P-256 and SHA-256.
    pub const ES256: i32 = -7;
    /// Ed25519.
    pub const EDDSA: i32 = -8;
    /// ECDSA with P-384 and SHA-384.
    pub const ES384: i32 = -35;
    /// ML-DSA-44 (FIPS 204).
    pub const MLDSA44: i32 = -48;
    /// ML-DSA-65 (FIPS 204).
    pub const MLDSA65: i32 = -49;
    /// ML-DSA-87 (FIPS 204).
    pub const MLDSA87: i32 = -50;
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    pub const RS256: i32 = -257;
}

#[allow(non_camel_case_types)]
mod ffi {
    use std::ffi::{c_char, c_int, c_uchar};

    pub enum fido_dev_t {}
    pub enum fido_dev_info_t {}
    pub enum fido_assert_t {}
    pub enum fido_cred_t {}

    pub const FIDO_OK: c_int = 0;
    pub const FIDO_ERR_UNSUPPORTED_ALGORITHM: c_int = 0x26;
    pub const FIDO_ERR_NO_CREDENTIALS: c_int = 0x2e;
    pub const FIDO_ERR_PIN_INVALID: c_int = 0x31;
    pub const FIDO_ERR_PIN_BLOCKED: c_int = 0x32;
    pub const FIDO_ERR_PIN_REQUIRED: c_int = 0x36;
    /// libfido2's own: what `fido_cred_set_type` answers for an algorithm
    /// it was built without.
    pub const FIDO_ERR_INVALID_ARGUMENT: c_int = -7;
    pub const FIDO_EXT_HMAC_SECRET: c_int = 0x01;
    /// `fido_opt_t`.
    pub const FIDO_OPT_OMIT: c_int = 0;
    pub const FIDO_OPT_TRUE: c_int = 2;

    #[link(name = "fido2")]
    unsafe extern "C" {
        pub fn fido_init(flags: c_int);
        pub fn fido_strerr(code: c_int) -> *const c_char;

        pub fn fido_dev_info_new(n: usize) -> *mut fido_dev_info_t;
        pub fn fido_dev_info_free(list: *mut *mut fido_dev_info_t, n: usize);
        pub fn fido_dev_info_manifest(
            list: *mut fido_dev_info_t,
            ilen: usize,
            olen: *mut usize,
        ) -> c_int;
        pub fn fido_dev_info_ptr(list: *const fido_dev_info_t, i: usize) -> *const fido_dev_info_t;
        pub fn fido_dev_info_path(di: *const fido_dev_info_t) -> *const c_char;
        pub fn fido_dev_info_manufacturer_string(di: *const fido_dev_info_t) -> *const c_char;
        pub fn fido_dev_info_product_string(di: *const fido_dev_info_t) -> *const c_char;

        pub fn fido_dev_new() -> *mut fido_dev_t;
        pub fn fido_dev_free(dev: *mut *mut fido_dev_t);
        pub fn fido_dev_open(dev: *mut fido_dev_t, path: *const c_char) -> c_int;
        pub fn fido_dev_close(dev: *mut fido_dev_t) -> c_int;
        pub fn fido_dev_has_pin(dev: *const fido_dev_t) -> bool;
        pub fn fido_dev_get_assert(
            dev: *mut fido_dev_t,
            assert: *mut fido_assert_t,
            pin: *const c_char,
        ) -> c_int;
        pub fn fido_dev_make_cred(
            dev: *mut fido_dev_t,
            cred: *mut fido_cred_t,
            pin: *const c_char,
        ) -> c_int;

        pub fn fido_assert_new() -> *mut fido_assert_t;
        pub fn fido_assert_free(assert: *mut *mut fido_assert_t);
        pub fn fido_assert_set_rp(assert: *mut fido_assert_t, id: *const c_char) -> c_int;
        pub fn fido_assert_set_clientdata_hash(
            assert: *mut fido_assert_t,
            ptr: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub fn fido_assert_allow_cred(
            assert: *mut fido_assert_t,
            ptr: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub fn fido_assert_set_uv(assert: *mut fido_assert_t, uv: c_int) -> c_int;
        pub fn fido_assert_set_extensions(assert: *mut fido_assert_t, ext: c_int) -> c_int;
        pub fn fido_assert_set_hmac_salt(
            assert: *mut fido_assert_t,
            ptr: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub fn fido_assert_count(assert: *const fido_assert_t) -> usize;
        pub fn fido_assert_id_ptr(assert: *const fido_assert_t, i: usize) -> *const c_uchar;
        pub fn fido_assert_id_len(assert: *const fido_assert_t, i: usize) -> usize;
        pub fn fido_assert_authdata_raw_ptr(
            assert: *const fido_assert_t,
            i: usize,
        ) -> *const c_uchar;
        pub fn fido_assert_authdata_raw_len(assert: *const fido_assert_t, i: usize) -> usize;
        pub fn fido_assert_sig_ptr(assert: *const fido_assert_t, i: usize) -> *const c_uchar;
        pub fn fido_assert_sig_len(assert: *const fido_assert_t, i: usize) -> usize;
        pub fn fido_assert_hmac_secret_ptr(
            assert: *const fido_assert_t,
            i: usize,
        ) -> *const c_uchar;
        pub fn fido_assert_hmac_secret_len(assert: *const fido_assert_t, i: usize) -> usize;

        pub fn fido_cred_new() -> *mut fido_cred_t;
        pub fn fido_cred_free(cred: *mut *mut fido_cred_t);
        pub fn fido_cred_set_type(cred: *mut fido_cred_t, cose_alg: c_int) -> c_int;
        pub fn fido_cred_set_clientdata_hash(
            cred: *mut fido_cred_t,
            ptr: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub fn fido_cred_set_rp(
            cred: *mut fido_cred_t,
            id: *const c_char,
            name: *const c_char,
        ) -> c_int;
        pub fn fido_cred_set_user(
            cred: *mut fido_cred_t,
            user_id: *const c_uchar,
            user_id_len: usize,
            name: *const c_char,
            display_name: *const c_char,
            icon: *const c_char,
        ) -> c_int;
        pub fn fido_cred_set_extensions(cred: *mut fido_cred_t, ext: c_int) -> c_int;
        pub fn fido_cred_set_rk(cred: *mut fido_cred_t, rk: c_int) -> c_int;
        pub fn fido_cred_id_ptr(cred: *const fido_cred_t) -> *const c_uchar;
        pub fn fido_cred_id_len(cred: *const fido_cred_t) -> usize;
        pub fn fido_cred_type(cred: *const fido_cred_t) -> c_int;
    }
}

/// Errors from libfido2 or from the arguments given to it.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A libfido2 or CTAP error: its code and libfido2's description.
    #[error("{what}: {message}")]
    Fido {
        /// What was being done.
        what: &'static str,
        /// The `FIDO_ERR_*` code.
        code: i32,
        /// `fido_strerr`.
        message: String,
    },
    /// A string argument holds a NUL byte.
    #[error("a FIDO2 argument holds a NUL byte")]
    Nul(#[from] std::ffi::NulError),
    /// The authenticator answered without what was asked for.
    #[error("the authenticator did not return {0}")]
    Missing(&'static str),
}

impl Error {
    /// The `FIDO_ERR_*` code, for a libfido2 error.
    #[must_use]
    pub fn code(&self) -> Option<i32> {
        match self {
            Self::Fido { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// The authenticator holds none of the allowed credentials.
    #[must_use]
    pub fn is_no_credentials(&self) -> bool {
        self.code() == Some(ffi::FIDO_ERR_NO_CREDENTIALS)
    }

    /// The PIN is needed, or the one given is wrong or blocked.
    #[must_use]
    pub fn is_pin(&self) -> bool {
        matches!(
            self.code(),
            Some(
                ffi::FIDO_ERR_PIN_REQUIRED | ffi::FIDO_ERR_PIN_INVALID | ffi::FIDO_ERR_PIN_BLOCKED
            )
        )
    }
}

/// Convenience alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

fn init() {
    static INIT: Once = Once::new();
    // SAFETY: fido_init only sets library-global flags; once.
    INIT.call_once(|| unsafe { ffi::fido_init(0) });
}

fn check(what: &'static str, code: c_int) -> Result<()> {
    if code == ffi::FIDO_OK {
        return Ok(());
    }
    // SAFETY: fido_strerr returns a static string for any code.
    let message = unsafe { CStr::from_ptr(ffi::fido_strerr(code)) }
        .to_string_lossy()
        .into_owned();
    Err(Error::Fido {
        what,
        code,
        message,
    })
}

/// Copy `len` bytes at `ptr`, which libfido2 owns.
///
/// # Safety
///
/// `ptr` is null or points at `len` readable bytes.
unsafe fn copy_out(ptr: *const c_uchar, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: the caller's contract.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

/// A string libfido2 owns, if any.
///
/// # Safety
///
/// `ptr` is null or a NUL-terminated string.
unsafe fn string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn pin_ptr(pin: Option<&CString>) -> *const c_char {
    pin.map_or(std::ptr::null(), |p| p.as_ptr())
}

/// An authenticator attached to the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Its path, for [`Device::open`].
    pub path: String,
    /// The manufacturer, as it reports itself.
    pub manufacturer: String,
    /// The product, as it reports itself.
    pub product: String,
}

/// The authenticators attached to the host, at most 64.
///
/// # Errors
///
/// A libfido2 error.
pub fn devices() -> Result<Vec<DeviceInfo>> {
    const MAX: usize = 64;
    init();
    // SAFETY: a list of MAX entries, freed below with the same size.
    let mut list = unsafe { ffi::fido_dev_info_new(MAX) };
    if list.is_null() {
        return Err(Error::Missing("a device list"));
    }
    let mut found = 0usize;
    // SAFETY: `list` holds MAX entries; `found` is written.
    let rc = unsafe { ffi::fido_dev_info_manifest(list, MAX, &raw mut found) };
    let result = check("list FIDO2 devices", rc).map(|()| {
        (0..found.min(MAX))
            .map(|i| {
                // SAFETY: i < found ≤ MAX entries; the strings live with the list.
                unsafe {
                    let di = ffi::fido_dev_info_ptr(list, i);
                    DeviceInfo {
                        path: string(ffi::fido_dev_info_path(di)),
                        manufacturer: string(ffi::fido_dev_info_manufacturer_string(di)),
                        product: string(ffi::fido_dev_info_product_string(di)),
                    }
                }
            })
            .collect()
    });
    // SAFETY: allocated above with MAX entries.
    unsafe { ffi::fido_dev_info_free(&raw mut list, MAX) };
    result
}

/// What to ask an authenticator to sign.
#[derive(Clone, Copy, Debug)]
pub struct AssertionRequest<'a> {
    /// The relying party ID.
    pub rp_id: &'a str,
    /// The challenge, as CTAP's `clientDataHash`.
    pub client_data_hash: &'a [u8; 32],
    /// The credentials allowed to answer; empty for discoverable ones.
    pub allow: &'a [Vec<u8>],
    /// Require user verification (a PIN, or built-in verification).
    pub user_verification: bool,
    /// Ask for the `hmac-secret` output for this salt.
    pub hmac_salt: Option<&'a [u8; 32]>,
}

/// An authenticator's assertion.
pub struct Assertion {
    /// The credential that signed.
    pub credential_id: Vec<u8>,
    /// The raw authenticator data.
    pub authenticator_data: Vec<u8>,
    /// The signature over `authenticator_data ‖ client_data_hash`.
    pub signature: Vec<u8>,
    /// The `hmac-secret` output, when a salt was given.
    pub hmac_secret: Option<SecretBuf>,
}

impl std::fmt::Debug for Assertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Assertion")
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

/// What credential to make.
#[derive(Clone, Copy, Debug)]
pub struct CredentialRequest<'a> {
    /// The relying party ID.
    pub rp_id: &'a str,
    /// The relying party's name, for the authenticator's display.
    pub rp_name: &'a str,
    /// The user handle.
    pub user_id: &'a [u8],
    /// The user's name.
    pub user_name: &'a str,
    /// COSE algorithms to try, in order ([`cose`]).
    pub algorithms: &'a [i32],
    /// Enable the `hmac-secret` extension.
    pub hmac_secret: bool,
}

/// A credential the authenticator made (not discoverable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    /// Its ID.
    pub id: Vec<u8>,
    /// Its COSE algorithm.
    pub alg: i32,
}

/// An open authenticator.
pub struct Device {
    dev: *mut ffi::fido_dev_t,
}

impl Device {
    /// Open the authenticator at `path` ([`devices`]).
    ///
    /// # Errors
    ///
    /// A libfido2 error.
    pub fn open(path: &str) -> Result<Self> {
        init();
        let path = CString::new(path)?;
        // SAFETY: freed in Drop (or below on failure).
        let mut dev = unsafe { ffi::fido_dev_new() };
        if dev.is_null() {
            return Err(Error::Missing("a device handle"));
        }
        // SAFETY: `dev` is a fresh handle, `path` a C string.
        if let Err(e) = check("open the FIDO2 device", unsafe {
            ffi::fido_dev_open(dev, path.as_ptr())
        }) {
            // SAFETY: allocated above, never opened.
            unsafe { ffi::fido_dev_free(&raw mut dev) };
            return Err(e);
        }
        Ok(Self { dev })
    }

    /// Whether a PIN is set on the authenticator.
    #[must_use]
    pub fn has_pin(&self) -> bool {
        // SAFETY: an open handle.
        unsafe { ffi::fido_dev_has_pin(self.dev) }
    }

    /// Get an assertion (`authenticatorGetAssertion`): waits for a touch.
    /// With `pin`, the PIN verifies the user.
    ///
    /// # Errors
    ///
    /// A libfido2 error ([`Error::is_no_credentials`] when the
    /// authenticator holds none of the allowed credentials,
    /// [`Error::is_pin`] for PIN trouble), or a NUL byte in an argument.
    pub fn get_assertion(
        &self,
        req: &AssertionRequest<'_>,
        pin: Option<&str>,
    ) -> Result<Assertion> {
        let rp = CString::new(req.rp_id)?;
        let pin = pin.map(CString::new).transpose()?;
        let assert = AssertHandle::new()?;
        let a = assert.0;
        // SAFETY: `a` is a fresh assertion; every buffer outlives the call
        // that copies it.
        unsafe {
            check(
                "set the relying party",
                ffi::fido_assert_set_rp(a, rp.as_ptr()),
            )?;
            check(
                "set the challenge",
                ffi::fido_assert_set_clientdata_hash(a, req.client_data_hash.as_ptr(), 32),
            )?;
            for id in req.allow {
                check(
                    "allow a credential",
                    ffi::fido_assert_allow_cred(a, id.as_ptr(), id.len()),
                )?;
            }
            // A PIN verifies the user itself; without one, ask for the
            // authenticator's own verification.
            let uv = if req.user_verification && pin.is_none() {
                ffi::FIDO_OPT_TRUE
            } else {
                ffi::FIDO_OPT_OMIT
            };
            check("ask for user verification", ffi::fido_assert_set_uv(a, uv))?;
            if let Some(salt) = req.hmac_salt {
                check(
                    "ask for hmac-secret",
                    ffi::fido_assert_set_extensions(a, ffi::FIDO_EXT_HMAC_SECRET),
                )?;
                check(
                    "set the hmac-secret salt",
                    ffi::fido_assert_set_hmac_salt(a, salt.as_ptr(), salt.len()),
                )?;
            }
            check(
                "get an assertion",
                ffi::fido_dev_get_assert(self.dev, a, pin_ptr(pin.as_ref())),
            )?;
            if ffi::fido_assert_count(a) == 0 {
                return Err(Error::Missing("an assertion"));
            }
            let hmac_secret = if req.hmac_salt.is_some() {
                let secret = copy_out(
                    ffi::fido_assert_hmac_secret_ptr(a, 0),
                    ffi::fido_assert_hmac_secret_len(a, 0),
                )
                .ok_or(Error::Missing("the hmac-secret output"))?;
                Some(SecretBuf::new(secret))
            } else {
                None
            };
            Ok(Assertion {
                // A single allowed credential may be left out of the answer.
                credential_id: copy_out(
                    ffi::fido_assert_id_ptr(a, 0),
                    ffi::fido_assert_id_len(a, 0),
                )
                .or_else(|| match req.allow {
                    [only] => Some(only.clone()),
                    _ => None,
                })
                .ok_or(Error::Missing("the credential ID"))?,
                authenticator_data: copy_out(
                    ffi::fido_assert_authdata_raw_ptr(a, 0),
                    ffi::fido_assert_authdata_raw_len(a, 0),
                )
                .ok_or(Error::Missing("the authenticator data"))?,
                signature: copy_out(
                    ffi::fido_assert_sig_ptr(a, 0),
                    ffi::fido_assert_sig_len(a, 0),
                )
                .ok_or(Error::Missing("the signature"))?,
                hmac_secret,
            })
        }
    }

    /// Make a credential (`authenticatorMakeCredential`), trying
    /// `req.algorithms` in turn until the authenticator supports one:
    /// waits for a touch.  The credential is not discoverable; its
    /// attestation is not kept.
    ///
    /// # Errors
    ///
    /// A libfido2 error, the last algorithm's when none is supported.
    pub fn make_credential(
        &self,
        req: &CredentialRequest<'_>,
        pin: Option<&str>,
    ) -> Result<Credential> {
        let rp = CString::new(req.rp_id)?;
        let rp_name = CString::new(req.rp_name)?;
        let user = CString::new(req.user_name)?;
        let pin = pin.map(CString::new).transpose()?;
        let mut cdh = [0u8; 32];
        native_ossl::rand::Rand::fill(&mut cdh).map_err(|_| Error::Missing("randomness"))?;
        let mut last = Error::Missing("an algorithm to try");
        for &alg in req.algorithms {
            let cred = CredHandle::new()?;
            let c = cred.0;
            // SAFETY: `c` is a fresh credential; every buffer outlives the
            // call that copies it.
            let made = unsafe {
                check("set the algorithm", ffi::fido_cred_set_type(c, alg))
                    .and_then(|()| {
                        check(
                            "set the challenge",
                            ffi::fido_cred_set_clientdata_hash(c, cdh.as_ptr(), cdh.len()),
                        )
                    })
                    .and_then(|()| {
                        check(
                            "set the relying party",
                            ffi::fido_cred_set_rp(c, rp.as_ptr(), rp_name.as_ptr()),
                        )
                    })
                    .and_then(|()| {
                        check(
                            "set the user",
                            ffi::fido_cred_set_user(
                                c,
                                req.user_id.as_ptr(),
                                req.user_id.len(),
                                user.as_ptr(),
                                user.as_ptr(),
                                std::ptr::null(),
                            ),
                        )
                    })
                    .and_then(|()| {
                        check(
                            "make it non-discoverable",
                            ffi::fido_cred_set_rk(c, ffi::FIDO_OPT_OMIT),
                        )
                    })
                    .and_then(|()| {
                        if req.hmac_secret {
                            check(
                                "ask for hmac-secret",
                                ffi::fido_cred_set_extensions(c, ffi::FIDO_EXT_HMAC_SECRET),
                            )
                        } else {
                            Ok(())
                        }
                    })
                    .and_then(|()| {
                        check(
                            "make a credential",
                            ffi::fido_dev_make_cred(self.dev, c, pin_ptr(pin.as_ref())),
                        )
                    })
            };
            match made {
                Ok(()) => {
                    // SAFETY: a credential the device just made.
                    let id =
                        unsafe { copy_out(ffi::fido_cred_id_ptr(c), ffi::fido_cred_id_len(c)) }
                            .ok_or(Error::Missing("the credential ID"))?;
                    // SAFETY: as above.
                    let alg = unsafe { ffi::fido_cred_type(c) };
                    return Ok(Credential { id, alg });
                }
                // An algorithm this libfido2 or this authenticator lacks:
                // the next one.  Nothing was asked of the user yet.
                Err(e)
                    if matches!(
                        e.code(),
                        Some(ffi::FIDO_ERR_UNSUPPORTED_ALGORITHM | ffi::FIDO_ERR_INVALID_ARGUMENT)
                    ) =>
                {
                    last = e;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: opened in `open`, closed and freed once.
        unsafe {
            ffi::fido_dev_close(self.dev);
            ffi::fido_dev_free(&raw mut self.dev);
        }
    }
}

// SAFETY: a libfido2 device handle is not tied to the thread that opened
// it; `&self` methods are not used concurrently (`Device` is not `Sync`).
unsafe impl Send for Device {}

struct AssertHandle(*mut ffi::fido_assert_t);

impl AssertHandle {
    fn new() -> Result<Self> {
        // SAFETY: freed in Drop.
        let a = unsafe { ffi::fido_assert_new() };
        if a.is_null() {
            Err(Error::Missing("an assertion handle"))
        } else {
            Ok(Self(a))
        }
    }
}

impl Drop for AssertHandle {
    fn drop(&mut self) {
        // SAFETY: allocated in `new`, freed once; it wipes the hmac-secret.
        unsafe { ffi::fido_assert_free(&raw mut self.0) };
    }
}

struct CredHandle(*mut ffi::fido_cred_t);

impl CredHandle {
    fn new() -> Result<Self> {
        // SAFETY: freed in Drop.
        let c = unsafe { ffi::fido_cred_new() };
        if c.is_null() {
            Err(Error::Missing("a credential handle"))
        } else {
            Ok(Self(c))
        }
    }
}

impl Drop for CredHandle {
    fn drop(&mut self) {
        // SAFETY: allocated in `new`, freed once.
        unsafe { ffi::fido_cred_free(&raw mut self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_libfido2_descriptions() {
        let err = check("get an assertion", ffi::FIDO_ERR_NO_CREDENTIALS).unwrap_err();
        assert!(err.is_no_credentials());
        assert!(!err.is_pin());
        assert!(err.to_string().starts_with("get an assertion: "), "{err}");
        assert!(check("x", ffi::FIDO_ERR_PIN_REQUIRED).unwrap_err().is_pin());
        assert!(check("x", ffi::FIDO_OK).is_ok());
    }

    #[test]
    fn listing_works_without_devices() {
        // Whatever is attached, listing must not fail.
        let found = devices().unwrap();
        assert!(found.len() <= 64);
    }

    #[test]
    fn a_missing_device_does_not_open() {
        assert!(Device::open("/nonexistent/hidraw").is_err());
        assert!(Device::open("bad\0path").is_err());
    }
}
