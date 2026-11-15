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

    pub(crate) enum fido_dev_t {}
    pub(crate) enum fido_dev_info_t {}
    pub(crate) enum fido_assert_t {}
    pub(crate) enum fido_cred_t {}

    pub(crate) const FIDO_OK: c_int = 0;
    pub(crate) const FIDO_ERR_UNSUPPORTED_ALGORITHM: c_int = 0x26;
    pub(crate) const FIDO_ERR_NO_CREDENTIALS: c_int = 0x2e;
    pub(crate) const FIDO_ERR_PIN_INVALID: c_int = 0x31;
    pub(crate) const FIDO_ERR_PIN_BLOCKED: c_int = 0x32;
    pub(crate) const FIDO_ERR_PIN_REQUIRED: c_int = 0x36;
    /// libfido2's own: what `fido_cred_set_type` answers for an algorithm
    /// it was built without.
    pub(crate) const FIDO_ERR_INVALID_ARGUMENT: c_int = -7;
    pub(crate) const FIDO_EXT_HMAC_SECRET: c_int = 0x01;
    /// `fido_opt_t`.
    pub(crate) const FIDO_OPT_OMIT: c_int = 0;
    pub(crate) const FIDO_OPT_TRUE: c_int = 2;

    #[link(name = "fido2")]
    unsafe extern "C" {
        pub(crate) safe fn fido_init(flags: c_int);
        pub(crate) safe fn fido_strerr(code: c_int) -> *const c_char;

        pub(crate) fn fido_dev_info_new(n: usize) -> *mut fido_dev_info_t;
        pub(crate) fn fido_dev_info_free(list: *mut *mut fido_dev_info_t, n: usize);
        pub(crate) fn fido_dev_info_manifest(
            list: *mut fido_dev_info_t,
            ilen: usize,
            olen: *mut usize,
        ) -> c_int;
        pub(crate) fn fido_dev_info_ptr(
            list: *const fido_dev_info_t,
            i: usize,
        ) -> *const fido_dev_info_t;
        pub(crate) fn fido_dev_info_path(di: *const fido_dev_info_t) -> *const c_char;
        pub(crate) fn fido_dev_info_manufacturer_string(
            di: *const fido_dev_info_t,
        ) -> *const c_char;
        pub(crate) fn fido_dev_info_product_string(di: *const fido_dev_info_t) -> *const c_char;

        pub(crate) safe fn fido_dev_new() -> *mut fido_dev_t;
        pub(crate) fn fido_dev_free(dev: *mut *mut fido_dev_t);
        pub(crate) fn fido_dev_open(dev: *mut fido_dev_t, path: *const c_char) -> c_int;
        pub(crate) fn fido_dev_close(dev: *mut fido_dev_t) -> c_int;
        pub(crate) fn fido_dev_get_assert(
            dev: *mut fido_dev_t,
            assert: *mut fido_assert_t,
            pin: *const c_char,
        ) -> c_int;
        pub(crate) fn fido_dev_make_cred(
            dev: *mut fido_dev_t,
            cred: *mut fido_cred_t,
            pin: *const c_char,
        ) -> c_int;

        pub(crate) safe fn fido_assert_new() -> *mut fido_assert_t;
        pub(crate) fn fido_assert_free(assert: *mut *mut fido_assert_t);
        pub(crate) fn fido_assert_set_rp(assert: *mut fido_assert_t, id: *const c_char) -> c_int;
        pub(crate) fn fido_assert_set_clientdata_hash(
            assert: *mut fido_assert_t,
            ptr: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub(crate) fn fido_assert_allow_cred(
            assert: *mut fido_assert_t,
            ptr: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub(crate) fn fido_assert_set_uv(assert: *mut fido_assert_t, uv: c_int) -> c_int;
        pub(crate) fn fido_assert_set_extensions(assert: *mut fido_assert_t, ext: c_int) -> c_int;
        pub(crate) fn fido_assert_set_hmac_salt(
            assert: *mut fido_assert_t,
            ptr: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub(crate) fn fido_assert_count(assert: *const fido_assert_t) -> usize;
        pub(crate) fn fido_assert_id_ptr(assert: *const fido_assert_t, i: usize) -> *const c_uchar;
        pub(crate) fn fido_assert_id_len(assert: *const fido_assert_t, i: usize) -> usize;
        pub(crate) fn fido_assert_authdata_raw_ptr(
            assert: *const fido_assert_t,
            i: usize,
        ) -> *const c_uchar;
        pub(crate) fn fido_assert_authdata_raw_len(assert: *const fido_assert_t, i: usize)
        -> usize;
        pub(crate) fn fido_assert_sig_ptr(assert: *const fido_assert_t, i: usize)
        -> *const c_uchar;
        pub(crate) fn fido_assert_sig_len(assert: *const fido_assert_t, i: usize) -> usize;
        pub(crate) fn fido_assert_hmac_secret_ptr(
            assert: *const fido_assert_t,
            i: usize,
        ) -> *const c_uchar;
        pub(crate) fn fido_assert_hmac_secret_len(assert: *const fido_assert_t, i: usize) -> usize;

        pub(crate) safe fn fido_cred_new() -> *mut fido_cred_t;
        pub(crate) fn fido_cred_free(cred: *mut *mut fido_cred_t);
        pub(crate) fn fido_cred_set_type(cred: *mut fido_cred_t, cose_alg: c_int) -> c_int;
        pub(crate) fn fido_cred_set_clientdata_hash(
            cred: *mut fido_cred_t,
            ptr: *const c_uchar,
            len: usize,
        ) -> c_int;
        pub(crate) fn fido_cred_set_rp(
            cred: *mut fido_cred_t,
            id: *const c_char,
            name: *const c_char,
        ) -> c_int;
        pub(crate) fn fido_cred_set_user(
            cred: *mut fido_cred_t,
            user_id: *const c_uchar,
            user_id_len: usize,
            name: *const c_char,
            display_name: *const c_char,
            icon: *const c_char,
        ) -> c_int;
        pub(crate) fn fido_cred_set_extensions(cred: *mut fido_cred_t, ext: c_int) -> c_int;
        pub(crate) fn fido_cred_set_rk(cred: *mut fido_cred_t, rk: c_int) -> c_int;
        pub(crate) fn fido_cred_id_ptr(cred: *const fido_cred_t) -> *const c_uchar;
        pub(crate) fn fido_cred_id_len(cred: *const fido_cred_t) -> usize;
        pub(crate) fn fido_cred_type(cred: *const fido_cred_t) -> c_int;
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
    fn code(&self) -> Option<i32> {
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

type Result<T, E = Error> = std::result::Result<T, E>;

fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| ffi::fido_init(0));
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
        // Freed in Drop (or below on failure).
        let mut dev = ffi::fido_dev_new();
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
        let assert = Handle::assertion()?;
        assert.set_rp(&rp)?;
        assert.set_challenge(req.client_data_hash)?;
        for id in req.allow {
            assert.allow(id)?;
        }
        // A PIN verifies the user itself; without one, ask for the
        // authenticator's own verification.
        let uv = req.user_verification && pin.is_none();
        assert.set_uv(uv)?;
        if let Some(salt) = req.hmac_salt {
            assert.set_hmac_salt(salt)?;
        }
        // SAFETY: both handles are live; `pin` is null or a C string.
        check("get an assertion", unsafe {
            ffi::fido_dev_get_assert(self.dev, assert.ptr, pin_ptr(pin.as_ref()))
        })?;
        // SAFETY: the handle is live.
        if unsafe { ffi::fido_assert_count(assert.ptr) } == 0 {
            return Err(Error::Missing("an assertion"));
        }
        let hmac_secret = if req.hmac_salt.is_some() {
            let secret = assert
                .field(
                    ffi::fido_assert_hmac_secret_ptr,
                    ffi::fido_assert_hmac_secret_len,
                )
                .ok_or(Error::Missing("the hmac-secret output"))?;
            Some(SecretBuf::new(secret))
        } else {
            None
        };
        Ok(Assertion {
            // A single allowed credential may be left out of the answer.
            credential_id: assert
                .field(ffi::fido_assert_id_ptr, ffi::fido_assert_id_len)
                .or_else(|| match req.allow {
                    [only] => Some(only.clone()),
                    _ => None,
                })
                .ok_or(Error::Missing("the credential ID"))?,
            authenticator_data: assert
                .field(
                    ffi::fido_assert_authdata_raw_ptr,
                    ffi::fido_assert_authdata_raw_len,
                )
                .ok_or(Error::Missing("the authenticator data"))?,
            signature: assert
                .field(ffi::fido_assert_sig_ptr, ffi::fido_assert_sig_len)
                .ok_or(Error::Missing("the signature"))?,
            hmac_secret,
        })
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
            let cred = Handle::credential()?;
            let made = cred.set_type(alg).and_then(|()| {
                cred.set_up(&rp, &rp_name, &user, req, &cdh)?;
                // SAFETY: both handles are live; `pin` is null or a C string.
                check("make a credential", unsafe {
                    ffi::fido_dev_make_cred(self.dev, cred.ptr, pin_ptr(pin.as_ref()))
                })
            });
            match made {
                Ok(()) => return cred.made(),
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

/// An owned libfido2 assertion or credential, freed on drop (libfido2 wipes
/// secrets such as the hmac-secret output on free).
struct Handle<T> {
    ptr: *mut T,
    free: unsafe extern "C" fn(*mut *mut T),
}

impl<T> Handle<T> {
    fn new(
        alloc: extern "C" fn() -> *mut T,
        free: unsafe extern "C" fn(*mut *mut T),
        what: &'static str,
    ) -> Result<Self> {
        let ptr = alloc();
        if ptr.is_null() {
            Err(Error::Missing(what))
        } else {
            Ok(Self { ptr, free })
        }
    }
}

impl<T> Drop for Handle<T> {
    fn drop(&mut self) {
        // SAFETY: allocated in `new`, freed once.
        unsafe { (self.free)(&raw mut self.ptr) };
    }
}

impl Handle<ffi::fido_assert_t> {
    fn assertion() -> Result<Self> {
        Self::new(
            ffi::fido_assert_new,
            ffi::fido_assert_free,
            "an assertion handle",
        )
    }

    fn set_rp(&self, rp: &CStr) -> Result<()> {
        // SAFETY: a live handle; libfido2 copies the string.
        check("set the relying party", unsafe {
            ffi::fido_assert_set_rp(self.ptr, rp.as_ptr())
        })
    }

    fn set_challenge(&self, hash: &[u8; 32]) -> Result<()> {
        // SAFETY: a live handle; libfido2 copies the 32 bytes.
        check("set the challenge", unsafe {
            ffi::fido_assert_set_clientdata_hash(self.ptr, hash.as_ptr(), hash.len())
        })
    }

    fn allow(&self, id: &[u8]) -> Result<()> {
        // SAFETY: a live handle; libfido2 copies the ID.
        check("allow a credential", unsafe {
            ffi::fido_assert_allow_cred(self.ptr, id.as_ptr(), id.len())
        })
    }

    fn set_uv(&self, uv: bool) -> Result<()> {
        let uv = if uv {
            ffi::FIDO_OPT_TRUE
        } else {
            ffi::FIDO_OPT_OMIT
        };
        // SAFETY: a live handle.
        check("ask for user verification", unsafe {
            ffi::fido_assert_set_uv(self.ptr, uv)
        })
    }

    fn set_hmac_salt(&self, salt: &[u8; 32]) -> Result<()> {
        // SAFETY: a live handle.
        check("ask for hmac-secret", unsafe {
            ffi::fido_assert_set_extensions(self.ptr, ffi::FIDO_EXT_HMAC_SECRET)
        })?;
        // SAFETY: a live handle; libfido2 copies the salt.
        check("set the hmac-secret salt", unsafe {
            ffi::fido_assert_set_hmac_salt(self.ptr, salt.as_ptr(), salt.len())
        })
    }

    /// A copy of one field of assertion 0, which must exist.
    fn field(
        &self,
        ptr: unsafe extern "C" fn(*const ffi::fido_assert_t, usize) -> *const c_uchar,
        len: unsafe extern "C" fn(*const ffi::fido_assert_t, usize) -> usize,
    ) -> Option<Vec<u8>> {
        // SAFETY: a live handle with an assertion at index 0 (`fido_assert_count`
        // was checked); libfido2 owns the bytes.
        unsafe { copy_out(ptr(self.ptr, 0), len(self.ptr, 0)) }
    }
}

impl Handle<ffi::fido_cred_t> {
    fn credential() -> Result<Self> {
        Self::new(
            ffi::fido_cred_new,
            ffi::fido_cred_free,
            "a credential handle",
        )
    }

    fn set_type(&self, alg: i32) -> Result<()> {
        // SAFETY: a live handle.
        check("set the algorithm", unsafe {
            ffi::fido_cred_set_type(self.ptr, alg)
        })
    }

    /// Everything but the algorithm: challenge, relying party, user, and the
    /// non-discoverable and `hmac-secret` options.
    fn set_up(
        &self,
        rp: &CStr,
        rp_name: &CStr,
        user: &CStr,
        req: &CredentialRequest<'_>,
        cdh: &[u8; 32],
    ) -> Result<()> {
        // SAFETY: a live handle; libfido2 copies every buffer.
        check("set the challenge", unsafe {
            ffi::fido_cred_set_clientdata_hash(self.ptr, cdh.as_ptr(), cdh.len())
        })?;
        // SAFETY: as above.
        check("set the relying party", unsafe {
            ffi::fido_cred_set_rp(self.ptr, rp.as_ptr(), rp_name.as_ptr())
        })?;
        // SAFETY: as above.
        check("set the user", unsafe {
            ffi::fido_cred_set_user(
                self.ptr,
                req.user_id.as_ptr(),
                req.user_id.len(),
                user.as_ptr(),
                user.as_ptr(),
                std::ptr::null(),
            )
        })?;
        // SAFETY: as above.
        check("make it non-discoverable", unsafe {
            ffi::fido_cred_set_rk(self.ptr, ffi::FIDO_OPT_OMIT)
        })?;
        if req.hmac_secret {
            // SAFETY: as above.
            check("ask for hmac-secret", unsafe {
                ffi::fido_cred_set_extensions(self.ptr, ffi::FIDO_EXT_HMAC_SECRET)
            })?;
        }
        Ok(())
    }

    /// The credential the device just made.
    fn made(&self) -> Result<Credential> {
        // SAFETY: a live handle that `fido_dev_make_cred` filled.
        let id = unsafe {
            copy_out(
                ffi::fido_cred_id_ptr(self.ptr),
                ffi::fido_cred_id_len(self.ptr),
            )
        }
        .ok_or(Error::Missing("the credential ID"))?;
        // SAFETY: as above.
        let alg = unsafe { ffi::fido_cred_type(self.ptr) };
        Ok(Credential { id, alg })
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
