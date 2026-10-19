//! An armoured password AS exchange in process, with its own Kerberos
//! configuration file: what `kinit -n` followed by `kinit -T` does, without
//! touching `KRB5_CONFIG` or the default credential cache.

use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr;

use crate::error::GssError;
use crate::ffi;

/// A libkrb5 context made from one configuration file.
struct Context(ffi::Krb5Context);

impl Context {
    fn from_file(config: &Path) -> Result<Self, GssError> {
        let path = CString::new(config.as_os_str().as_encoded_bytes())
            .map_err(|_| GssError::NulInConfigPath)?;
        let mut profile: ffi::Profile = ptr::null_mut();
        // SAFETY: path is a live C string; profile is a valid output pointer.
        let ret = unsafe { ffi::profile_init_path(path.as_ptr(), &raw mut profile) };
        if ret != 0 {
            return Err(GssError::Krb5 {
                code: i32::try_from(ret).unwrap_or(-1),
                msg: "profile_init_path",
            });
        }
        let mut ctx: ffi::Krb5Context = ptr::null_mut();
        // SAFETY: profile was set above; the context copies it, so it is
        // released right after.
        let ret = unsafe {
            let ret = ffi::krb5_init_context_profile(profile, 0, &raw mut ctx);
            ffi::profile_release(profile);
            ret
        };
        if ret != 0 {
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_init_context_profile",
            });
        }
        Ok(Self(ctx))
    }

    /// `Err` with libkrb5's message for `code`, if it is not zero.
    fn check(&self, code: i32, msg: &'static str) -> Result<(), GssError> {
        if code == 0 {
            return Ok(());
        }
        // SAFETY: self.0 is a live context; the message is freed below.
        let detail = unsafe {
            let p = ffi::krb5_get_error_message(self.0, code);
            let s = if p.is_null() {
                String::new()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            };
            ffi::krb5_free_error_message(self.0, p);
            s
        };
        tracing::warn!(code = %format_args!("{code:#010x}"), %detail, "{msg} failed");
        Err(GssError::Krb5Detail { code, msg, detail })
    }

    fn principal(&self, name: &str) -> Result<Principal<'_>, GssError> {
        let name = CString::new(name).map_err(|_| GssError::NulInUserPrincipal)?;
        let mut p: ffi::Krb5Principal = ptr::null_mut();
        // SAFETY: name is a live C string; p is a valid output pointer.
        self.check(
            unsafe { ffi::krb5_parse_name(self.0, name.as_ptr(), &raw mut p) },
            "krb5_parse_name",
        )?;
        Ok(Principal(self, p))
    }

    fn ccache(&self, name: &str) -> Result<Ccache<'_>, GssError> {
        let name = CString::new(name).map_err(|_| GssError::NulInCcacheName)?;
        let mut cc: ffi::Krb5Ccache = ptr::null_mut();
        // SAFETY: name is a live C string; cc is a valid output pointer.
        self.check(
            unsafe { ffi::krb5_cc_resolve(self.0, name.as_ptr(), &raw mut cc) },
            "krb5_cc_resolve",
        )?;
        Ok(Ccache(self, cc))
    }

    fn options(&self) -> Result<Options<'_>, GssError> {
        let mut opt: ffi::Krb5GetInitCredsOpt = ptr::null_mut();
        // SAFETY: opt is a valid output pointer.
        self.check(
            unsafe { ffi::krb5_get_init_creds_opt_alloc(self.0, &raw mut opt) },
            "krb5_get_init_creds_opt_alloc",
        )?;
        Ok(Options(self, opt))
    }

    /// One AS exchange for `client`, with `password` (none for anonymous),
    /// for `service` (`None`: the TGS), with `opt`; the credentials go to
    /// the options' output ccache.
    fn init_creds(
        &self,
        client: &Principal<'_>,
        password: Option<&CStr>,
        service: Option<&CStr>,
        opt: &Options<'_>,
        msg: &'static str,
    ) -> Result<(), GssError> {
        let mut creds = ffi::Krb5Creds([0u8; 128]);
        // SAFETY: every handle is live; the C strings outlive the call; the
        // credentials are freed whether or not the call succeeded (zeroed
        // contents are freed as empty).
        let ret = unsafe {
            let ret = ffi::krb5_get_init_creds_password(
                self.0,
                &raw mut creds,
                client.1,
                password.map_or(ptr::null(), CStr::as_ptr),
                ptr::null(),
                ptr::null_mut(),
                0,
                service.map_or(ptr::null(), CStr::as_ptr),
                opt.1,
            );
            ffi::krb5_free_cred_contents(self.0, &raw mut creds);
            ret
        };
        self.check(ret, msg)
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: self.0 was made by krb5_init_context_profile.
        unsafe { ffi::krb5_free_context(self.0) };
    }
}

struct Principal<'a>(&'a Context, ffi::Krb5Principal);

impl Drop for Principal<'_> {
    fn drop(&mut self) {
        // SAFETY: self.1 was made by krb5_parse_name in this context.
        unsafe { ffi::krb5_free_principal(self.0 .0, self.1) };
    }
}

struct Ccache<'a>(&'a Context, ffi::Krb5Ccache);

impl Ccache<'_> {
    /// Destroy the cache and its contents.
    fn destroy(self) {
        // SAFETY: self.1 is a live ccache; destroy also closes it, so Drop
        // must not run.
        unsafe { ffi::krb5_cc_destroy(self.0 .0, self.1) };
        std::mem::forget(self);
    }
}

impl Drop for Ccache<'_> {
    fn drop(&mut self) {
        // SAFETY: self.1 was resolved in this context.
        unsafe { ffi::krb5_cc_close(self.0 .0, self.1) };
    }
}

struct Options<'a>(&'a Context, ffi::Krb5GetInitCredsOpt);

impl Drop for Options<'_> {
    fn drop(&mut self) {
        // SAFETY: self.1 was allocated in this context.
        unsafe { ffi::krb5_get_init_creds_opt_free(self.0 .0, self.1) };
    }
}

/// Get a ticket for `service` (a principal name with its realm, e.g.
/// `ipa-ku/ipa1.example.test@EXAMPLE.TEST`) as `principal` with `password`,
/// in an AS exchange armoured with anonymous PKINIT (FAST is required),
/// using only the Kerberos configuration file `config`, which names the
/// realm's KDCs and PKINIT anchors.  The ticket is stored in the
/// credential cache `ccache` (e.g. `MEMORY:…`, initialised here), for
/// [`crate::GssClientCred::from_named_ccache`].
///
/// The AS reply for a plain password user is encrypted in that user's
/// long-term key, so a KDC that answers it knows the key: the realm, not
/// whoever serves the configuration.  With an OTP or RADIUS factor the
/// reply key comes from the armour instead.
///
/// # Errors
///
/// A NUL byte in an argument, or libkrb5's error (no anonymous PKINIT, no
/// FAST, a wrong password, an unreachable KDC).
pub fn password_ticket(
    config: &Path,
    principal: &str,
    password: &[u8],
    service: &str,
    ccache: &str,
) -> Result<(), GssError> {
    let password = CString::new(password).map_err(|_| GssError::NulInPassword)?;
    let service = CString::new(service).map_err(|_| GssError::NulInTargetName)?;
    let realm = principal
        .rsplit_once('@')
        .map(|(_, r)| r)
        .filter(|r| !r.is_empty())
        .ok_or(GssError::NulInUserPrincipal)?;
    let ctx = Context::from_file(config)?;

    // The armour: an anonymous PKINIT ticket in a private ccache.
    let armour = ctx.ccache(&format!("{ccache}-armour"))?;
    {
        let anonymous = ctx.principal(&format!("WELLKNOWN/ANONYMOUS@{realm}"))?;
        let opt = ctx.options()?;
        // SAFETY: opt and armour are live.
        unsafe { ffi::krb5_get_init_creds_opt_set_anonymous(opt.1, 1) };
        ctx.check(
            unsafe { ffi::krb5_get_init_creds_opt_set_out_ccache(ctx.0, opt.1, armour.1) },
            "krb5_get_init_creds_opt_set_out_ccache",
        )?;
        ctx.init_creds(&anonymous, None, None, &opt, "anonymous PKINIT")?;
    }

    // The armoured exchange, straight for the service.
    let result = (|| {
        let client = ctx.principal(principal)?;
        let out = ctx.ccache(ccache)?;
        let opt = ctx.options()?;
        // SAFETY: every handle is live.
        unsafe {
            ctx.check(
                ffi::krb5_get_init_creds_opt_set_fast_ccache(ctx.0, opt.1, armour.1),
                "krb5_get_init_creds_opt_set_fast_ccache",
            )?;
            ctx.check(
                ffi::krb5_get_init_creds_opt_set_fast_flags(ctx.0, opt.1, ffi::KRB5_FAST_REQUIRED),
                "krb5_get_init_creds_opt_set_fast_flags",
            )?;
            ctx.check(
                ffi::krb5_get_init_creds_opt_set_out_ccache(ctx.0, opt.1, out.1),
                "krb5_get_init_creds_opt_set_out_ccache",
            )?;
        }
        ctx.init_creds(
            &client,
            Some(&password),
            Some(&service),
            &opt,
            "armoured AS exchange",
        )
    })();
    armour.destroy();
    wipe(password.into_bytes_with_nul());
    result
}

/// Overwrite a copy of a secret before freeing it.
fn wipe(mut bytes: Vec<u8>) {
    for b in &mut bytes {
        // SAFETY: b is a valid, aligned byte of the vector.
        unsafe { ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
