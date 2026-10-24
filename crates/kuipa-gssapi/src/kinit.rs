//! An armoured AS exchange in process, with its own Kerberos configuration
//! file: what `kinit -n` followed by `kinit -T` does, without touching
//! `KRB5_CONFIG` or the default credential cache.
//!
//! # Pre-authentication, with MIT Kerberos
//!
//! [`ticket`] registers two libkrb5 callbacks:
//!
//! * the **responder**, called once per exchange with the questions the KDC
//!   offered, answered in priority order — passwordless methods first and
//!   methods this build does not know last, so a password never stands in for
//!   a token the realm offered:
//!
//!   | Question             | Answer                                                          |
//!   |----------------------|-----------------------------------------------------------------|
//!   | `"passkey"`          | none, so the passkey plugin collects the PIN through the prompter |
//!   | `"otp"`              | the token's value and, when the token asks, a PIN of its own    |
//!   | `"idp"`, `"radius"`, `"pkinit"`, anything else | the challenge shown, then a secret answer |
//!   | `"password"`         | none: libkrb5 takes the long-term password from the caller's secret, or asks for it through the prompter |
//!
//! * the **prompter**, used by client plugins that drive their own prompts —
//!   a passkey plugin's FIDO2 PIN and device presence, after the responder
//!   handed the question back by answering it with nothing — and by libkrb5
//!   itself, to collect the password it needs for the FAST encrypted
//!   challenge when the caller brought none.
//!
//! Both send every prompt and every line of a challenge through
//! [`Preauth`], so the caller decides where a question is asked.  Answers
//! are never traced.
//!
//! # Pre-authentication, with Heimdal
//!
//! Heimdal's libkrb5 has no responder callbacks, so [`ticket`] drives its
//! step-by-step credential API instead: an anonymous PKINIT exchange for the
//! FAST armour, then `krb5_init_creds_init` with the prompter below.
//!
//! * a **password**, asked through [`Preauth`] before the exchange starts,
//!   since Heimdal's step API never prompts for the long-term password itself;
//!   a secret the caller brought is used as is, and nothing is asked.
//! * the **prompter**, which answers the expiration notices of
//!   `krb5_process_last_request` and whatever a plugin asks for.
//!
//! What that leaves on the shelf, in a build against Heimdal: the OTP, IdP
//! and RADIUS methods and the passkey and PKINIT client plugins have no
//! responder to answer their questions, and their formats are MIT's, not
//! Heimdal's; there are no thread-local credential caches and no S4U2Self.
//! Password and anonymous-PKINIT FAST armoring — what enrollment needs —
//! work.

use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr;

use libc::{c_char, c_int, c_void};

use crate::error::GssError;
use crate::ffi;

/// A libkrb5 context made from one configuration file.
struct Context(ffi::Krb5Context);

impl Context {
    /// A context that reads `config` and nothing else.
    #[cfg(mit_kerberos)]
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

    /// A context that reads `config` and nothing else.
    ///
    /// Heimdal has no profile handles: the list is given to a plain context,
    /// which takes it as a NULL-terminated array of paths and re-reads the
    /// defaults and realms from it.
    #[cfg(heimdal_kerberos)]
    fn from_file(config: &Path) -> Result<Self, GssError> {
        let path = CString::new(config.as_os_str().as_encoded_bytes())
            .map_err(|_| GssError::NulInConfigPath)?;
        let mut ctx: ffi::Krb5Context = ptr::null_mut();
        // SAFETY: ctx is a valid output pointer.
        let ret = unsafe { ffi::krb5_init_context(&raw mut ctx) };
        if ret != 0 {
            return Err(GssError::Krb5 {
                code: ret,
                msg: "krb5_init_context",
            });
        }
        let ctx = Self(ctx);
        // SAFETY: `paths` is NULL-terminated and both it and the string it
        // points into outlive the call; Heimdal copies the paths it keeps.
        let ret = unsafe {
            let mut paths: [*mut c_char; 2] = [path.as_ptr().cast_mut(), ptr::null_mut()];
            ffi::krb5_set_config_files(ctx.0, paths.as_mut_ptr())
        };
        ctx.check(ret, "krb5_set_config_files")?;
        Ok(ctx)
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
    /// the options' output ccache.  With `answers`, the exchange asks the
    /// caller's front end for anything the KDC requests.
    #[cfg(mit_kerberos)]
    fn init_creds(
        &self,
        client: &Principal<'_>,
        password: Option<&CStr>,
        service: Option<&CStr>,
        opt: &Options<'_>,
        answers: Option<&mut Answers<'_>>,
        msg: &'static str,
    ) -> Result<(), GssError> {
        let mut creds = ffi::Krb5Creds::new();
        let (prompter_fn, prompter_data) = match answers {
            Some(a) => (
                Some(prompter as ffi::Krb5PrompterFn),
                ptr::from_mut(a).cast::<c_void>(),
            ),
            None => (None, ptr::null_mut()),
        };
        // SAFETY: every handle is live; the C strings outlive the call; the
        // credentials are freed whether or not the call succeeded (zeroed
        // contents are freed as empty); the prompter's data is `answers`,
        // which the caller keeps alive for the whole exchange.
        let ret = unsafe {
            let ret = ffi::krb5_get_init_creds_password(
                self.0,
                &raw mut creds,
                client.1,
                password.map_or(ptr::null(), CStr::as_ptr),
                prompter_fn,
                prompter_data,
                0,
                service.map_or(ptr::null(), CStr::as_ptr),
                opt.1,
            );
            ffi::krb5_free_cred_contents(self.0, &raw mut creds);
            ret
        };
        self.check(ret, msg)
    }

    /// The anonymous PKINIT ticket that armors the exchange to come.
    ///
    /// Heimdal's PKINIT takes its trust anchors from the realm's
    /// `pkinit_anchors`, which [`Context::from_file`] just read; with no
    /// client identity to present it proves nothing about the caller, which
    /// is the point: it proves who the KDC is.
    #[cfg(heimdal_kerberos)]
    fn armour(&self, client: &Principal<'_>, out: &Ccache<'_>) -> Result<(), GssError> {
        let opt = self.options()?;
        // SAFETY: every handle is live; the options hold no string of ours.
        unsafe {
            ffi::krb5_get_init_creds_opt_set_anonymous(opt.1, 1);
            // A minute, as `kinit` does for the cache given to `-T`: the
            // armour is used once, immediately.
            ffi::krb5_get_init_creds_opt_set_tkt_life(opt.1, 60);
            ffi::krb5_get_init_creds_opt_set_pkinit(
                self.0,
                opt.1,
                client.1,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ffi::KRB5_GIC_OPT_PKINIT_ANONYMOUS,
                None,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
        let step = Step::new(self, client, None, &opt, None)?;
        step.get("anonymous PKINIT")?;
        step.report_last_request();
        step.store(out, "krb5_init_creds_store (armour)")
    }

    /// The armoured exchange for `client`, giving `service` a ticket in
    /// `out`.  `password` is the long-term key, if the caller brought one;
    /// otherwise the front end is asked before the exchange starts, because
    /// Heimdal's step API never prompts for the password itself.
    // One argument per thing libkrb5's own step API takes: the principal,
    // the password, the service, its realm, the armour, the output cache,
    // the front end.
    #[cfg(heimdal_kerberos)]
    #[allow(clippy::too_many_arguments)]
    fn exchange(
        &self,
        client: &Principal<'_>,
        password: Option<&CStr>,
        service: &CStr,
        realm: &str,
        armour: &Ccache<'_>,
        out: &Ccache<'_>,
        answers: &Answers<'_>,
    ) -> Result<(), GssError> {
        let opt = self.options()?;
        // The realm's defaults for an init-creds exchange: `kinit` applies
        // them, and `krb5_init_creds_init` does not when options are given.
        let realm = CString::new(realm).map_err(|_| GssError::NulInUserPrincipal)?;
        // SAFETY: opt is live; the realm string outlives the call, which
        // copies what it takes.
        unsafe {
            ffi::krb5_get_init_creds_opt_set_default_flags(
                self.0,
                c"kinit".as_ptr(),
                realm.as_ptr(),
                opt.1,
            );
        }
        let asked = password.map_or_else(
            || answers.cstring("Password", answers.ask("Password", true)),
            |_| None,
        );
        let password = password.or(asked.as_deref());
        let step = Step::new(self, client, Some(answers), &opt, Some(password))?;
        // SAFETY: every handle is live; the C strings outlive the exchange.
        unsafe {
            self.check(
                ffi::krb5_init_creds_set_service(self.0, step.handle, service.as_ptr()),
                "krb5_init_creds_set_service",
            )?;
            self.check(
                ffi::krb5_init_creds_set_fast_ccache(self.0, step.handle, armour.1),
                "krb5_init_creds_set_fast_ccache",
            )?;
        }
        step.get("armoured AS exchange")?;
        step.report_last_request();
        step.store(out, "krb5_init_creds_store")?;
        if let Some(asked) = asked {
            wipe(asked.into_bytes());
        }
        Ok(())
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

/// One step-by-step AS exchange of Heimdal's libkrb5: the handle, plus what
/// keeps the prompter's data alive while libkrb5 may call it.
#[cfg(heimdal_kerberos)]
struct Step<'a, 'b> {
    ctx: &'a Context,
    /// The handle; only ever used through the methods below.
    handle: ffi::Krb5InitCredsContext,
    /// Borrowed so it cannot be dropped, or moved, while libkrb5 holds the
    /// pointer handed to it as the prompter's data.  Never read here.
    #[allow(dead_code)]
    answers: Option<&'b Answers<'b>>,
}

#[cfg(heimdal_kerberos)]
impl<'a, 'b> Step<'a, 'b> {
    /// Start an exchange for `client`.  With `answers` the prompter of
    /// [`prompter`] is registered for it, so an expiration notice, or a
    /// plugin's PIN, reaches the caller's front end.
    ///
    /// `password` is set before anything can prompt: the step API never
    /// asks for the long-term password itself, unlike the one-call wrapper.
    fn new(
        ctx: &'a Context,
        client: &Principal<'_>,
        answers: Option<&'b Answers<'b>>,
        opt: &Options<'_>,
        password: Option<Option<&CStr>>,
    ) -> Result<Self, GssError> {
        let (prompter_fn, prompter_data): (Option<ffi::Krb5PrompterFn>, *mut c_void) =
            match &answers {
                Some(a) => (
                    Some(prompter as ffi::Krb5PrompterFn),
                    ptr::from_ref(*a).cast::<c_void>().cast_mut(),
                ),
                None => (None, ptr::null_mut()),
            };
        let mut handle: ffi::Krb5InitCredsContext = ptr::null_mut();
        // SAFETY: every handle is live; the C strings outlive the call; the
        // prompter's data is `answers`, borrowed here for as long as the
        // step lives.  On failure libkrb5 frees what it made and leaves the
        // output pointer alone, so Drop has nothing to release.
        let ret = unsafe {
            ffi::krb5_init_creds_init(
                ctx.0,
                client.1,
                prompter_fn,
                prompter_data,
                0,
                opt.1,
                &raw mut handle,
            )
        };
        ctx.check(ret, "krb5_init_creds_init")?;
        let step = Self {
            ctx,
            handle,
            answers,
        };
        if let Some(password) = password {
            // SAFETY: the handle is live; the string outlives the call,
            // which copies it.
            ctx.check(
                unsafe {
                    ffi::krb5_init_creds_set_password(
                        ctx.0,
                        step.handle,
                        password.map_or(ptr::null(), CStr::as_ptr),
                    )
                },
                "krb5_init_creds_set_password",
            )?;
        }
        Ok(step)
    }

    /// Run the exchange through to a ticket.
    fn get(&self, msg: &'static str) -> Result<(), GssError> {
        // SAFETY: the handle is live.
        self.ctx.check(
            unsafe { ffi::krb5_init_creds_get(self.ctx.0, self.handle) },
            msg,
        )
    }

    /// Whatever the KDC's last reply had to say — an expired password, for
    /// instance — through the prompter.  The options are not passed: they
    /// are only read for a last-request callback kuipa does not set.
    /// Nothing useful to do with the code.
    fn report_last_request(&self) {
        // SAFETY: the handle is live.
        let ret =
            unsafe { ffi::krb5_process_last_request(self.ctx.0, ptr::null_mut(), self.handle) };
        if ret != 0 {
            tracing::warn!(code = %format_args!("{ret:#010x}"), "krb5_process_last_request failed");
        }
    }

    /// Cache the credentials collected in `out`.
    fn store(&self, out: &Ccache<'_>, msg: &'static str) -> Result<(), GssError> {
        // SAFETY: every handle is live; with the exchange complete the
        // client principal is set, and the credentials are copied into the
        // cache.
        self.ctx.check(
            unsafe { ffi::krb5_init_creds_store(self.ctx.0, self.handle, out.1) },
            msg,
        )
    }
}

#[cfg(heimdal_kerberos)]
impl Drop for Step<'_, '_> {
    fn drop(&mut self) {
        // SAFETY: the handle was made by krb5_init_creds_init, which only
        // returns it set.
        unsafe { ffi::krb5_init_creds_free(self.ctx.0, self.handle) };
    }
}

// ── Pre-authentication ────────────────────────────────────────────────────────

/// Where an exchange asks a human for what the KDC asks for.
///
/// The responder and the prompter of [`ticket`] route every prompt, and
/// every line a challenge carries, through this trait, so the tool that
/// enrolls a host decides where a question is asked: a terminal, a window,
/// a test.  An implementation must not trace what it collects.
pub trait Preauth {
    /// Show a line the KDC sent with a challenge: the service that checks
    /// the token, a token vendor, a realm to log into.
    fn info(&self, msg: &str) {
        eprintln!("{msg}");
    }

    /// Ask for an answer that may be echoed — a plugin's own prompt.
    ///
    /// # Errors
    ///
    /// Whatever the front end cannot collect; [`ticket`] reports it as the
    /// reason the exchange failed.
    fn prompt(&self, label: &str) -> Result<Vec<u8>, GssError>;

    /// Ask for a secret: a password, a token value, a PIN.  Echo must be
    /// off: with FreeIPA's password-plus-OTP tokens one field carries both.
    ///
    /// # Errors
    ///
    /// As for [`prompt`][Preauth::prompt].
    fn secret(&self, label: &str) -> Result<Vec<u8>, GssError>;

    /// Offer `uri` for scanning — the key of a token that is not enrolled
    /// yet.
    fn qr(&self, uri: &str) {
        self.info(uri);
    }
}

/// A [`Preauth`] that answers nothing: for an exchange whose secret must
/// suffice on its own, so a KDC that asks for a second factor is refused
/// with a reason instead of a read that never returns.
pub struct NoPreauth;

impl Preauth for NoPreauth {
    fn prompt(&self, label: &str) -> Result<Vec<u8>, GssError> {
        Err(GssError::Preauth {
            detail: format!("{label}: nothing can be asked here"),
        })
    }

    fn secret(&self, label: &str) -> Result<Vec<u8>, GssError> {
        self.prompt(label)
    }
}

/// Where an exchange asks for what the KDC asks for, and what it could not
/// get.
struct Answers<'a> {
    ui: &'a dyn Preauth,
    /// Why a question could not be answered, as the front end said.
    /// [`ticket`] reports this instead of libkrb5's own failure, which only
    /// says that pre-authentication failed.
    refused: RefCell<Option<String>>,
}

impl Answers<'_> {
    /// Remember why a question could not be answered, the first reason wins.
    fn record(&self, reason: impl Into<String>) {
        let mut refused = self.refused.borrow_mut();
        if refused.is_none() {
            *refused = Some(reason.into());
        }
    }

    /// Whether some question was refused, so the exchange is over.
    #[cfg(mit_kerberos)]
    fn failed(&self) -> bool {
        self.refused.borrow().is_some()
    }

    /// Why a question could not be answered, if one could not.
    fn reason(&self) -> Option<String> {
        self.refused.borrow().clone()
    }

    /// Ask the front end, remembering why it could not answer.
    fn ask(&self, label: &str, hidden: bool) -> Option<Vec<u8>> {
        let asked = if hidden {
            self.ui.secret(label)
        } else {
            self.ui.prompt(label)
        };
        match asked {
            Ok(answer) => Some(answer),
            Err(e) => {
                self.record(format!("{label}: {e}"));
                None
            }
        }
    }

    /// Make `answer` a C string libkrb5 will take, refusing one with an
    /// interior NUL byte rather than cutting it short.
    fn cstring(&self, label: &str, answer: Option<Vec<u8>>) -> Option<CString> {
        match answer.map(CString::new) {
            None => None,
            Some(Ok(s)) => Some(s),
            Some(Err(_)) => {
                self.record(format!("{label}: cannot be given to Kerberos (a NUL byte)"));
                None
            }
        }
    }

    /// Show a challenge, offering it for scanning when it is a URL.
    #[cfg(mit_kerberos)]
    fn show(&self, text: &str) {
        self.ui.info(text);
        if text.contains("://") {
            self.ui.qr(text);
        }
    }
}

#[cfg(mit_kerberos)]
/// What the responder does with one question the KDC offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handling {
    /// Decode the OTP challenge: show the token, ask for its value, and for
    /// a PIN of its own when the token wants one.
    Otp,
    /// Answer nothing, which hands the question back to the plugin that
    /// asked it; that plugin drives the prompter itself.
    Plugin,
    /// Show the challenge and ask for a secret answer.
    Challenge,
}

#[cfg(mit_kerberos)]
/// One question the KDC offered: its name, and libkrb5's pointer to the
/// name it wants back in `krb5_responder_set_answer`.
struct Question {
    name: String,
    ptr: *const c_char,
}

#[cfg(mit_kerberos)]
/// The methods a password must not stand in for, strongest first.  FreeIPA
/// offers a password alongside a token for a user who has both, and the
/// password alone would authenticate the weaker factor.
const PASSWORDLESS: &[(&str, Handling)] = &[
    ("passkey", Handling::Plugin),
    ("idp", Handling::Challenge),
    ("otp", Handling::Otp),
    ("radius", Handling::Challenge),
    ("pkinit", Handling::Challenge),
];

#[cfg(mit_kerberos)]
/// The questions the responder answers: passwordless methods first, methods
/// this build knows nothing about last, as generic challenges.
///
/// `"password"` is never answered here.  libkrb5 needs the long-term password
/// to build the FAST encrypted challenge, and takes it from the secret the
/// caller brought or asks for it through the prompter; an answer set for the
/// password question is not used for that challenge, so answering it here
/// would only keep the prompter from asking.
fn plan(questions: &[&str]) -> Vec<(usize, Handling)> {
    let mut chosen: Vec<(usize, Handling)> = Vec::new();
    for (method, handling) in PASSWORDLESS {
        if let Some(i) = questions.iter().position(|q| *q == *method) {
            chosen.push((i, *handling));
        }
    }
    for (i, name) in questions.iter().enumerate() {
        if !chosen.iter().any(|(j, _)| *j == i)
            && *name != "password"
            && !PASSWORDLESS.iter().any(|(m, _)| *m == *name)
        {
            chosen.push((i, Handling::Challenge));
        }
    }
    chosen
}

/// A library string as text; lossy, since these are only ever shown.
///
/// # Safety
///
/// `s` must point at a live, NUL-terminated string.
unsafe fn text(s: *const c_char) -> Cow<'static, str> {
    // SAFETY: the caller guarantees the pointer.
    unsafe { CStr::from_ptr(s) }
        .to_string_lossy()
        .into_owned()
        .into()
}

#[cfg(mit_kerberos)]
/// The libkrb5 responder: answer, this round, the questions the KDC offered.
///
/// A question this build cannot answer is left unanswered; libkrb5 then
/// fails the exchange, and [`ticket`] reports why, from the front end.
///
/// # Safety
///
/// `data` must point at a live [`Answers`] for the whole exchange, and `ctx`
/// and `rctx` must be live handles for this call.
unsafe extern "C" fn responder(
    ctx: ffi::Krb5Context,
    data: *mut c_void,
    rctx: ffi::Krb5ResponderContext,
) -> c_int {
    // SAFETY: `ticket` keeps the Answers alive for the exchange, and this is
    // the only pointer that touches it during the call.
    let answers = unsafe { &*(data.cast::<Answers<'_>>()) };

    // SAFETY: the list is NULL-terminated and aliases rctx for this call.
    let questions: Vec<Question> = unsafe {
        let mut list = Vec::new();
        let mut p = ffi::krb5_responder_list_questions(ctx, rctx);
        while !p.is_null() && !(*p).is_null() {
            list.push(Question {
                name: CStr::from_ptr(*p).to_string_lossy().into_owned(),
                ptr: *p,
            });
            p = p.add(1);
        }
        list
    };
    tracing::debug!(
        questions = ?questions.iter().map(|q| q.name.as_str()).collect::<Vec<_>>(),
        "the KDC offered pre-authentication"
    );

    let names: Vec<&str> = questions.iter().map(|q| q.name.as_str()).collect();
    for (i, handling) in plan(&names) {
        let name = questions[i].name.as_str();
        // SAFETY: this pointer came out of the list above, and rctx lives
        // for this call.
        let question = questions[i].ptr;
        match handling {
            Handling::Otp => otp_challenge(ctx, rctx, answers),
            Handling::Plugin => {
                // Answering with nothing makes the plugin that asked — a
                // passkey plugin, say — collect the answer itself through
                // the prompter.  Anything else it would take as the answer.
                // SAFETY: ctx and rctx are live; question names this context.
                unsafe {
                    let _ = ffi::krb5_responder_set_answer(ctx, rctx, question, ptr::null());
                }
                return 0;
            }
            Handling::Challenge => {
                // SAFETY: ctx and rctx are live; question names this context.
                let challenge = unsafe { ffi::krb5_responder_get_challenge(ctx, rctx, question) };
                if !challenge.is_null() {
                    // SAFETY: a live string, or null, checked just above.
                    answers.show(&unsafe { text(challenge) });
                }
                let answer = answers.cstring(name, answers.ask(name, true));
                // SAFETY: ctx and rctx are live; question names this context.
                unsafe {
                    let _ = ffi::krb5_responder_set_answer(
                        ctx,
                        rctx,
                        question,
                        answer.map_or(ptr::null(), |a| a.as_ptr()),
                    );
                }
                return 0;
            }
        }
        if answers.failed() {
            return 0;
        }
    }
    0
}

#[cfg(mit_kerberos)]
/// Answer the OTP question of a responder context.
///
/// The first token the KDC offered is the one used, as FreeIPA offers one.
/// Its value is asked for with echo off: a password-plus-OTP token takes
/// both in the one field.
///
/// # Safety
///
/// `ctx` and `rctx` must be live handles for this call, and `answers` must
/// outlive it.
unsafe fn otp_challenge(
    ctx: ffi::Krb5Context,
    rctx: ffi::Krb5ResponderContext,
    answers: &Answers<'_>,
) {
    let mut chl: *mut ffi::Krb5OtpChallenge = ptr::null_mut();
    // SAFETY: live handles; chl is a valid output pointer.
    if unsafe { ffi::krb5_responder_otp_get_challenge(ctx, rctx, &raw mut chl) } != 0
        || chl.is_null()
    {
        return;
    }
    // SAFETY: chl holds a challenge the library allocated for this call.
    let service = unsafe { (*chl).service };
    if !service.is_null() {
        // SAFETY: a live string, or null, checked just above.
        answers
            .ui
            .info(&format!("the token is checked by {}", unsafe {
                text(service)
            }));
    }
    // SAFETY: same challenge; tokeninfo is a NULL-terminated array.
    let tokens = unsafe { (*chl).tokeninfo };
    if !tokens.is_null() && !unsafe { *tokens }.is_null() {
        // SAFETY: the first entry of that array.
        let token = unsafe { &**tokens };
        for shown in [token.vendor, token.challenge] {
            if !shown.is_null() {
                // SAFETY: live strings, or nulls, checked just above.
                answers.show(&unsafe { text(shown) });
            }
        }
        let value = if token.flags & ffi::KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN != 0 {
            answers.ask("OTP token value", true)
        } else {
            None
        };
        let pin = if token.flags
            & (ffi::KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN
                | ffi::KRB5_RESPONDER_OTP_FLAGS_SEPARATE_PIN)
            == ffi::KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN
                | ffi::KRB5_RESPONDER_OTP_FLAGS_SEPARATE_PIN
        {
            answers.ask("PIN", true)
        } else {
            None
        };
        let value = answers.cstring("OTP token value", value);
        let pin = answers.cstring("PIN", pin);
        // SAFETY: live handles; the first token is the one asked about; the
        // C strings outlive the call.
        unsafe {
            let _ = ffi::krb5_responder_otp_set_answer(
                ctx,
                rctx,
                0,
                value.map_or(ptr::null(), |v| v.as_ptr()),
                pin.map_or(ptr::null(), |p| p.as_ptr()),
            );
        }
    }
    // SAFETY: chl was returned by krb5_responder_otp_get_challenge.
    unsafe { ffi::krb5_responder_otp_challenge_free(ctx, rctx, chl) };
}

/// The libkrb5 prompter: client plugins that drive their own prompts — the
/// PIN and device presence of a passkey, on a MIT build — reach the same
/// front end as kuipa's own questions instead of libkrb5's POSIX reader.  On
/// a Heimdal build it is what a password asked for up front, and the
/// expiration notices of `krb5_process_last_request`, go through.
///
/// # Safety
///
/// `data` must point at a live [`Answers`] for the whole exchange; `prompts`
/// must be an array of `num_prompts` entries, each with a reply buffer of
/// the capacity its `length` says.
unsafe extern "C" fn prompter(
    _ctx: ffi::Krb5Context,
    data: *mut c_void,
    name: *const c_char,
    banner: *const c_char,
    num_prompts: c_int,
    prompts: *mut ffi::Krb5Prompt,
) -> c_int {
    // SAFETY: `ticket` keeps the Answers alive for the exchange.
    let answers = unsafe { &*(data.cast::<Answers<'_>>()) };
    for heading in [name, banner] {
        if !heading.is_null() {
            // SAFETY: a live string, or null, checked just above.
            let shown = unsafe { text(heading) };
            if !shown.is_empty() {
                answers.ui.info(&shown);
            }
        }
    }
    for i in 0..num_prompts.max(0) as usize {
        // SAFETY: prompts holds num_prompts entries.
        let prompt = unsafe { &*prompts.add(i) };
        let label = if prompt.prompt.is_null() {
            String::new()
        } else {
            // SAFETY: a live string, or null, checked just above.
            unsafe { text(prompt.prompt) }.into_owned()
        };
        let Some(answer) = answers.ask(&label, prompt.hidden != 0) else {
            return 0;
        };
        // SAFETY: reply is a buffer of the capacity in its length; the
        // answer is cut to fit it, with a NUL after what is written, and
        // length is set to the number of bytes written.
        unsafe {
            let reply = &mut *prompt.reply;
            let capacity = reply.reply_length();
            if capacity == 0 || reply.data.is_null() {
                continue;
            }
            let len = answer.len().min(capacity - 1);
            ptr::copy_nonoverlapping(answer.as_ptr(), reply.data.cast::<u8>(), len);
            *reply.data.add(len) = 0;
            reply.set_reply_length(len);
        }
    }
    0
}

// ── The exchange ──────────────────────────────────────────────────────────────

/// Get a ticket for `service` (a principal name with its realm, e.g.
/// `ipa-ku/ipa1.example.test@EXAMPLE.TEST`) as `principal`, in an AS
/// exchange armoured with anonymous PKINIT (FAST is required), using only
/// the Kerberos configuration file `config`, which names the realm's KDCs
/// and PKINIT anchors.  The ticket is stored in the credential cache
/// `ccache` (e.g. `MEMORY:…`, initialised here), for
/// [`crate::GssClientCred::from_named_ccache`].
///
/// Whatever the KDC asks for is answered the way [`Preauth`] describes:
/// `secret` answers a plain password, and `None` leaves the KDC to drive
/// collection, so an OTP, a RADIUS or an IdP factor, or a passkey, is asked
/// for through `preauth`.  FAST armours every one of those questions, so a
/// fake KDC — one named by an impostor's advertisement — cannot collect
/// them.
///
/// The AS reply for a plain password user is encrypted in that user's
/// long-term key, so a KDC that answers it knows the key: the realm, not
/// whoever serves the configuration.  With an OTP or RADIUS factor the
/// reply key comes from the armour instead.
///
/// # Errors
///
/// A NUL byte in an argument, a question the front end could not answer, or
/// libkrb5's error (no anonymous PKINIT, no FAST, a refused factor, an
/// unreachable KDC).
pub fn ticket(
    config: &Path,
    principal: &str,
    secret: Option<&[u8]>,
    service: &str,
    ccache: &str,
    preauth: &dyn Preauth,
) -> Result<(), GssError> {
    let password = secret
        .map(CString::new)
        .transpose()
        .map_err(|_| GssError::NulInPassword)?;
    let service = CString::new(service).map_err(|_| GssError::NulInTargetName)?;
    let realm = principal
        .rsplit_once('@')
        .map(|(_, r)| r)
        .filter(|r| !r.is_empty())
        .ok_or(GssError::NulInUserPrincipal)?;
    let ctx = Context::from_file(config)?;

    // The armour: an anonymous PKINIT ticket in a private ccache.  Nothing
    // of it asks anything of a human, so it needs no responder and no
    // prompter.
    let armour = ctx.ccache(&format!("{ccache}-armour"))?;
    {
        let anonymous = ctx.principal(&format!("WELLKNOWN/ANONYMOUS@{realm}"))?;
        #[cfg(mit_kerberos)]
        {
            let opt = ctx.options()?;
            // SAFETY: opt and armour are live.
            unsafe { ffi::krb5_get_init_creds_opt_set_anonymous(opt.1, 1) };
            ctx.check(
                unsafe { ffi::krb5_get_init_creds_opt_set_out_ccache(ctx.0, opt.1, armour.1) },
                "krb5_get_init_creds_opt_set_out_ccache",
            )?;
            ctx.init_creds(&anonymous, None, None, &opt, None, "anonymous PKINIT")?;
        }
        #[cfg(heimdal_kerberos)]
        ctx.armour(&anonymous, &armour)?;
    }

    #[cfg(mit_kerberos)]
    let mut answers = Answers {
        ui: preauth,
        refused: RefCell::new(None),
    };
    #[cfg(heimdal_kerberos)]
    let answers = Answers {
        ui: preauth,
        refused: RefCell::new(None),
    };

    // The armoured exchange, straight for the service.
    let result = (|| {
        let client = ctx.principal(principal)?;
        let out = ctx.ccache(ccache)?;
        #[cfg(mit_kerberos)]
        {
            let opt = ctx.options()?;
            // SAFETY: every handle is live; `answers` outlives the exchange
            // below, which is the only thing that reads the pointer.
            unsafe {
                ctx.check(
                    ffi::krb5_get_init_creds_opt_set_responder(
                        ctx.0,
                        opt.1,
                        Some(responder),
                        ptr::from_mut(&mut answers).cast(),
                    ),
                    "krb5_get_init_creds_opt_set_responder",
                )?;
                ctx.check(
                    ffi::krb5_get_init_creds_opt_set_fast_ccache(ctx.0, opt.1, armour.1),
                    "krb5_get_init_creds_opt_set_fast_ccache",
                )?;
                ctx.check(
                    ffi::krb5_get_init_creds_opt_set_fast_flags(
                        ctx.0,
                        opt.1,
                        ffi::KRB5_FAST_REQUIRED,
                    ),
                    "krb5_get_init_creds_opt_set_fast_flags",
                )?;
                ctx.check(
                    ffi::krb5_get_init_creds_opt_set_out_ccache(ctx.0, opt.1, out.1),
                    "krb5_get_init_creds_opt_set_out_ccache",
                )?;
            }
            ctx.init_creds(
                &client,
                password.as_deref(),
                Some(&service),
                &opt,
                Some(&mut answers),
                "armoured AS exchange",
            )
        }
        #[cfg(heimdal_kerberos)]
        ctx.exchange(
            &client,
            password.as_deref(),
            &service,
            realm,
            &armour,
            &out,
            &answers,
        )
    })();
    armour.destroy();
    if let Some(password) = password {
        wipe(password.into_bytes());
    }
    // A question nobody could answer is the reason the exchange failed, and
    // says more than libkrb5's "preauthentication failed".
    match (result, answers.reason()) {
        (Err(_), Some(detail)) => Err(GssError::Preauth { detail }),
        (result, _) => result,
    }
}

/// Overwrite a copy of a secret before freeing it.
fn wipe(mut bytes: Vec<u8>) {
    for b in &mut bytes {
        // SAFETY: b is a valid, aligned byte of the vector.
        unsafe { ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// A [`Preauth`] that answers from a script, recording what it was
    /// asked and whether echo was to be kept off.
    struct Scripted {
        answers: std::cell::RefCell<VecDeque<(String, Vec<u8>)>>,
        asked: std::cell::RefCell<Vec<(String, bool)>>,
    }

    impl Scripted {
        fn new(answers: &[(&str, &str)]) -> Self {
            Self {
                answers: std::cell::RefCell::new(
                    answers
                        .iter()
                        .map(|(label, answer)| ((*label).to_owned(), (*answer).as_bytes().to_vec()))
                        .collect::<VecDeque<_>>(),
                ),
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn record(&self, label: &str, hidden: bool) -> Result<Vec<u8>, GssError> {
            self.asked.borrow_mut().push((label.to_owned(), hidden));
            self.answers
                .borrow_mut()
                .pop_front()
                .map(|(_, answer)| answer)
                .ok_or_else(|| GssError::Preauth {
                    detail: format!("{label}: nothing left to answer with"),
                })
        }
    }

    impl Preauth for Scripted {
        fn prompt(&self, label: &str) -> Result<Vec<u8>, GssError> {
            self.record(label, false)
        }

        fn secret(&self, label: &str) -> Result<Vec<u8>, GssError> {
            self.record(label, true)
        }
    }

    #[cfg(mit_kerberos)]
    #[test]
    fn a_password_never_stands_in_for_a_passwordless_method() {
        // The KDC offers both to a user with a token and a password; only
        // the token answers.
        assert_eq!(
            plan(&["password", "otp"]),
            [(1, Handling::Otp)],
            "the password question must be dropped"
        );
        assert_eq!(
            plan(&["radius", "password", "pkinit"]),
            [(0, Handling::Challenge), (2, Handling::Challenge)],
            "every passwordless method is answered, before anything else"
        );
        // A passkey answers itself, through the prompter.
        assert_eq!(
            plan(&["passkey", "otp"]),
            [(0, Handling::Plugin), (1, Handling::Otp)]
        );
    }

    #[cfg(mit_kerberos)]
    #[test]
    fn the_password_is_libkrb5_to_collect_not_the_responder() {
        assert_eq!(
            plan(&["password"]),
            [],
            "answering it here would keep libkrb5 from asking for the password it needs"
        );
        // A method this build does not know is asked about, as a generic
        // challenge, whatever else was offered.
        assert_eq!(
            plan(&["unknown-factor", "password"]),
            [(0, Handling::Challenge)],
            "the unknown method is asked about, last"
        );
        assert_eq!(plan(&["unknown-factor"]), [(0, Handling::Challenge)]);
    }

    #[test]
    fn the_prompter_fills_every_reply_and_cuts_it_to_the_buffer() {
        let ui = Scripted::new(&[("Password", "hunter2"), ("Passkey PIN", "1234")]);
        let mut answers = Answers {
            ui: &ui,
            refused: RefCell::new(None),
        };
        let mut buffers = [vec![0u8; 8], vec![0u8; 4]];
        let mut replies = [
            ffi::Krb5Data::from_buffer(&mut buffers[0]),
            ffi::Krb5Data::from_buffer(&mut buffers[1]),
        ];
        let prompts = [
            ffi::Krb5Prompt::new(c"Password", true, &mut replies[0]),
            ffi::Krb5Prompt::new(c"Passkey PIN", false, &mut replies[1]),
        ];
        // SAFETY: the prompts, their reply buffers and the answers all
        // outlive the call.
        let code = unsafe {
            prompter(
                ptr::null_mut(),
                ptr::from_mut(&mut answers).cast(),
                ptr::null(),
                ptr::null(),
                2,
                prompts.as_ptr().cast_mut(),
            )
        };
        assert_eq!(code, 0);
        // A hidden prompt is asked as a secret; an informative one is not.
        assert_eq!(
            ui.asked.borrow().as_slice(),
            [
                ("Password".to_owned(), true),
                ("Passkey PIN".to_owned(), false)
            ],
        );
        assert_eq!(&buffers[0][..replies[0].reply_length()], b"hunter2");
        assert_eq!(buffers[0][7], 0, "the reply ends with a NUL byte");
        assert_eq!(
            replies[1].reply_length(),
            3,
            "the answer is cut to one less than the capacity"
        );
        assert_eq!(&buffers[1][..3], b"123");
        assert_eq!(buffers[1][3], 0);
    }

    #[test]
    fn a_prompt_nobody_can_answer_is_kept_as_the_reason() {
        let ui = Scripted::new(&[]);
        let answers = Answers {
            ui: &ui,
            refused: RefCell::new(None),
        };
        assert_eq!(answers.ask("OTP token value", true), None);
        assert!(answers
            .reason()
            .is_some_and(|d| d.contains("OTP token value")));
    }
}
