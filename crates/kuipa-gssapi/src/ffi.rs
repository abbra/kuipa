//! Raw FFI bindings to `libgssapi_krb5`.
//!
//! Only the subset needed for server-side SPNEGO acceptance is declared here.
//! All pointer types use opaque enum structs to prevent accidental dereferencing.

#[cfg(test)]
use std::ffi::CStr;
use std::ffi::{c_char, c_int, c_long, c_uint, c_void};
use std::ptr;

pub(crate) type OmUint32 = u32;

/// Opaque GSSAPI security context handle.
pub(crate) enum GssCtxIdStruct {}
pub(crate) type GssCtxIdT = *mut GssCtxIdStruct;

/// Opaque GSSAPI credential handle.
pub(crate) enum GssCredIdStruct {}
pub(crate) type GssCredIdT = *mut GssCredIdStruct;

/// Opaque GSSAPI name handle.
pub(crate) enum GssNameStruct {}
pub(crate) type GssNameT = *mut GssNameStruct;

/// Opaque GSSAPI OID set handle.
pub(crate) enum GssOidSetStruct {}
pub(crate) type GssOidSetT = *mut GssOidSetStruct;

/// Variable-length byte buffer used for tokens and name strings.
#[repr(C)]
pub(crate) struct GssBufferDesc {
    pub length: usize,
    pub value: *mut c_void,
}

impl GssBufferDesc {
    /// A read-only view of `bytes`; it must outlive every call the result is passed to.
    pub(crate) fn borrowing(bytes: &[u8]) -> Self {
        Self {
            length: bytes.len(),
            // GSS-API never writes through an input buffer (RFC 2744 §2).
            value: bytes.as_ptr().cast_mut().cast(),
        }
    }
}

/// OID descriptor: a DER-encoded object identifier.
#[repr(C)]
pub(crate) struct GssOidDesc {
    pub length: c_uint,
    pub elements: *mut c_void,
}

/// One key-value pair in a credential store (RFC 5587 extension).
///
/// Credential stores are a MIT Kerberos extension; Heimdal has no equivalent,
/// so the whole `gss_*_from`/`gss_store_cred_into` family is MIT-only.
#[cfg(mit_kerberos)]
#[repr(C)]
pub(crate) struct GssKeyValueElementDesc {
    pub key: *const c_char,
    pub value: *const c_char,
}

/// Array of key-value pairs for `gss_acquire_cred_from()`.
#[cfg(mit_kerberos)]
#[repr(C)]
pub(crate) struct GssKeyValueSetDesc {
    pub count: OmUint32,
    pub elements: *mut GssKeyValueElementDesc,
}

// ── Constants ──────────────────────────────────────────────────────────────────

pub(crate) const GSS_S_COMPLETE: OmUint32 = 0;
pub(crate) const GSS_S_CONTINUE_NEEDED: OmUint32 = 1;

#[cfg(mit_kerberos)]
pub(crate) const GSS_C_ACCEPT: i32 = 2;

pub(crate) const GSS_C_NO_CONTEXT: GssCtxIdT = ptr::null_mut();
pub(crate) const GSS_C_NO_OID_SET: GssOidSetT = ptr::null_mut();

pub(crate) fn gss_c_no_buffer() -> GssBufferDesc {
    GssBufferDesc {
        length: 0,
        value: ptr::null_mut(),
    }
}

/// Usage flag: credential may be used by both an initiator (client) and acceptor (server).
#[cfg(mit_kerberos)]
pub(crate) const GSS_C_BOTH: i32 = 0;

/// Usage flag: credential may be used by an initiator (client).
pub(crate) const GSS_C_INITIATE: i32 = 1;

/// Status type: interpret `status_value` as a GSS-API major code.
pub(crate) const GSS_C_GSS_CODE: i32 = 1;
/// Status type: interpret `status_value` as a mechanism-specific minor code.
pub(crate) const GSS_C_MECH_CODE: i32 = 2;

/// Return flag: replay detection is active on this context (RFC 2744).
pub(crate) const GSS_C_REPLAY_FLAG: OmUint32 = 4;

/// Address family "unset" — used in channel bindings for non-IP endpoints.
pub(crate) const GSS_C_AF_UNSET: OmUint32 = 0;

/// `gss_channel_bindings_struct` (RFC 2744 Appendix B).
///
/// For tls-server-end-point channel bindings:
///   - `initiator/acceptor_addrtype` = `GSS_C_AF_UNSET`
///   - `initiator/acceptor_address`  = empty `GssBufferDesc`
///   - `application_data`            = the channel binding bytes
#[repr(C)]
pub(crate) struct GssChannelBindingsStruct {
    pub initiator_addrtype: OmUint32,
    pub initiator_address: GssBufferDesc,
    pub acceptor_addrtype: OmUint32,
    pub acceptor_address: GssBufferDesc,
    pub application_data: GssBufferDesc,
}

/// `prf_key` for `gss_pseudo_random`: the full key (RFC 4401 §2).
pub(crate) const GSS_C_PRF_KEY_FULL: c_int = 0;

// Kerberos V5 mechanism OID: 1.2.840.113554.1.2.2
static GSS_MECH_KRB5_OID_BYTES: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// OID descriptor for the Kerberos V5 mechanism itself (no SPNEGO).
pub(crate) fn gss_mech_krb5() -> GssOidDesc {
    GssOidDesc {
        length: 9,
        elements: GSS_MECH_KRB5_OID_BYTES.as_ptr().cast_mut().cast(),
    }
}

// NT_HOSTBASED_SERVICE OID: 1.3.6.1.5.6.2 (DER encoding: 2b 06 01 05 06 02)
static GSS_C_NT_HOSTBASED_SERVICE_OID_BYTES: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x06, 0x02];

// GSS_KRB5_NT_PRINCIPAL_NAME OID: 1.2.840.113554.1.2.2.1
// Accepts "user@REALM" Kerberos principal strings for gss_import_name.
static GSS_KRB5_NT_PRINCIPAL_NAME_OID_BYTES: [u8; 10] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01];

/// OID descriptor for `GSS_C_NT_HOSTBASED_SERVICE` (e.g. "HTTP@host").
///
/// The GSSAPI C API takes `*mut c_void` for the OID elements even though it
/// never writes through the pointer; casting from `*const` is safe here.
pub(crate) fn gss_c_nt_hostbased_service() -> GssOidDesc {
    GssOidDesc {
        length: 6,
        elements: GSS_C_NT_HOSTBASED_SERVICE_OID_BYTES
            .as_ptr()
            .cast_mut()
            .cast(),
    }
}

/// OID descriptor for `GSS_KRB5_NT_PRINCIPAL_NAME` (Kerberos principal, e.g. "user@REALM").
pub(crate) fn gss_krb5_nt_principal_name() -> GssOidDesc {
    GssOidDesc {
        length: 10,
        elements: GSS_KRB5_NT_PRINCIPAL_NAME_OID_BYTES
            .as_ptr()
            .cast_mut()
            .cast(),
    }
}

// ── libkrb5 opaque types ───────────────────────────────────────────────────────

pub(crate) enum Krb5ContextStruct {}
pub(crate) type Krb5Context = *mut Krb5ContextStruct;

#[cfg(heimdal_kerberos)] // only Heimdal gets a TGT from a keytab by hand
pub(crate) enum Krb5KeytabStruct {}
#[cfg(heimdal_kerberos)] // only Heimdal gets a TGT from a keytab by hand
pub(crate) type Krb5Keytab = *mut Krb5KeytabStruct;

pub(crate) enum Krb5CcacheStruct {}
pub(crate) type Krb5Ccache = *mut Krb5CcacheStruct;

pub(crate) enum Krb5PrincipalStruct {}
pub(crate) type Krb5Principal = *mut Krb5PrincipalStruct;

/// Opaque byte buffer standing in for `krb5_creds`.
///
/// Zeroed before every use; only passed to `krb5_get_init_creds_keytab`,
/// `krb5_cc_store_cred`, and `krb5_free_cred_contents` — we never inspect its
/// fields.  MIT Kerberos 1.21 measures 120 bytes, Heimdal 7.8 measures 144.
///
/// # Safety
///
/// The buffer size (256 bytes, `align(8)`) must be at least as large as the
/// real `krb5_creds` struct on all supported targets.  If either library
/// changes its ABI layout and the struct grows beyond 256 bytes, writing
/// through a `*mut Krb5Creds` pointer will silently overflow the buffer.
/// `build.rs` asserts `sizeof(krb5_creds) <= 256` against the header it
/// compiled against, on both vendors.
#[repr(C, align(8))]
pub(crate) struct Krb5Creds(pub [u8; 256]); // 256 ≥ 144, aligned to pointer size

impl Krb5Creds {
    /// A zeroed buffer, as every krb5 call that fills one expects.
    pub(crate) fn new() -> Self {
        Self([0u8; 256])
    }
}

impl Default for Krb5Creds {
    fn default() -> Self {
        Self::new()
    }
}

// ── libkrb5 extern functions ───────────────────────────────────────────────────

#[link(name = "krb5")]
unsafe extern "C" {
    #[cfg(heimdal_kerberos)] // only Heimdal gets a TGT from a keytab by hand
    pub(crate) fn krb5_init_context(context: *mut Krb5Context) -> c_int;
    pub(crate) fn krb5_free_context(context: Krb5Context);
    pub(crate) fn krb5_parse_name(
        context: Krb5Context,
        name: *const c_char,
        principal_out: *mut Krb5Principal,
    ) -> c_int;
    pub(crate) fn krb5_free_principal(context: Krb5Context, val: Krb5Principal);
    #[cfg(heimdal_kerberos)] // only Heimdal gets a TGT from a keytab by hand
    pub(crate) fn krb5_kt_resolve(
        context: Krb5Context,
        name: *const c_char,
        id: *mut Krb5Keytab,
    ) -> c_int;
    #[cfg(heimdal_kerberos)] // only Heimdal gets a TGT from a keytab by hand
    pub(crate) fn krb5_kt_close(context: Krb5Context, id: Krb5Keytab) -> c_int;
    pub(crate) fn krb5_cc_resolve(
        context: Krb5Context,
        name: *const c_char,
        cache: *mut Krb5Ccache,
    ) -> c_int;
    #[cfg(heimdal_kerberos)] // only Heimdal gets a TGT from a keytab by hand
    pub(crate) fn krb5_cc_initialize(
        context: Krb5Context,
        cache: Krb5Ccache,
        principal: Krb5Principal,
    ) -> c_int;
    pub(crate) fn krb5_cc_close(context: Krb5Context, cache: Krb5Ccache) -> c_int;
    #[cfg(heimdal_kerberos)] // only Heimdal gets a TGT from a keytab by hand
    pub(crate) fn krb5_get_init_creds_keytab(
        context: Krb5Context,
        creds: *mut Krb5Creds,
        client: Krb5Principal,
        arg_keytab: Krb5Keytab,
        start_time: Krb5Deltat,
        in_tkt_service: *const c_char,
        k5_gic_options: *mut c_void,
    ) -> c_int;
    #[cfg(heimdal_kerberos)] // only Heimdal gets a TGT from a keytab by hand
    pub(crate) fn krb5_cc_store_cred(
        context: Krb5Context,
        cache: Krb5Ccache,
        creds: *mut Krb5Creds,
    ) -> c_int;
    pub(crate) fn krb5_free_cred_contents(context: Krb5Context, val: *mut Krb5Creds);
    pub(crate) fn krb5_get_error_message(ctx: Krb5Context, code: c_int) -> *const c_char;
    pub(crate) fn krb5_free_error_message(ctx: Krb5Context, msg: *const c_char);

    pub(crate) fn krb5_cc_destroy(context: Krb5Context, cache: Krb5Ccache) -> c_int;
    pub(crate) fn krb5_get_init_creds_opt_alloc(
        context: Krb5Context,
        opt: *mut Krb5GetInitCredsOpt,
    ) -> c_int;
    pub(crate) fn krb5_get_init_creds_opt_free(context: Krb5Context, opt: Krb5GetInitCredsOpt);
    /// MIT's setter returns `errcode_t`; Heimdal's is `void`.
    #[cfg(mit_kerberos)]
    pub(crate) fn krb5_get_init_creds_opt_set_anonymous(
        opt: Krb5GetInitCredsOpt,
        anonymous: c_int,
    ) -> c_int;
    /// Drive an AS exchange with a password, prompting through `prompter`.
    /// MIT's convenience wrapper; Heimdal's step API collects the password
    /// with `krb5_init_creds_set_password` instead.
    #[cfg(mit_kerberos)]
    pub(crate) fn krb5_get_init_creds_password(
        context: Krb5Context,
        creds: *mut Krb5Creds,
        client: Krb5Principal,
        password: *const c_char,
        prompter: Option<Krb5PrompterFn>,
        data: *mut c_void,
        start_time: Krb5Deltat,
        in_tkt_service: *const c_char,
        k5_gic_options: Krb5GetInitCredsOpt,
    ) -> c_int;

}

/// `krb5_deltat`: MIT's is an `int`, Heimdal's a `time_t`.  `build.rs` checks
/// the width against `<krb5.h>`, so a mismatch is a build failure.
#[cfg(mit_kerberos)]
pub(crate) type Krb5Deltat = c_int;
#[cfg(heimdal_kerberos)]
pub(crate) type Krb5Deltat = c_long;

/// The length field of `krb5_data`: MIT's `magic`-bearing `krb5_data` counts
/// in `unsigned int`, Heimdal's `heim_octet_string` in `size_t`.
#[cfg(mit_kerberos)]
pub(crate) type Krb5DataLength = c_uint;
#[cfg(heimdal_kerberos)]
pub(crate) type Krb5DataLength = usize;

/// Opaque profile handle (`profile_t`), MIT's profile API.
#[cfg(mit_kerberos)]
pub(crate) enum ProfileStruct {}
#[cfg(mit_kerberos)]
pub(crate) type Profile = *mut ProfileStruct;

/// Opaque `krb5_get_init_creds_opt *`.
pub(crate) enum Krb5GetInitCredsOptStruct {}
pub(crate) type Krb5GetInitCredsOpt = *mut Krb5GetInitCredsOptStruct;

/// `KRB5_FAST_REQUIRED`: fail unless the KDC supports FAST.  MIT's FAST flags
/// only; Heimdal requires the armour whenever one is set.
#[cfg(mit_kerberos)]
pub(crate) const KRB5_FAST_REQUIRED: c_int = 1;

/// Length-prefixed byte buffer used by krb5 prompts (`krb5_data`).
///
/// MIT's carries a magic field and counts in `unsigned int`; Heimdal's is
/// `heim_octet_string`, with no magic and a `size_t` length.  Both are 16
/// bytes, with `length` and `data` in that order — asserted in `build.rs`
/// against the header of whichever library this build uses.
#[repr(C)]
pub(crate) struct Krb5Data {
    /// MIT's `krb5_data::magic`; Heimdal's buffer has no such field.
    #[cfg(mit_kerberos)]
    pub magic: c_int,
    pub length: Krb5DataLength,
    pub data: *mut c_char,
}

impl Krb5Data {
    /// A buffer view of `buf` whose `length` is its capacity: what a prompter
    /// callback expects on entry.  MIT wants the magic set; Heimdal reads the
    /// capacity straight out of `length`.  Only the prompter's test builds one.
    #[cfg(test)]
    pub(crate) fn from_buffer(buf: &mut [u8]) -> Self {
        Self {
            #[cfg(mit_kerberos)]
            magic: 0,
            length: Krb5DataLength::try_from(buf.len()).unwrap_or(Krb5DataLength::MAX),
            data: buf.as_mut_ptr().cast::<c_char>(),
        }
    }

    /// How many bytes the reply holds now, as the callback left it.
    pub(crate) fn reply_length(&self) -> usize {
        #[cfg(mit_kerberos)]
        {
            self.length as usize
        }
        #[cfg(heimdal_kerberos)]
        {
            self.length
        }
    }

    /// Record that `len` bytes of the reply were written, as the callback
    /// must on exit.
    pub(crate) fn set_reply_length(&mut self, len: usize) {
        #[cfg(mit_kerberos)]
        {
            self.length = Krb5DataLength::try_from(len).unwrap_or(Krb5DataLength::MAX);
        }
        #[cfg(heimdal_kerberos)]
        {
            self.length = len;
        }
    }
}

// ── MIT-only libkrb5 externs ─────────────────────────────────────────────────
//
// The profile API, the named-output-ccache and FAST-flag options, and the
// responder callbacks exist only in MIT Kerberos; Heimdal has no equivalent,
// so a Heimdal build must not reference them at all — the symbols are not in
// its libkrb5.
#[cfg(mit_kerberos)]
#[link(name = "krb5")]
unsafe extern "C" {
    pub(crate) fn profile_init_path(filepath: *const c_char, ret_profile: *mut Profile) -> c_long;
    pub(crate) fn profile_release(profile: Profile);
    pub(crate) fn krb5_init_context_profile(
        profile: Profile,
        flags: c_int,
        context: *mut Krb5Context,
    ) -> c_int;
    /// Write the AS reply to `ccache` rather than the caller's own handling.
    pub(crate) fn krb5_get_init_creds_opt_set_out_ccache(
        context: Krb5Context,
        opt: Krb5GetInitCredsOpt,
        ccache: Krb5Ccache,
    ) -> c_int;
    /// Armour the exchange with the ticket in `ccache`.
    pub(crate) fn krb5_get_init_creds_opt_set_fast_ccache(
        context: Krb5Context,
        opt: Krb5GetInitCredsOpt,
        ccache: Krb5Ccache,
    ) -> c_int;
    pub(crate) fn krb5_get_init_creds_opt_set_fast_flags(
        context: Krb5Context,
        opt: Krb5GetInitCredsOpt,
        flags: c_int,
    ) -> c_int;

    // ── Responder API (MIT Kerberos 1.11 and later) ──────────────────────────
    //
    // Client pre-authentication modules — the OTP plugin, the PKINIT plugin,
    // an installed passkey or IdP plugin — put named questions into a
    // responder context that a registered responder callback answers.

    /// Register `responder`, with `data` as its callback argument, on `opt`.
    pub(crate) fn krb5_get_init_creds_opt_set_responder(
        context: Krb5Context,
        opt: Krb5GetInitCredsOpt,
        responder: Option<Krb5ResponderFn>,
        data: *mut c_void,
    ) -> c_int;
    /// The NULL-terminated question names in `rctx`, an alias into it.
    pub(crate) fn krb5_responder_list_questions(
        context: Krb5Context,
        rctx: Krb5ResponderContext,
    ) -> *const *const c_char;
    /// The challenge of `question` in `rctx`, an alias into it, or null.
    pub(crate) fn krb5_responder_get_challenge(
        context: Krb5Context,
        rctx: Krb5ResponderContext,
        question: *const c_char,
    ) -> *const c_char;
    /// Answer `question` in `rctx`; both strings are printable UTF-8.  A null
    /// `answer` hands the question back to the module that asked it, which
    /// then collects the answer through the prompter callback.
    pub(crate) fn krb5_responder_set_answer(
        context: Krb5Context,
        rctx: Krb5ResponderContext,
        question: *const c_char,
        answer: *const c_char,
    ) -> c_int;
    /// Decode the OTP question; free the result with
    /// `krb5_responder_otp_challenge_free`.
    pub(crate) fn krb5_responder_otp_get_challenge(
        context: Krb5Context,
        rctx: Krb5ResponderContext,
        chl: *mut *mut Krb5OtpChallenge,
    ) -> c_int;
    /// Answer the OTP question with the value and PIN of token `ti`; either
    /// may be null when it is not collected.
    pub(crate) fn krb5_responder_otp_set_answer(
        context: Krb5Context,
        rctx: Krb5ResponderContext,
        ti: usize,
        value: *const c_char,
        pin: *const c_char,
    ) -> c_int;
    /// Free what `krb5_responder_otp_get_challenge` returned.
    pub(crate) fn krb5_responder_otp_challenge_free(
        context: Krb5Context,
        rctx: Krb5ResponderContext,
        chl: *mut Krb5OtpChallenge,
    );
}

/// Opaque `krb5_responder_context` (MIT Kerberos 1.11 and later).
#[cfg(mit_kerberos)]
pub(crate) enum Krb5ResponderContextStruct {}
#[cfg(mit_kerberos)]
pub(crate) type Krb5ResponderContext = *mut Krb5ResponderContextStruct;

/// `krb5_responder_otp_tokeninfo` — one token the KDC offered.  `build.rs`
/// checks this layout against `<krb5.h>` at compile time.
#[cfg(mit_kerberos)]
#[repr(C)]
pub(crate) struct Krb5OtpTokenInfo {
    /// Which answers the token needs: the flags below, `ORed`.
    pub flags: c_int,
    /// The token's format, or -1 when unspecified.
    pub format: c_int,
    /// The token's length, or -1 when unspecified.
    pub length: c_int,
    /// Who issued the token; may be a URL to enrol with.
    pub vendor: *const c_char,
    /// What the user should do; may be a URL to enrol with.
    pub challenge: *const c_char,
    /// The token's serial.
    pub token_id: *const c_char,
    /// The algorithm it runs.
    pub alg_id: *const c_char,
}

/// `krb5_responder_otp_challenge` — the token(s) offered for an OTP.
#[cfg(mit_kerberos)]
#[repr(C)]
pub(crate) struct Krb5OtpChallenge {
    /// The service that verifies the OTP, e.g. FreeIPA's `otp` service.
    pub service: *const c_char,
    /// The tokens, NULL-terminated.
    pub tokeninfo: *mut *mut Krb5OtpTokenInfo,
}

/// `krb5_prompt` — one entry the prompter callback fills in.
///
/// Heimdal adds a prompt-type field after `reply`; MIT's entry is three
/// fields, so the mirror carries the extra word only in a Heimdal build
/// (`build.rs` checks the size of both).
#[repr(C)]
pub(crate) struct Krb5Prompt {
    /// What to ask the user for.
    pub prompt: *const c_char,
    /// Non-zero when the answer is a secret and echo must stay off.
    pub hidden: c_int,
    /// The caller-allocated answer buffer: `length` is its capacity on entry
    /// and the number of bytes written on exit.
    pub reply: *mut Krb5Data,
    /// `krb5_prompt_type`: `KRB5_PROMPT_TYPE_PASSWORD` for a secret,
    /// `KRB5_PROMPT_TYPE_PREAUTH` otherwise.  MIT has no such field.
    #[cfg(heimdal_kerberos)]
    pub kind: c_int,
}

// Heimdal's `krb5_prompt_type`, the values of [`Krb5Prompt::kind`].  MIT's
// prompt struct carries no type field, and only [`Krb5Prompt::new`], which
// the prompter's test uses, names these.
#[cfg(heimdal_kerberos)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const KRB5_PROMPT_TYPE_PASSWORD: c_int = 0x1;
#[cfg(heimdal_kerberos)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const KRB5_PROMPT_TYPE_PREAUTH: c_int = 0x4;

impl Krb5Prompt {
    /// An entry asking for `label`, whose answer goes into `reply`.  A hidden
    /// prompt is a password, which is how Heimdal marks a secret answer as
    /// distinct from an interactive one.  Only the prompter's test builds a
    /// prompt; the library hands kuipa its own.
    #[cfg(test)]
    pub(crate) fn new(label: &CStr, hidden: bool, reply: &mut Krb5Data) -> Self {
        Self {
            prompt: label.as_ptr(),
            hidden: c_int::from(hidden),
            reply: &raw mut *reply,
            #[cfg(heimdal_kerberos)]
            kind: {
                if hidden {
                    KRB5_PROMPT_TYPE_PASSWORD
                } else {
                    KRB5_PROMPT_TYPE_PREAUTH
                }
            },
        }
    }
}

/// `krb5_prompter_fct`.
pub(crate) type Krb5PrompterFn = unsafe extern "C" fn(
    context: Krb5Context,
    data: *mut c_void,
    name: *const c_char,
    banner: *const c_char,
    num_prompts: c_int,
    prompts: *mut Krb5Prompt,
) -> c_int;

/// `krb5_responder_fn`.
#[cfg(mit_kerberos)]
pub(crate) type Krb5ResponderFn = unsafe extern "C" fn(
    context: Krb5Context,
    data: *mut c_void,
    rctx: Krb5ResponderContext,
) -> c_int;

/// `KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN`: ask for the token's value.
#[cfg(mit_kerberos)]
pub(crate) const KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN: c_int = 0x0001;
/// `KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN`: ask for a PIN as well.
#[cfg(mit_kerberos)]
pub(crate) const KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN: c_int = 0x0002;
/// `KRB5_RESPONDER_OTP_FLAGS_SEPARATE_PIN`: return the PIN on its own rather
/// than concatenated with the value.
#[cfg(mit_kerberos)]
pub(crate) const KRB5_RESPONDER_OTP_FLAGS_SEPARATE_PIN: c_int = 0x0008;

// ── MIT-only GSSAPI externs ──────────────────────────────────────────────────
//
// Credential stores, S4U2Self and thread-local ccaches are MIT extensions:
// Heimdal has none of them, so a Heimdal build must not reference them.
#[cfg(mit_kerberos)]
unsafe extern "C" {
    /// Acquire an initiator credential that impersonates `desired_name` (S4U2Self).
    ///
    /// `impersonator_cred_handle` must be an initiator (`GSS_C_INITIATE` or
    /// `GSS_C_BOTH`) credential for the HTTP service.  MIT Kerberos uses it to
    /// obtain a Kerberos TGT (via the keytab it refers to) and then issues a
    /// service-for-user (S4U2Self) ticket.  The returned credential can be used
    /// with `gss_init_sec_context` to request service tickets on behalf of the
    /// user (S4U2Proxy), subject to the KDC's constrained-delegation policy.
    pub(crate) fn gss_acquire_cred_impersonate_name(
        minor_status: *mut OmUint32,
        impersonator_cred_handle: GssCredIdT,
        desired_name: GssNameT,
        time_req: OmUint32,
        desired_mechs: GssOidSetT,
        cred_usage: i32,
        output_cred_handle: *mut GssCredIdT,
        actual_mechs: *mut GssOidSetT,
        time_rec: *mut OmUint32,
    ) -> OmUint32;
}

// ── Heimdal-only libkrb5 and GSSAPI externs ──────────────────────────────────
//
// Heimdal has no credential stores, so the equivalents of kuipa's MIT paths
// go through the step-by-step init-creds API and `gss_krb5_import_cred`.
/// `KRB5_GIC_OPT_PKINIT_ANONYMOUS`: authenticate the armour with PKINIT but
/// not as a user, so the AS reply carries no user identity.  Heimdal's flag
/// value; MIT's headers spell no PKINIT flags.
#[cfg(heimdal_kerberos)]
pub(crate) const KRB5_GIC_OPT_PKINIT_ANONYMOUS: c_int = 4;

/// Opaque `krb5_init_creds_context *`.
#[cfg(heimdal_kerberos)]
pub(crate) enum Krb5InitCredsContextStruct {}
#[cfg(heimdal_kerberos)]
pub(crate) type Krb5InitCredsContext = *mut Krb5InitCredsContextStruct;

/// `krb5_keytab_entry` — one keytab entry.  Only `principal` is read; the
/// rest is padding to the size `build.rs` checks against `<krb5.h>`, so a
/// library-side layout change fails the build instead of misreading a key.
#[cfg(heimdal_kerberos)]
#[repr(C)]
pub(crate) struct Krb5KtEntry {
    pub principal: Krb5Principal,
    /// `krb5_kvno`, an `int32_t` followed by the `krb5_keyblock` it aligns to.
    pub vno: i32,
    _rest: [u8; 44],
}

#[cfg(heimdal_kerberos)]
impl Krb5KtEntry {
    /// A zeroed entry for `krb5_kt_next_entry` to fill; the padding needs no
    /// value because the library writes the whole struct.
    pub(crate) fn new() -> Self {
        Self {
            principal: ptr::null_mut(),
            vno: 0,
            _rest: [0u8; 44],
        }
    }
}

/// `krb5_kt_cursor` — a keytab iteration position, opaque here.
#[cfg(heimdal_kerberos)]
#[repr(C)]
pub(crate) struct Krb5KtCursor(pub [u8; 24]);

#[cfg(heimdal_kerberos)]
impl Krb5KtCursor {
    /// A zeroed cursor, as `krb5_kt_start_seq_get` expects.
    pub(crate) fn new() -> Self {
        Self([0u8; 24])
    }
}

#[cfg(heimdal_kerberos)]
impl Default for Krb5KtCursor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(heimdal_kerberos)]
impl Default for Krb5KtEntry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(heimdal_kerberos)]
#[link(name = "krb5")]
unsafe extern "C" {
    /// Read `filenames`, a NULL-terminated array, as the whole configuration,
    /// replacing what the context loaded from the environment.
    pub(crate) fn krb5_set_config_files(context: Krb5Context, filenames: *mut *mut c_char)
    -> c_int;

    /// `krb5_init_creds_context`: one AS exchange, driven step by step.
    pub(crate) fn krb5_init_creds_init(
        context: Krb5Context,
        client: Krb5Principal,
        prompter: Option<Krb5PrompterFn>,
        prompter_data: *mut c_void,
        start_time: Krb5Deltat,
        options: Krb5GetInitCredsOpt,
        rctx: *mut Krb5InitCredsContext,
    ) -> c_int;
    /// Run the exchange `rctx` describes, prompts included.
    pub(crate) fn krb5_init_creds_get(context: Krb5Context, rctx: Krb5InitCredsContext) -> c_int;
    /// Store the credentials `rctx` obtained; requires `krb5_init_creds_get`
    /// to have completed first.
    pub(crate) fn krb5_init_creds_store(
        context: Krb5Context,
        rctx: Krb5InitCredsContext,
        id: Krb5Ccache,
    ) -> c_int;
    pub(crate) fn krb5_init_creds_free(context: Krb5Context, rctx: Krb5InitCredsContext);
    /// The long-term password for the exchange.  The step API never prompts
    /// for one itself, unlike `krb5_get_init_creds_password`.
    pub(crate) fn krb5_init_creds_set_password(
        context: Krb5Context,
        rctx: Krb5InitCredsContext,
        password: *const c_char,
    ) -> c_int;
    pub(crate) fn krb5_init_creds_set_service(
        context: Krb5Context,
        rctx: Krb5InitCredsContext,
        service: *const c_char,
    ) -> c_int;
    /// Armour the exchange with the ticket in `fast_ccache`; Heimdal requires
    /// FAST once an armour is set.
    pub(crate) fn krb5_init_creds_set_fast_ccache(
        context: Krb5Context,
        rctx: Krb5InitCredsContext,
        fast_ccache: Krb5Ccache,
    ) -> c_int;

    /// PKINIT for `principal`.  Null `user_id` presents no client identity,
    /// which is what an anonymous exchange wants; null `x509_anchors`,
    /// `pool` and `pki_revoke` leave Heimdal to read the realm's
    /// `pkinit_anchors` and the `appdefaults` pool itself.
    pub(crate) fn krb5_get_init_creds_opt_set_pkinit(
        context: Krb5Context,
        opt: Krb5GetInitCredsOpt,
        principal: Krb5Principal,
        user_id: *const c_char,
        x509_anchors: *const c_char,
        pool: *const *const c_char,
        pki_revoke: *const *const c_char,
        flags: c_int,
        prompter: Option<Krb5PrompterFn>,
        prompter_data: *mut c_void,
        password: *mut c_char,
    ) -> c_int;

    /// The printable name of `principal`, allocated by the library.
    pub(crate) fn krb5_unparse_name(
        context: Krb5Context,
        principal: Krb5Principal,
        name: *mut *mut c_char,
    ) -> c_int;
    /// Free what `krb5_unparse_name` returned — the only way to free it,
    /// however much Heimdal marks the pair deprecated.
    pub(crate) fn krb5_free_unparsed_name(context: Krb5Context, name: *mut c_char);

    /// Walk the entries of `id`; used to find a principal when the caller
    /// named none.
    pub(crate) fn krb5_kt_start_seq_get(
        context: Krb5Context,
        id: Krb5Keytab,
        cursor: *mut Krb5KtCursor,
    ) -> c_int;
    pub(crate) fn krb5_kt_next_entry(
        context: Krb5Context,
        id: Krb5Keytab,
        entry: *mut Krb5KtEntry,
        cursor: *mut Krb5KtCursor,
    ) -> c_int;
    pub(crate) fn krb5_kt_end_seq_get(
        context: Krb5Context,
        id: Krb5Keytab,
        cursor: *mut Krb5KtCursor,
    ) -> c_int;
    /// Free the contents of an entry `krb5_kt_next_entry` filled.
    pub(crate) fn krb5_kt_free_entry(context: Krb5Context, entry: *mut Krb5KtEntry);
}

// The pieces of Heimdal's init-creds plumbing that have no MIT counterpart
// with the same meaning: the default-flag helper `kinit` applies, the
// `void` anonymous setter, the short lifetime for an armour ticket, and the
// last-request report.
#[cfg(heimdal_kerberos)]
#[link(name = "krb5")]
unsafe extern "C" {
    /// Apply the configuration's default init-creds flags to `opt`.  Only
    /// `krb5_init_creds_init` given no options applies them itself, so kuipa
    /// has to, exactly as `kinit` does.
    pub(crate) fn krb5_get_init_creds_opt_set_default_flags(
        context: Krb5Context,
        appname: *const c_char,
        realm: *const c_char,
        opt: Krb5GetInitCredsOpt,
    );
    /// Heimdal's anonymous flag; MIT's setter of the same name returns a code.
    pub(crate) fn krb5_get_init_creds_opt_set_anonymous(opt: Krb5GetInitCredsOpt, anonymous: c_int);
    /// How long the ticket is to live.  Both vendors have this, but only the
    /// Heimdal armour needs it; MIT takes the lifetime from the options of
    /// its one-call exchange.
    pub(crate) fn krb5_get_init_creds_opt_set_tkt_life(
        opt: Krb5GetInitCredsOpt,
        tkt_life: Krb5Deltat,
    );
    /// Report, through the exchange's prompter, the text the KDC sent back in
    /// its last reply.  `kinit` calls this once the exchange succeeded.
    pub(crate) fn krb5_process_last_request(
        context: Krb5Context,
        opt: Krb5GetInitCredsOpt,
        rctx: Krb5InitCredsContext,
    ) -> c_int;
}

#[cfg(heimdal_kerberos)]
unsafe extern "C" {
    /// Acquire a credential for `desired_name` from the default ccache or
    /// keytab — with no credential store, the only way in on a plain name.
    pub(crate) fn gss_acquire_cred(
        minor_status: *mut OmUint32,
        desired_name: GssNameT,
        time_req: OmUint32,
        desired_mechs: GssOidSetT,
        cred_usage: i32,
        output_cred_handle: *mut GssCredIdT,
        actual_mechs: *mut GssOidSetT,
        time_rec: *mut OmUint32,
    ) -> OmUint32;

    /// Build a credential from a live ccache and/or keytab handle: the
    /// initiator form takes the TGT from `ccache`, the acceptor form from
    /// `keytab`, and both together give a credential of either usage.
    pub(crate) fn gss_krb5_import_cred(
        minor_status: *mut OmUint32,
        ccache: Krb5Ccache,
        keytab_principal: Krb5Principal,
        keytab: Krb5Keytab,
        out: *mut GssCredIdT,
    ) -> OmUint32;
}

// ── GSSAPI extern functions ────────────────────────────────────────────────────

unsafe extern "C" {
    /// Parse a host-based service name string into a `GssNameT`.
    pub(crate) fn gss_import_name(
        minor_status: *mut OmUint32,
        input_name_buffer: *const GssBufferDesc,
        input_name_type: *const GssOidDesc,
        output_name: *mut GssNameT,
    ) -> OmUint32;

    /// Acquire server credentials from a credential store (RFC 5587).
    /// Pass a `GssKeyValueSetDesc` with `{"keytab", "/path"}` to select the keytab.
    #[cfg(mit_kerberos)]
    pub(crate) fn gss_acquire_cred_from(
        minor_status: *mut OmUint32,
        desired_name: GssNameT,
        time_req: OmUint32,
        desired_mechs: GssOidSetT,
        cred_usage: i32,
        cred_store: *const GssKeyValueSetDesc,
        output_cred_handle: *mut GssCredIdT,
        actual_mechs: *mut GssOidSetT,
        time_rec: *mut OmUint32,
    ) -> OmUint32;

    /// Process one client SPNEGO/Kerberos token on the server side.
    pub(crate) fn gss_accept_sec_context(
        minor_status: *mut OmUint32,
        context_handle: *mut GssCtxIdT,
        acceptor_cred_handle: GssCredIdT,
        input_token_buffer: *const GssBufferDesc,
        input_chan_bindings: *const GssChannelBindingsStruct,
        src_name: *mut GssNameT,
        mech_type: *mut *mut GssOidDesc,
        output_token: *mut GssBufferDesc,
        ret_flags: *mut OmUint32,
        time_rec: *mut OmUint32,
        delegated_cred_handle: *mut GssCredIdT,
    ) -> OmUint32;

    /// Convert a `GssNameT` to a human-readable string (e.g. "user@REALM").
    pub(crate) fn gss_display_name(
        minor_status: *mut OmUint32,
        input_name: GssNameT,
        output_name_buffer: *mut GssBufferDesc,
        output_name_type: *mut *mut GssOidDesc,
    ) -> OmUint32;

    /// Release a name handle.
    pub(crate) fn gss_release_name(minor_status: *mut OmUint32, name: *mut GssNameT) -> OmUint32;

    /// Release a buffer allocated by GSSAPI.
    pub(crate) fn gss_release_buffer(
        minor_status: *mut OmUint32,
        buffer: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Release a credential handle.
    pub(crate) fn gss_release_cred(
        minor_status: *mut OmUint32,
        cred_handle: *mut GssCredIdT,
    ) -> OmUint32;

    /// Delete a security context, releasing all associated state.
    pub(crate) fn gss_delete_sec_context(
        minor_status: *mut OmUint32,
        context_handle: *mut GssCtxIdT,
        output_token: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Release an OID set (e.g. from `gss_acquire_cred_from` `actual_mechs` output).
    #[cfg(mit_kerberos)]
    pub(crate) fn gss_release_oid_set(
        minor_status: *mut OmUint32,
        set: *mut GssOidSetT,
    ) -> OmUint32;

    /// Convert a major or minor status code to a human-readable string.
    pub(crate) fn gss_display_status(
        minor_status: *mut OmUint32,
        status_value: OmUint32,
        status_type: i32,
        mech_type: *const GssOidDesc,
        message_context: *mut OmUint32,
        status_string: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Return information about an existing credential: the associated name, remaining
    /// lifetime, usage flags, and supported mechanisms.  Pass `ptr::null_mut()` for
    /// outputs you do not need.
    pub(crate) fn gss_inquire_cred(
        minor_status: *mut OmUint32,
        cred_handle: GssCredIdT,
        name: *mut GssNameT,
        lifetime: *mut OmUint32,
        cred_usage: *mut i32,
        mechanisms: *mut GssOidSetT,
    ) -> OmUint32;

    /// Derive `desired_output_len` bytes from an established context's key
    /// (RFC 4401): both peers get the same output for the same input.
    pub(crate) fn gss_pseudo_random(
        minor_status: *mut OmUint32,
        context_handle: GssCtxIdT,
        prf_key: c_int,
        prf_in: *const GssBufferDesc,
        desired_output_len: isize,
        prf_out: *mut GssBufferDesc,
    ) -> OmUint32;

    /// Initiate a security context (client side); produces the outbound SPNEGO token.
    pub(crate) fn gss_init_sec_context(
        minor_status: *mut OmUint32,
        initiator_cred_handle: GssCredIdT,
        context_handle: *mut GssCtxIdT,
        target_name: GssNameT,
        mech_type: *const GssOidDesc,
        req_flags: OmUint32,
        time_req: OmUint32,
        input_chan_bindings: *const GssChannelBindingsStruct,
        input_token: *const GssBufferDesc,
        actual_mech_type: *mut *mut GssOidDesc,
        output_token: *mut GssBufferDesc,
        ret_flags: *mut OmUint32,
        time_rec: *mut OmUint32,
    ) -> OmUint32;

}
