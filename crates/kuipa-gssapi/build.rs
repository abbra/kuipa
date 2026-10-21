fn main() {
    // Declare the cfg flag so rustc knows it is intentional (suppresses
    // the `unexpected_cfg` lint when compiling the crate).
    println!("cargo::rustc-check-cfg=cfg(mit_kerberos)");

    // Probe for the MIT Kerberos GSSAPI library via pkg-config first.
    // The canonical Fedora pkg-config name is "krb5-gssapi"; Debian/Ubuntu use "mit-krb5-gssapi".
    // Fall back to a hardcoded link directive if pkg-config is unavailable (e.g. cross-compile).
    if pkg_config::probe_library("krb5-gssapi")
        .or_else(|_| pkg_config::probe_library("mit-krb5-gssapi"))
        .is_err()
    {
        // The canonical MIT Kerberos shared library name — used when pkg-config is absent.
        println!("cargo:rustc-link-lib=gssapi_krb5");
    }
    // All three paths above resolve to MIT Kerberos; emit the cfg so that the
    // unsafe Sync impl (only sound with MIT Kerberos) is conditionally compiled.
    println!("cargo:rustc-cfg=mit_kerberos");

    // Verify that the opaque Krb5Creds buffer (128 bytes) is large enough for
    // the real krb5_creds struct on this target. Compile a small C program that
    // static_asserts the size; if the assertion fails the build breaks with a
    // clear error instead of silently corrupting the stack at runtime.
    check_krb5_layouts();
}

fn check_krb5_layouts() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let src_path = format!("{out_dir}/check_krb5_layouts.c");
    std::fs::write(
        &src_path,
        r#"
#include <krb5.h>

_Static_assert(sizeof(krb5_creds) <= 128,
    "krb5_creds exceeds 128 bytes — update Krb5Creds in ffi.rs");

/* The responder and prompter structures mirrored in ffi.rs are read field by
   field, so their layouts have to match the library's exactly. */
_Static_assert(sizeof(krb5_responder_otp_tokeninfo) == 48,
    "krb5_responder_otp_tokeninfo is not 48 bytes — update Krb5OtpTokenInfo in ffi.rs");
_Static_assert(offsetof(krb5_responder_otp_tokeninfo, vendor) == 16,
    "krb5_responder_otp_tokeninfo::vendor moved — update Krb5OtpTokenInfo in ffi.rs");
_Static_assert(offsetof(krb5_responder_otp_tokeninfo, alg_id) == 40,
    "krb5_responder_otp_tokeninfo::alg_id moved — update Krb5OtpTokenInfo in ffi.rs");
_Static_assert(sizeof(krb5_responder_otp_challenge) == 16,
    "krb5_responder_otp_challenge is not 16 bytes — update Krb5OtpChallenge in ffi.rs");
_Static_assert(sizeof(krb5_prompt) == 24,
    "krb5_prompt is not 24 bytes — update Krb5Prompt in ffi.rs");
_Static_assert(offsetof(krb5_prompt, reply) == 16,
    "krb5_prompt::reply moved — update Krb5Prompt in ffi.rs");
_Static_assert(sizeof(krb5_data) == 16,
    "krb5_data is not 16 bytes — update Krb5Data in ffi.rs");
int main(void) { return 0; }
"#,
    )
    .expect("write size-check C source");

    let bin_path = format!("{out_dir}/check_krb5_layouts");
    let status = std::process::Command::new("cc")
        .args([&src_path, "-o", &bin_path, "-lkrb5"])
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => panic!(
            "the krb5 layout check failed (exit {}). \
             A structure mirrored in ffi.rs no longer matches <krb5.h> on this target.",
            s.code().unwrap_or(-1)
        ),
        Err(e) => {
            // If the C compiler is unavailable (e.g. cross-compile), warn but
            // don't block the build — the 128-byte buffer has margin.
            println!("cargo:warning=could not run the krb5 layout check: {e}");
        }
    }
}
