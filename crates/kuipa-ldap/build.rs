use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Probe for the OpenLDAP client library via pkg-config first.
    // Fall back to hardcoded link directives if pkg-config is unavailable.
    if pkg_config::probe_library("ldap").is_ok() {
        // pkg-config already emitted `-lldap`/`-llber` and their search paths;
        // the private dependencies below are what OpenLDAP itself needs.
        link_sasl_and_krb5();
        return;
    }
    // Nothing pkg-config-visible: name the libraries, and point the linker at
    // the keg-only installs (Homebrew) so the names resolve to OpenLDAP rather
    // than the macOS SDK's own stubs, which lack `ldap_sasl_interactive_bind`.
    emit_keg_search("openldap", "libldap");
    println!("cargo:rustc-link-lib=ldap");
    println!("cargo:rustc-link-lib=lber");
    link_sasl_and_krb5();
}

/// The SASL/Kerberos half of the link line.
///
/// This crate calls only `ldap_sasl_bind` / `ldap_sasl_interactive_bind`: it
/// names no Kerberos or GSSAPI symbol itself, and the SASL GSSAPI mechanism is
/// loaded by libsasl2 at bind time.  So it must link the *same* Kerberos
/// implementation `kuipa-gssapi` was built against — the credentials handed to
/// `ldap_sasl_interactive_bind` come from that library, and a process holding
/// two Kerberos implementations hands one library's credentials to the other's
/// mechanism.  The vendor comes from kuipa-gssapi's build script through the
/// `links` metadata, so there is a single detection site (`DEP_KRB5_VENDOR`).
fn link_sasl_and_krb5() {
    println!("cargo:rustc-link-lib=sasl2");
    match std::env::var("DEP_KRB5_VENDOR").ok().as_deref() {
        Some("mit") => link_krb5("krb5", "libgssapi_krb5", "gssapi_krb5"),
        Some("heimdal") => {
            // Heimdal's GSSAPI lives in `libgssapi`, and its Kerberos core is a
            // separate `libkrb5`; `heimdal-gssapi.pc` lists only the former.
            link_krb5("heimdal", "libgssapi", "gssapi");
            link_krb5("heimdal", "libkrb5", "krb5");
        }
        // A platform with no Homebrew kegs and no `links` metadata yet: name
        // the MIT library, which is what every distro puts on the linker path
        // and what kuipa-gssapi falls back to when it cannot detect either.
        _ => println!("cargo:rustc-link-lib=gssapi_krb5"),
    }
}

/// Point the linker at `formula`'s keg for `stem`, then name the library.
fn link_krb5(formula: &str, stem: &str, name: &str) {
    emit_keg_search(formula, stem);
    println!("cargo:rustc-link-lib={name}");
}

/// Add the keg directory holding `stem` to the linker search path, if there is
/// one.
fn emit_keg_search(formula: &str, stem: &str) {
    for prefix in keg_prefixes(formula) {
        let lib = prefix.join("lib");
        if has_library(&lib, stem) {
            emit_search(&lib);
            return;
        }
    }
}

fn emit_search(path: &Path) {
    println!("cargo:rustc-link-search=native={}", path.display());
}

/// `brew --prefix <formula>`, if brew is installed and the formula is; then the
/// standard Homebrew keg locations, for the case where brew itself is absent.
///
/// Homebrew refuses to symlink these formulae into the normal prefix because
/// macOS ships its own (Heimdal) copy, so neither is on PATH or in
/// `PKG_CONFIG_PATH`.
fn keg_prefixes(formula: &str) -> Vec<PathBuf> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    brew_prefix(formula)
        .into_iter()
        .chain([
            PathBuf::from("/opt/homebrew/opt").join(formula),
            PathBuf::from("/usr/local/opt").join(formula),
        ])
        .collect()
}

fn brew_prefix(formula: &str) -> Option<PathBuf> {
    let out = Command::new("brew")
        .arg("--prefix")
        .arg(formula)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let prefix = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!prefix.is_empty()).then_some(PathBuf::from(prefix))
}

/// Whether `dir` holds any build of `stem` (shared, static, or versioned).
fn has_library(dir: &Path, stem: &str) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(stem))
    })
}
