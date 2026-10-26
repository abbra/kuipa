use std::path::{Path, PathBuf};
use std::process::Command;

/// Which Kerberos implementation the crate is compiled against.
///
/// MIT and Heimdal disagree on `krb5_data`, `krb5_prompt` and `krb5_creds`
/// layouts, and MIT has a set of GSSAPI/libkrb5 extensions Heimdal lacks
/// (`gss_acquire_cred_from`, S4U2Self, the responder API, thread-local
/// ccaches).  The chosen vendor is exported as exactly one cfg —
/// `mit_kerberos` or `heimdal_kerberos` — and the crate's FFI mirrors and
/// credential paths are gated on it.
#[derive(Copy, Clone, Default, PartialEq, Eq)]
enum Vendor {
    #[default]
    Mit,
    Heimdal,
}

impl Vendor {
    fn cfg(self) -> &'static str {
        match self {
            Vendor::Mit => "mit_kerberos",
            Vendor::Heimdal => "heimdal_kerberos",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Vendor::Mit => "MIT Kerberos",
            Vendor::Heimdal => "Heimdal",
        }
    }

    /// Homebrew formula name, for the keg-only fallback scan.
    fn formula(self) -> &'static str {
        match self {
            Vendor::Mit => "krb5",
            Vendor::Heimdal => "heimdal",
        }
    }
}

/// How to compile and link against one Kerberos installation.
#[derive(Default)]
struct Krb5Install {
    vendor: Vendor,
    /// Include directories, passed as `-isystem` so they take precedence over
    /// the SDK's own copy of <krb5.h> (see `check_krb5_layouts`).
    include_paths: Vec<PathBuf>,
    /// Linker words (`-L…`, `-l…`) exactly as the discovery tool gave them.
    lflags: Vec<String>,
}

fn main() {
    // Declare the cfg flags so rustc knows they are intentional (suppresses
    // the `unexpected_cfg` lint when compiling the crate).
    // Switching `KUIPA_KRB5_VENDOR` must re-run detection, not reuse a cached
    // vendor choice from a previous build.
    println!("cargo::rerun-if-env-changed=KUIPA_KRB5_VENDOR");
    println!("cargo::rustc-check-cfg=cfg(mit_kerberos)");
    println!("cargo::rustc-check-cfg=cfg(heimdal_kerberos)");

    let requested = requested_vendor();
    let install = detect_krb5(requested);
    println!("cargo:rustc-cfg={}", install.vendor.cfg());
    // Discoverable in `cargo metadata` output; cargo ignores unknown keys.
    println!("cargo:krb5-vendor={}", install.vendor.label());

    // Verify that the structures mirrored in ffi.rs match the real ones on
    // this target. Compile a small C program that static_asserts each one; if
    // an assertion fails the build breaks with a clear error instead of
    // corrupting memory at runtime.
    check_krb5_layouts(&install);
}

/// `KUIPA_KRB5_VENDOR=mit|heimdal`, or None for auto-detection.  An unknown
/// value is a build error rather than a silently ignored request.
fn requested_vendor() -> Option<Vendor> {
    let raw = std::env::var("KUIPA_KRB5_VENDOR").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "auto" {
        return None;
    }
    let vendor = match trimmed.to_ascii_lowercase().as_str() {
        "mit" | "mit-krb5" | "krb5" | "massachusetts" => Vendor::Mit,
        "heimdal" => Vendor::Heimdal,
        _ => panic!(
            "KUIPA_KRB5_VENDOR={raw:?} is not a known vendor \
             (expected `mit`, `heimdal` or `auto`)"
        ),
    };
    Some(vendor)
}

/// Find the Kerberos installation to build against, honouring `requested` when
/// the caller named a vendor.
fn detect_krb5(requested: Option<Vendor>) -> Krb5Install {
    if let Some(install) = krb5_via_pkg_config(requested) {
        // The probe printed the link directives itself.
        return install;
    }
    let install = krb5_via_config_tool(requested)
        .or_else(|| krb5_via_keg_prefix(requested))
        .unwrap_or_else(|| {
            // A named vendor that nothing on this machine provides: fail with
            // the reason instead of compiling against the other one.
            if let Some(vendor) = requested {
                panic!(
                    "KUIPA_KRB5_VENDOR={} but no {} installation was found \
                     (pkg-config, krb5-config and the Homebrew kegs were all checked)",
                    vendor.label(),
                    vendor.label()
                );
            }
            // Nothing knows where krb5 lives — a cross-compile toolchain
            // locates it on its own, and Linux distros put MIT krb5 on the
            // default search path.
            println!("cargo:rustc-link-lib=gssapi_krb5");
            Krb5Install {
                vendor: Vendor::Mit,
                include_paths: Vec::new(),
                lflags: Vec::new(),
            }
        });
    install.print_link_metadata();
    install
}

/// The layout check for the vendor we chose: MIT asserts the responder and
/// prompter mirrors it calls into, Heimdal asserts the `krb5_data` and
/// `krb5_prompt` shapes, which differ from MIT's.
fn check_krb5_layouts(install: &Krb5Install) {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let src_path = format!("{out_dir}/check_krb5_layouts.c");
    let source = match install.vendor {
        Vendor::Mit => {
            r#"
#include <stddef.h>
#include <krb5.h>

_Static_assert(sizeof(krb5_creds) <= 256,
    "krb5_creds exceeds 256 bytes — update Krb5Creds in ffi.rs");

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
"#
        }
        Vendor::Heimdal => {
            r#"
#include <stddef.h>
#include <krb5.h>

/* Heimdal's krb5_data is heim_octet_string — no magic field, and `length` is
   a size_t — and krb5_prompt carries a prompt-type field MIT's lacks. */
_Static_assert(sizeof(krb5_creds) <= 256,
    "krb5_creds exceeds 256 bytes — update Krb5Creds in ffi.rs");
_Static_assert(sizeof(krb5_data) == 16,
    "krb5_data is not 16 bytes — update Krb5Data in ffi.rs");
_Static_assert(offsetof(krb5_data, length) == 0,
    "krb5_data::length moved — update Krb5Data in ffi.rs");
_Static_assert(offsetof(krb5_data, data) == 8,
    "krb5_data::data moved — update Krb5Data in ffi.rs");
_Static_assert(sizeof(krb5_prompt) == 32,
    "krb5_prompt is not 32 bytes — update Krb5Prompt in ffi.rs");
_Static_assert(offsetof(krb5_prompt, reply) == 16,
    "krb5_prompt::reply moved — update Krb5Prompt in ffi.rs");

/* `krb5_deltat` is a time_t here, where MIT's is an int; the lifetime
   argument of the init-creds calls has to be the right width. */
_Static_assert(sizeof(krb5_deltat) == 8,
    "krb5_deltat is not 8 bytes — update Krb5Deltat in ffi.rs");

/* Keytab entries are scanned to find a principal when the caller names none;
   only the leading principal pointer is read, so the offsets matter. */
_Static_assert(offsetof(krb5_keytab_entry, principal) == 0,
    "krb5_keytab_entry::principal moved — update Krb5KtEntry in ffi.rs");
_Static_assert(sizeof(krb5_kt_cursor) == 24,
    "krb5_kt_cursor is not 24 bytes — update Krb5KtCursor in ffi.rs");

/* The PKINIT flag values are spelled identically in ffi.rs. */
_Static_assert(KRB5_GIC_OPT_PKINIT_ANONYMOUS == 4,
    "KRB5_GIC_OPT_PKINIT_ANONYMOUS is not 4 — update ffi.rs");
_Static_assert(KRB5_GIC_OPT_PKINIT_USE_ENCKEY == 2,
    "KRB5_GIC_OPT_PKINIT_USE_ENCKEY is not 2 — update ffi.rs");
_Static_assert(KRB5_PROMPT_TYPE_PASSWORD == 1,
    "KRB5_PROMPT_TYPE_PASSWORD is not 1 — update ffi.rs");
int main(void) { return 0; }
"#
        }
    };
    std::fs::write(&src_path, source).expect("write size-check C source");

    let bin_path = format!("{out_dir}/check_krb5_layouts");
    // The include paths have to be passed explicitly, and as `-isystem` rather
    // than the CPPFLAGS the probe exports: the system SDK ships its own
    // <krb5.h>, and on macOS that is Heimdal's, which lacks the MIT responder
    // structures — cc would find it first and report a layout mismatch for a
    // correct MIT install. A keg-only install (Homebrew) puts its headers
    // outside the default search path entirely.
    let mut cmd = Command::new("cc");
    cmd.args([&src_path, "-o", &bin_path]);
    for path in &install.include_paths {
        cmd.arg("-isystem").arg(path);
    }
    cmd.args(&install.lflags);
    // The prompt structures live in libkrb5, which the pkg-config GSSAPI
    // package does not always list.
    cmd.args(["-lkrb5"]);

    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => panic!(
            "the {} layout check failed (exit {}). \
             A structure mirrored in ffi.rs no longer matches <krb5.h> on this target.",
            install.vendor.label(),
            s.code().unwrap_or(-1)
        ),
        Err(e) => {
            // If the C compiler is unavailable (e.g. cross-compile), warn but
            // don't block the build — the buffers have margin.
            println!("cargo:warning=could not run the krb5 layout check: {e}");
        }
    }
}

impl Krb5Install {
    /// Emit the cargo link directives, for the discovery paths where no tool
    /// already printed them on our behalf.
    fn print_link_metadata(&self) {
        for flag in &self.lflags {
            if let Some(path) = flag.strip_prefix("-L") {
                println!("cargo:rustc-link-search=native={path}");
            } else if let Some(lib) = flag.strip_prefix("-l") {
                println!("cargo:rustc-link-lib={lib}");
            }
        }
    }
}

/// pkg-config package names for each vendor.  Both vendors ship bare `krb5`
/// and `krb5-gssapi` packages, so the name alone does not identify the
/// vendor — `pkg_vendor` reads the `.pc` file's `vendor` variable instead.
fn pkg_config_candidates(vendor: Vendor) -> &'static [&'static str] {
    match vendor {
        Vendor::Mit => &["krb5-gssapi", "mit-krb5-gssapi"],
        Vendor::Heimdal => &["heimdal-gssapi", "heimdal-krb5"],
    }
}

/// The vendor a pkg-config package belongs to, or None when the package is
/// absent or reports a vendor neither of our cfgs covers.
fn pkg_vendor(name: &str) -> Option<Vendor> {
    let out = Command::new("pkg-config")
        .args(["--variable=vendor", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let vendor = text.trim().to_ascii_lowercase();
    if vendor.is_empty() {
        // Homebrew's `heimdal-gssapi.pc` leaves `vendor` unset; the prefixed
        // package names belong to their own vendor, an unprefixed one is MIT's
        // (Heimdal's own bare `krb5-gssapi.pc` does set vendor=Heimdal).
        return Some(if name.starts_with("heimdal") {
            Vendor::Heimdal
        } else {
            Vendor::Mit
        });
    }
    if vendor.contains("heimdal") {
        Some(Vendor::Heimdal)
    } else if vendor.contains("mit") || vendor.contains("massachusetts") {
        Some(Vendor::Mit)
    } else {
        None
    }
}

/// Probe a GSSAPI pkg-config package for the wanted vendor.  The probe emits
/// the cargo link directives itself, so only the paths are returned.
fn krb5_via_pkg_config(requested: Option<Vendor>) -> Option<Krb5Install> {
    // `--cflags` is off by default, and without it the include directories
    // stay unknown — `check_krb5_layouts` needs them to find the right header.
    let mut cfg = pkg_config::Config::new();
    cfg.probe_cflags(true);
    let mut result = None;
    for vendor in preferred_order(requested) {
        for name in pkg_config_candidates(vendor) {
            if pkg_vendor(name) != Some(vendor) {
                continue;
            }
            if let Ok(lib) = cfg.probe(name) {
                let mut lflags: Vec<String> = lib
                    .link_paths
                    .iter()
                    .map(|p| format!("-L{}", p.display()))
                    .chain(lib.libs.iter().map(|l| format!("-l{l}")))
                    .collect();
                // Heimdal's GSSAPI package names only libgssapi; the libkrb5
                // symbols the crate calls live in a separate library the `.pc`
                // file does not always require.
                if vendor == Vendor::Heimdal && !lflags.iter().any(|f| f == "-lkrb5") {
                    lflags.push("-lkrb5".to_string());
                }
                result = Some(Krb5Install {
                    vendor,
                    include_paths: lib.include_paths,
                    lflags,
                });
                break;
            }
        }
        if result.is_some() {
            break;
        }
    }
    result
}

/// Vendors to look for, in priority order.  MIT first when nothing was
/// requested: the runtime behaviour kuipa depends on (S4U2Self, named ccache
/// stores, thread-local ccaches) is MIT-only, so a machine with both kegs
/// installed should default to MIT.
fn preferred_order(requested: Option<Vendor>) -> Vec<Vendor> {
    match requested {
        Some(vendor) => vec![vendor],
        None => vec![Vendor::Mit, Vendor::Heimdal],
    }
}

/// Ask `krb5-config`, which finds installs pkg-config cannot see.  The
/// `--vendor` answer decides which implementation is behind it.
fn krb5_via_config_tool(requested: Option<Vendor>) -> Option<Krb5Install> {
    krb5_config_candidates()
        .iter()
        .filter_map(|prog| config_tool_vendor(prog).map(|vendor| (prog, vendor)))
        .filter(|(_, vendor)| Some(*vendor) == requested || requested.is_none())
        .find_map(|(prog, vendor)| {
            krb5_config_flags(prog).map(|mut flags| {
                flags.vendor = vendor;
                flags
            })
        })
}

/// Which Kerberos a `krb5-config` belongs to.  Anything unrecognised — Apple's
/// deprecated `MITKerberosShim`, a distro patch with its own string — is `None`,
/// because compiling against an unknown vendor's headers with MIT's cfg would
/// be a silent ABI gamble.
fn config_tool_vendor(prog: &Path) -> Option<Vendor> {
    let out = Command::new(prog).arg("--vendor").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let vendor = text.trim().to_ascii_lowercase();
    if vendor.contains("heimdal") {
        Some(Vendor::Heimdal)
    } else if vendor.contains("massachusetts") {
        Some(Vendor::Mit)
    } else {
        None
    }
}

/// Candidate `krb5-config` executables, in priority order.
fn krb5_config_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(explicit) = std::env::var_os("KRB5_CONFIG") {
        candidates.push(PathBuf::from(explicit));
    }
    candidates.push(PathBuf::from("krb5-config"));
    candidates.extend(
        keg_candidates()
            .iter()
            .map(|(_, prefix)| prefix.join("bin").join("krb5-config")),
    );
    candidates
}

/// Install prefixes worth inspecting, each tagged with the vendor it holds.
/// Homebrew refuses to symlink krb5 and heimdal into the normal prefix — macOS
/// ships its own Heimdal — so neither is on PATH or in `PKG_CONFIG_PATH`.  Ask
/// brew where they live, and fall back to the standard keg locations when brew
/// itself is absent.
fn keg_candidates() -> Vec<(Vendor, PathBuf)> {
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    preferred_order(None)
        .into_iter()
        .flat_map(|vendor| {
            brew_prefix(vendor.formula())
                .into_iter()
                .chain(
                    ["/opt/homebrew/opt", "/usr/local/opt"]
                        .map(|root| PathBuf::from(root).join(vendor.formula())),
                )
                .map(move |prefix| (vendor, prefix))
        })
        .collect()
}

/// Derive the paths from the install tree, for the case where the tools report
/// nothing: Homebrew's MIT `krb5-config` prints no `-I` and no `-L`, so it
/// cannot point at its own keg.
fn krb5_via_keg_prefix(requested: Option<Vendor>) -> Option<Krb5Install> {
    for (vendor, prefix) in keg_candidates() {
        if Some(vendor) != requested {
            continue;
        }
        let include = prefix.join("include");
        let lib = prefix.join("lib");
        if !include.join("krb5.h").is_file() {
            continue;
        }
        let flags = match vendor {
            // MIT's GSSAPI lives in libgssapi_krb5.
            Vendor::Mit if has_library(&lib, "libgssapi_krb5") => {
                vec![format!("-L{}", lib.display()), "-lgssapi_krb5".to_string()]
            }
            // Heimdal's is libgssapi (versioned); `libgssapi.` does not match
            // MIT's `libgssapi_krb5.*`, so a keg can satisfy only one vendor.
            Vendor::Heimdal if has_library(&lib, "libgssapi.") => vec![
                format!("-L{}", lib.display()),
                "-lgssapi".to_string(),
                "-lkrb5".to_string(),
            ],
            _ => continue,
        };
        return Some(Krb5Install {
            vendor,
            include_paths: vec![include],
            lflags: flags,
        });
    }
    None
}

/// Whether `dir` holds any build of `stem` (shared, static, or versioned).
fn has_library(dir: &Path, stem: &str) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(stem))
    })
}

/// `brew --prefix <formula>`, if brew is installed and the formula is.
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

/// `(include paths, link flags)` from one `krb5-config` run, or None if the
/// executable is not a usable krb5-config.
fn krb5_config_flags(prog: &Path) -> Option<Krb5Install> {
    let cflags = krb5_config_words(prog, &["--cflags"])?;
    let libs = krb5_config_words(prog, &["--libs", "gssapi"])?;
    let mut flags = Krb5Install::default();
    for word in cflags.iter().chain(libs.iter()) {
        if let Some(path) = word.strip_prefix("-I") {
            flags.include_paths.push(PathBuf::from(path));
        } else if word.starts_with("-L") || word.starts_with("-l") {
            flags.lflags.push(word.clone());
        }
    }
    // A bare `-l` is not evidence of a usable install — Homebrew's MIT
    // krb5-config prints exactly that, and neither the header nor the library
    // is then reachable. `krb5_via_keg_prefix` covers that keg.
    if flags.include_paths.is_empty() && !flags.lflags.iter().any(|f| f.starts_with("-L")) {
        return None;
    }
    Some(flags)
}

fn krb5_config_words(prog: &Path, args: &[&str]) -> Option<Vec<String>> {
    let out = Command::new(prog).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.split_whitespace().map(str::to_string).collect())
}
