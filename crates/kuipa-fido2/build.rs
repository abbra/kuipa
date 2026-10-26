fn main() {
    // libfido2 ships a pkg-config file everywhere it is packaged; fall back
    // to the bare library name for hand-built installs.
    if pkg_config::probe_library("libfido2").is_err() {
        println!("cargo:rustc-link-lib=fido2");
    }
}
