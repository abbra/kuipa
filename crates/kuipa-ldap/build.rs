fn main() {
    // Probe for the OpenLDAP client library via pkg-config first.
    // Fall back to hardcoded link directives if pkg-config is unavailable.
    if pkg_config::probe_library("ldap").is_err() {
        println!("cargo:rustc-link-lib=ldap");
        println!("cargo:rustc-link-lib=lber");
    }
    // SASL library — required by OpenLDAP for SASL mechanism dispatch (GSSAPI, EXTERNAL, …).
    println!("cargo:rustc-link-lib=sasl2");
    // MIT Kerberos GSSAPI implementation — required for SASL GSSAPI binds.
    println!("cargo:rustc-link-lib=gssapi_krb5");
}
