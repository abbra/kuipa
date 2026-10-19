//! The `kuipa` command line: `--realm` with an enrollment string is a
//! cross-check of the string's realm (DESIGN §4.6), made before anything is
//! sent.

use std::process::Command;

use kuipa_enroll::enrollment::{EnrollmentString, Secret};
use tang_pqc::{SignatureAlg, SigningKey, unix_seconds};

/// Run `kuipa enroll` with an OTP enrollment string for EXAMPLE.TEST and
/// `args`; the only server is unreachable.  Returns the exit status and
/// standard error.
fn enroll(name: &str, args: &[&str]) -> (i32, String) {
    let dir = std::env::temp_dir().join(format!("kuipa-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let string = EnrollmentString::new(
        "EXAMPLE.TEST",
        *anchor.public().thumbprint(),
        unix_seconds(std::time::SystemTime::now()) + 86_400,
        Some(Secret::new(b"Secret123")),
    );
    let file = dir.join("enrollment");
    std::fs::write(&file, string.encode().as_ref()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_kuipa"))
        .args(["enroll", "--server", "ipa1.example.test"])
        .args(["--hostname", "web1.example.test"])
        .arg("--enrollment-file")
        .arg(&file)
        .args(args)
        .env("KUIPA_ROOT", &dir)
        .env("KUIPA_ENDPOINTS", "ipa1.example.test=http://127.0.0.1:9")
        .env_remove("KUIPA_ENROLLMENT_FILE")
        .env_remove("KUIPA_TRACE")
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn realm_option_cross_checks_the_enrollment_string() {
    // The string is for another realm than -r says: an error, before any
    // server is contacted.
    let (code, stderr) = enroll("other-realm", &["--realm", "OTHER.TEST"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("the enrollment string is for realm EXAMPLE.TEST, not OTHER.TEST"),
        "{stderr}"
    );
    assert!(!stderr.contains("no usable server"), "{stderr}");

    // The same realm passes the check and goes on to the (unreachable)
    // server: retry later.
    let (code, stderr) = enroll("same-realm", &["--realm", "EXAMPLE.TEST"]);
    assert_eq!(code, 75, "{stderr}");
    assert!(stderr.contains("no usable server"), "{stderr}");

    // Realms are case-sensitive, as in Kerberos.
    let (code, stderr) = enroll("realm-case", &["--realm", "example.test"]);
    assert_eq!(code, 1, "{stderr}");
}
