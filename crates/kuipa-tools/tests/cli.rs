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

/// A host with a state file and unreadable pins: enough for `status` to
/// render every label, with no server contacted.
fn host_state(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("kuipa-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("var/lib/ipa-client/ku")).unwrap();
    std::fs::create_dir_all(dir.join("etc/ipa")).unwrap();
    std::fs::write(
        dir.join("var/lib/ipa-client/ku/state.json"),
        r#"{"realm":"EXAMPLE.TEST","fqdn":"web1.example.test","servers":["ipa1.example.test","ipa2.example.test"]}"#,
    )
    .unwrap();
    std::fs::write(dir.join("etc/ipa/ku-anchors"), "not-a-thumbprint\n").unwrap();
    dir
}

/// `kuipa status` for a person: who the values are about, and which file on
/// this host holds each of them; `--json` still prints the flow's object.
#[test]
fn status_names_its_subject_and_where_each_value_lives() {
    let dir = host_state("status");

    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_kuipa"))
            .args(args)
            .env("KUIPA_ROOT", &dir)
            .env_remove("KUIPA_ENROLLMENT_FILE")
            .env_remove("KUIPA_TRACE")
            .env_remove("CLICOLOR_FORCE")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let human = run(&["status"]);
    for expected in [
        "host/web1.example.test@EXAMPLE.TEST (state file:",
        "principal: host/web1.example.test@EXAMPLE.TEST",
        "realm: EXAMPLE.TEST",
        "IPA servers: ipa1.example.test, ipa2.example.test",
        "keytab: ",
        "pinned anchors: ",
    ] {
        assert!(human.contains(expected), "{human}");
    }
    // A key, not a JSON key: the labels say what a value is.
    assert!(!human.contains("\"fqdn\""), "{human}");
    // Values line up in one column: every label of the block ends at the
    // same place, and each row still greps as `label: value`.
    let columns: Vec<usize> = human
        .lines()
        .filter(|line| line.starts_with(' '))
        .filter_map(|line| line.find(": "))
        .collect();
    assert!(columns.len() > 3, "{human}");
    assert!(columns.windows(2).all(|pair| pair[0] == pair[1]), "{human}");

    let json: serde_json::Value = serde_json::from_str(&run(&["status", "--json"])).unwrap();
    assert_eq!(json["realm"], "EXAMPLE.TEST", "{json}");
    assert_eq!(json["servers"][0], "ipa1.example.test", "{json}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// On a terminal the labels are emphasised, as `clap` emphasises its help,
/// and the escape codes must not disturb the aligned column: stripped, the
/// output is byte-for-byte the plain one a pipe or `$NO_COLOR` gets.
#[test]
fn emphasised_labels_keep_the_same_column() {
    let dir = host_state("emphasis");
    let status = |env: &[(&str, &str)]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kuipa"));
        cmd.args(["status"])
            .env("KUIPA_ROOT", &dir)
            .env_remove("KUIPA_ENROLLMENT_FILE")
            .env_remove("KUIPA_TRACE")
            .env_remove("CLICOLOR_FORCE")
            .env_remove("CLICOLOR")
            .env_remove("NO_COLOR");
        for (name, value) in env {
            cmd.env(name, value);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    // Output is captured here, so it is a pipe: plain, as it is for
    // `kuipa status | grep` and for the playground's recorded session.
    let plain = status(&[]);
    assert!(!plain.contains('\x1b'), "{plain}");

    // `$CLICOLOR_FORCE` is how `clap` itself is told to colour piped
    // output; the labels are the only thing that changes.
    let colour = status(&[("CLICOLOR_FORCE", "1")]);
    let bold = colour.matches("\x1b[1m").count();
    assert!(bold > 5, "{colour}");
    assert_eq!(
        colour.matches("\x1b[1m").count(),
        colour.matches("\x1b[0m").count()
    );
    assert_eq!(colour.replace("\x1b[1m", "").replace("\x1b[0m", ""), plain);

    // `$NO_COLOR` wins over a forced terminal, as everywhere else.
    let uncached = status(&[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")]);
    assert_eq!(uncached, plain);
    let _ = std::fs::remove_dir_all(&dir);
}

/// What `kuipa` prints is for a person at a terminal: help text, rendered
/// results, error messages.  Design section numbers belong in DESIGN.md and
/// the source, not in any of that.
#[test]
fn output_never_cites_design_sections() {
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_kuipa"))
            .args(args)
            .env_remove("KUIPA_ROOT")
            .env_remove("KUIPA_ENROLLMENT_FILE")
            .env_remove("KUIPA_TRACE")
            .output()
            .unwrap();
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        text
    };

    // Every subcommand's own help, named from the top-level help so a new
    // command is covered without editing this test.
    let help = run(&["--help"]);
    let commands: Vec<&str> = help
        .lines()
        .skip_while(|line| !line.starts_with("Commands:"))
        .skip(1)
        .take_while(|line| !line.starts_with("Options:"))
        .filter(|line| line.starts_with("  ") && !line.starts_with("   "))
        .map(|line| line.trim().split(' ').next().unwrap_or_default())
        .collect();
    assert!(commands.contains(&"advertisement"), "{help}");
    let mut printed = vec![help.clone()];
    for &command in &commands {
        printed.push(run(&[command, "--help"]));
    }
    printed.push(help);

    // Rendered output and an error message, with no realm reachable.
    printed.push(run(&["status"]));
    printed.push(run(&["status", "--json"]));
    printed.push(run(&[
        "advertisement",
        "--realm",
        "EXAMPLE.TEST",
        "--server",
        "ipa1.example.test",
    ]));
    for text in &printed {
        assert!(!text.contains('§'), "{text}");
    }
}

/// Run `kuipa-unseal --sealed <missing> args`, with standard output a pipe.
fn unseal(args: &[&str]) -> (i32, String, Vec<u8>) {
    let out = Command::new(env!("CARGO_BIN_EXE_kuipa-unseal"))
        .args(["--sealed", "/nonexistent/app.conf.sealed"])
        .args(args)
        .env(
            "KUIPA_ROOT",
            std::env::temp_dir().join("kuipa-cli-unseal-none"),
        )
        .env_remove("KUIPA_TRACE")
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.stdout,
    )
}

#[test]
fn unseal_output_targets_are_checked_before_anything_is_read() {
    // Replacing /dev/stdout (a symlink) atomically would replace the link.
    let (code, stderr, _) = unseal(&["--out", "/dev/stdout"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("use `--out -`"), "{stderr}");

    // Any other target that is not a regular file is refused too.
    let dir = std::env::temp_dir().join(format!("kuipa-cli-unseal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(dir.join("target"), &link).unwrap();
    let (code, stderr, _) = unseal(&["--out", link.to_str().unwrap()]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("not a regular file"), "{stderr}");
    assert!(!dir.join("target").exists());
    let _ = std::fs::remove_dir_all(&dir);

    // Standard output as a pipe is accepted: the failure is the missing
    // sealed file, and nothing is written to standard output.
    let (code, stderr, stdout) = unseal(&["--out", "-"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(!stderr.contains("terminal"), "{stderr}");
    assert_eq!(stdout, b"");

    // --force only means something with --out.
    let (code, _, _) = unseal(&["--force"]);
    assert_eq!(code, 2);
}
