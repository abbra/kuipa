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

/// An enrolled host verifies the realm with the anchors it pinned, even
/// when an enrollment file is in the environment (the playground keeps
/// one for every command): its pins are its trust state, grown by every
/// verified exchange, while the string names the single anchor of the
/// day it was issued.  With only the string's anchor, a server whose
/// claim — or whose part of the anchor log — is vouched by an anchor the
/// host learned since is refused, and so is every other server of the
/// realm: no failover.
///
/// The server here is unreachable, so the refusal the query string
/// reaches is visible in the error: it must name both pins, not the
/// string's one.
#[test]
fn an_enrolled_host_verifies_with_its_pins_not_the_strings() {
    let dir = std::env::temp_dir().join(format!("kuipa-cli-pins-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("var/lib/ipa-client/ku")).unwrap();
    std::fs::create_dir_all(dir.join("etc/ipa")).unwrap();
    std::fs::write(
        dir.join("var/lib/ipa-client/ku/state.json"),
        r#"{"realm":"EXAMPLE.TEST","fqdn":"web1.example.test","servers":["ipa1.example.test","ipa2.example.test"]}"#,
    )
    .unwrap();

    // The enrollment string's anchor, and a second anchor the host pinned
    // later (a rotation, or the second server's own).
    let string_anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let other_anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let string = EnrollmentString::new(
        "EXAMPLE.TEST",
        *string_anchor.public().thumbprint(),
        unix_seconds(std::time::SystemTime::now()) + 86_400,
        Some(Secret::new(b"Secret123")),
    );
    let file = dir.join("enrollment");
    std::fs::write(&file, string.encode().as_ref()).unwrap();
    std::fs::write(
        dir.join("etc/ipa/ku-anchors"),
        format!(
            "{}\n{}\n",
            string_anchor.public().thumbprint(),
            other_anchor.public().thumbprint()
        ),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_kuipa"))
        .args([
            "enroll",
            "--server",
            "ipa1.example.test",
            "--hostname",
            "web1.example.test",
        ])
        .arg("--enrollment-file")
        .arg(&file)
        .env("KUIPA_ROOT", &dir)
        .env("KUIPA_ENDPOINTS", "ipa1.example.test=http://127.0.0.1:9")
        .env_remove("KUIPA_ENROLLMENT_FILE")
        .env_remove("KUIPA_TRACE")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("anchor={}", other_anchor.public().thumbprint())),
        "the query must carry the pinned anchors, not only the string's: {stderr}"
    );
    assert!(
        stderr.contains(&format!("anchor={}", string_anchor.public().thumbprint())),
        "{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
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
    // A real pin line: anchor, a window of two heads, frozen
    // (DESIGN-claim-logs.md §1.2); status reports the window.
    std::fs::write(
        dir.join("etc/ipa/ku-anchors"),
        "ERERERERERERERERERERERERERERERERERERERERERE 12 \
IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI 20 \
ERERERERERERERERERERERERERERERERERERERERERE frozen\n",
    )
    .unwrap();
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
        "head window: ERERERERERERERERERERERERERERERERERERERERERE: 12 leaves, 20 leaves (frozen)",
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

/// A pin file that cannot be parsed is not "no trust": `status` refuses
/// and names the file, so a corrupted trust store is visible instead of
/// silently empty.
#[test]
fn a_corrupt_pin_file_refuses_not_forgets() {
    let dir = host_state("corrupt-pin");
    std::fs::write(dir.join("etc/ipa/ku-anchors"), "not-a-thumbprint\n").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_kuipa"))
        .args(["status"])
        .env("KUIPA_ROOT", &dir)
        .env_remove("KUIPA_ENROLLMENT_FILE")
        .env_remove("KUIPA_TRACE")
        .output()
        .unwrap();
    assert!(!out.status.success(), "a corrupt pin file must not pass");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("ku-anchors"), "{err}");
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

/// Run binary `exe` with `args` in an empty root, with no server reachable;
/// standard error.
fn run(exe: &str, args: &[&str]) -> String {
    let root = std::env::temp_dir().join(format!("kuipa-cli-hyphen-{}", std::process::id()));
    let out = Command::new(exe)
        .args(args)
        .env("KUIPA_ROOT", &root)
        .env("KUIPA_ENDPOINTS", "ipa1.example.test=http://127.0.0.1:9")
        .env_remove("KUIPA_TRACE")
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn ids_and_thumbprints_may_begin_with_a_hyphen() {
    // Device ids and key thumbprints are base64url: one in 64 begins with
    // `-`, and must still be taken as the value it is, not as an option.
    let id = "-mIdStartsWithAHyphen0000000000000000000000";
    let kuipa = env!("CARGO_BIN_EXE_kuipa");
    let audit = env!("CARGO_BIN_EXE_kuipa-audit");
    let witness = env!("CARGO_BIN_EXE_kuipa-witness");
    let head = format!("{id} 1 AAAA");
    let cases: [(&str, Vec<&str>); 7] = [
        (kuipa, vec!["seal", "device", "remove", "v", id]),
        (
            kuipa,
            vec![
                "seal", "recover", "deliver", "00ff", "--user", "bob", "--device", id,
            ],
        ),
        (kuipa, vec!["tlog", "witnesses", "--remove", id]),
        (
            audit,
            vec!["claim-log", "--server", "ipa1.example.test", "--anchor", id],
        ),
        (
            audit,
            vec![
                "coverage",
                "--server",
                "ipa1.example.test",
                "--anchor",
                id,
                "--pinned-head",
                &head,
            ],
        ),
        (
            audit,
            vec!["tlog", "--server", "ipa1.example.test", "--anchor", id],
        ),
        (
            witness,
            vec![
                "run",
                "--once",
                "--key",
                "/nonexistent",
                "--state",
                "/nonexistent",
                "--server",
                "ipa1.example.test",
                "--anchor",
                id,
            ],
        ),
    ];
    for (exe, args) in cases {
        let stderr = run(exe, &args);
        assert!(
            !stderr.contains("unexpected argument"),
            "{args:?}: {stderr}"
        );
    }
}

/// A stand-in HTTP proxy on loopback: it records each request line and
/// answers `502 Bad Gateway`, so nothing goes further.
fn proxy() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{BufRead as _, BufReader, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                log.lock().unwrap().push(line.trim_end().to_owned());
            }
            // The rest of the head, then the answer.
            while reader.read_line(&mut line).is_ok_and(|n| n > 2) {}
            let _ = stream.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    (url, seen)
}

/// Run `kuipa enroll` against ipa1.example.test with `env` and no other
/// proxy settings; returns the exit status and standard error.
fn enroll_with(name: &str, env: &[(&str, &str)]) -> (i32, String) {
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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kuipa"));
    cmd.args(["enroll", "--server", "ipa1.example.test"])
        .args(["--hostname", "web1.example.test"])
        .arg("--enrollment-file")
        .arg(&file)
        .env("KUIPA_ROOT", &dir)
        .env_remove("KUIPA_ENDPOINTS")
        .env_remove("KUIPA_ENROLLMENT_FILE")
        .env_remove("KUIPA_TRACE");
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "REQUEST_METHOD",
    ] {
        cmd.env_remove(var);
    }
    for (var, value) in env {
        cmd.env(var, value);
    }
    let out = cmd.output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// HTTPS to a server goes through `$HTTPS_PROXY` as a `CONNECT` tunnel, and
/// a proxy that refuses it is a server that could not be reached: retry
/// later, saying why.
#[test]
fn https_goes_through_the_environments_proxy() {
    let (url, seen) = proxy();
    let (code, stderr) = enroll_with("https-proxy", &[("HTTPS_PROXY", &url)]);
    assert_eq!(code, 75, "{stderr}");
    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .all(|l| l == "CONNECT ipa1.example.test:443 HTTP/1.1"),
        "{seen:?}"
    );
    assert!(!seen.is_empty(), "the proxy was not asked: {stderr}");
    // The HTTP client keeps the proxy's status to itself, but says the
    // tunnel failed, which is the hint a misconfigured proxy needs.
    assert!(stderr.contains("tunnel error"), "{stderr}");

    // ALL_PROXY serves when no HTTPS_PROXY is set, as in curl.
    let (all, seen) = proxy();
    let (code, stderr) = enroll_with("all-proxy", &[("all_proxy", &all)]);
    assert_eq!(code, 75, "{stderr}");
    assert!(!seen.lock().unwrap().is_empty(), "{stderr}");

    // NO_PROXY exempts the server: the proxy is never asked.
    let (url, seen) = proxy();
    let (code, stderr) = enroll_with(
        "no-proxy",
        &[("HTTPS_PROXY", &url), ("NO_PROXY", ".example.test")],
    );
    assert_eq!(code, 75, "{stderr}");
    assert_eq!(seen.lock().unwrap().len(), 0, "{stderr}");
}

/// A plain-HTTP endpoint goes through `$HTTP_PROXY`, by absolute URL.
#[test]
fn plain_http_goes_through_http_proxy() {
    let (url, seen) = proxy();
    let (code, stderr) = enroll_with(
        "http-proxy",
        &[
            ("HTTP_PROXY", &url),
            (
                "KUIPA_ENDPOINTS",
                "ipa1.example.test=http://ipa1.example.test:8080",
            ),
        ],
    );
    assert_ne!(code, 0, "{stderr}");
    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.first()
            .is_some_and(|l| l.starts_with("GET http://ipa1.example.test:8080/ipa/ku/")),
        "{seen:?}: {stderr}"
    );
}
