//! The `tang-pqc` binary, as a command and as the Clevis pin (invoked
//! through `clevis-encrypt-tang-pqc` / `clevis-decrypt-tang-pqc` links),
//! against a plain `tang-pqc` server over HTTP.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path as UrlPath, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tang_pqc::{ExchangeKeyPair, KemAlg, RecoveryRequest, Server, SignatureAlg, SigningKey};

async fn adv(State(server): State<Arc<Server>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/jose+json")],
        server.advertisement().unwrap().to_json(),
    )
        .into_response()
}

async fn key(State(server): State<Arc<Server>>, UrlPath(kid): UrlPath<String>) -> Response {
    let Ok(kid) = kid.parse() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match server.exchange_key(&kid) {
        Ok(k) => (
            [(header::CONTENT_TYPE, "application/jwk+json")],
            k.to_jwk_json(),
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn rec(
    State(server): State<Arc<Server>>,
    UrlPath(kid): UrlPath<String>,
    body: Bytes,
) -> Response {
    match RecoveryRequest::from_bytes(&body) {
        Ok(r) if r.kid().to_string() == kid => match server.recover(&r) {
            Ok(response) => response.to_bytes().into_response(),
            Err(_) => StatusCode::NOT_FOUND.into_response(),
        },
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// A Tang server at `<url>/tang`; returns the URL and the pinned thumbprint.
fn serve() -> (String, String) {
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let thp = signing.public().thumbprint().to_string();
    let server = Arc::new(
        Server::new(
            vec![signing],
            vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
        )
        .unwrap(),
    );
    let app = Router::new()
        .route("/tang/adv", get(adv))
        .route("/tang/key/{kid}", get(key))
        .route("/tang/rec/{kid}", post(rec))
        .with_state(server);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}/tang", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        rt.block_on(async move { axum::serve(listener, app).await.unwrap() });
    });
    (url, thp)
}

/// The pin's names, linked to the binary in a temporary directory.
fn links() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tang-pqc-pin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["clevis-encrypt-tang-pqc", "clevis-decrypt-tang-pqc"] {
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_tang-pqc"), dir.join(name)).unwrap();
    }
    dir
}

fn run(program: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn pin_and_command_against_a_tang_server() {
    let (url, thp) = serve();
    let dir = links();
    let tool = Path::new(env!("CARGO_BIN_EXE_tang-pqc"));
    let encrypt = dir.join("clevis-encrypt-tang-pqc");
    let decrypt = dir.join("clevis-decrypt-tang-pqc");
    let secret = b"a disk passphrase\n";

    // Clevis lists pins with --summary.
    let out = run(&encrypt, &["--summary"], b"");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("tang-pqc"));

    // `tang-pqc adv` lists the thumbprints to pin.
    let out = run(tool, &["adv", &url], b"");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), thp);

    // Without a pin, encrypt refuses and names the advertised keys.
    let out = run(&encrypt, &[&format!(r#"{{"url":"{url}"}}"#)], secret);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains(&thp));
    // A wrong pin is refused.
    let wrong = tang_pqc::Thumbprint::from_bytes([1; 32]).to_string();
    let out = run(
        &encrypt,
        &[&format!(r#"{{"url":"{url}","thp":"{wrong}"}}"#)],
        secret,
    );
    assert!(!out.status.success());

    // The pin round trip.
    let config = format!(r#"{{"url":"{url}","thp":"{thp}"}}"#);
    let out = run(&encrypt, &[&config], secret);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let jwe = String::from_utf8(out.stdout).unwrap();
    assert_eq!(jwe.split('.').count(), 5);
    let out = run(&decrypt, &[], jwe.as_bytes());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, secret);

    // The command does the same; a second encryption is another binding.
    let out = run(tool, &["encrypt", &config], secret);
    let jwe2 = String::from_utf8(out.stdout).unwrap();
    assert_ne!(jwe.split('.').next(), jwe2.split('.').next());
    assert_eq!(run(tool, &["decrypt"], jwe2.as_bytes()).stdout, secret);

    // A changed header (here: the URL) or ciphertext does not decrypt.
    let mut parts: Vec<String> = jwe.trim().split('.').map(str::to_owned).collect();
    let header = String::from_utf8(tang_pqc::b64::decode(&parts[0]).unwrap()).unwrap();
    parts[0] = tang_pqc::b64::encode(header.replace("/tang", "/tang/").as_bytes());
    assert!(
        !run(&decrypt, &[], parts.join(".").as_bytes())
            .status
            .success()
    );
    let mut parts: Vec<String> = jwe.trim().split('.').map(str::to_owned).collect();
    let mut ct = tang_pqc::b64::decode(&parts[3]).unwrap();
    ct[0] ^= 1;
    parts[3] = tang_pqc::b64::encode(&ct);
    assert!(
        !run(&decrypt, &[], parts.join(".").as_bytes())
            .status
            .success()
    );

    // `clevis luks regen` passes the old header's pin object back: the
    // binding in it is ignored.
    let regen = format!(r#"{{"url":"{url}","thp":"{thp}","binding":"AAAA"}}"#);
    let out = run(&encrypt, &[&regen], secret);
    assert!(out.status.success());

    // Usage errors exit 2.
    assert_eq!(run(&encrypt, &[], b"").status.code(), Some(2));
    assert_eq!(run(tool, &["frobnicate"], b"").status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
