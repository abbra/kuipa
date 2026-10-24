//! The system crypto policy picks the proof's level (Fedora/RHEL
//! crypto-policies).
//!
//! The policy is read once per process from OpenSSL's configuration, so
//! each scenario re-runs its own test in a child process whose
//! `OPENSSL_CONF` points at a configuration with the policy's
//! `system_default` lists.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ml_dsa_zk::{Circuit, Error, Level, Proof, prove, prove_at, verify};

const CHILD: &str = "ML_DSA_ZK_POLICY_CHILD";
const DATA: &str = "ML_DSA_ZK_POLICY_DATA";

/// In the parent, prepare data, re-run `test` in a child whose OpenSSL
/// configuration allows only `sigalgs`, and assert it passed; returns
/// `None`.  In the child, returns the data directory.
fn under_policy(test: &str, sigalgs: &str, prepare: impl FnOnce(&Path)) -> Option<PathBuf> {
    if std::env::var_os(CHILD).is_some() {
        return Some(PathBuf::from(std::env::var_os(DATA).unwrap()));
    }
    let dir = std::env::temp_dir().join(format!("ml-dsa-zk-policy-{test}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("openssl.cnf");
    fs::write(
        &conf,
        format!(
            "openssl_conf = openssl_init\n\
             [openssl_init]\nssl_conf = ssl_module\n\
             [ssl_module]\nsystem_default = crypto_policy\n\
             [crypto_policy]\nSignatureAlgorithms = {sigalgs}\n"
        ),
    )
    .unwrap();
    prepare(&dir);

    let out = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--test-threads=1", "--nocapture"])
        .env("OPENSSL_CONF", &conf)
        .env(CHILD, "1")
        .env(DATA, &dir)
        .output()
        .unwrap();
    let _ = fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "child under policy failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    None
}

/// `x₀ ∧ x₁`.
fn and() -> Circuit {
    let mut c = Circuit::new(2);
    let a = c.and(c.input(0), c.input(1));
    c.output(a);
    c
}

/// A λ = 128 proof, made under the host's policy.
fn prepare_weak_proof(dir: &Path) {
    let (proof, _) = prove_at(Level::L128, &and(), &[true, true]).unwrap();
    fs::write(dir.join("weak.proof"), proof.to_bytes()).unwrap();
}

#[test]
fn cnsa_policy_proves_and_requires_lambda_256() {
    let Some(dir) = under_policy(
        "cnsa_policy_proves_and_requires_lambda_256",
        "?mldsa87:?ECDSA+SHA384",
        prepare_weak_proof,
    ) else {
        return;
    };
    assert_eq!(Level::from_system().unwrap(), Level::L256);
    let c = and();
    let (proof, outputs) = prove(&c, &[true, true]).unwrap();
    assert_eq!(proof.level(), Level::L256);
    verify(&c, &outputs, &proof).unwrap();
    // A valid λ = 128 proof from elsewhere is refused here.
    let weak = Proof::from_bytes(&c, &fs::read(dir.join("weak.proof")).unwrap()).unwrap();
    assert!(matches!(
        verify(&c, &[true], &weak),
        Err(Error::Weak(Level::L128))
    ));
}

#[test]
fn a_policy_allowing_ml_dsa_65_proves_at_lambda_128() {
    let Some(_) = under_policy(
        "a_policy_allowing_ml_dsa_65_proves_at_lambda_128",
        "?mldsa65:?mldsa87:?ECDSA+SHA256",
        |_| {},
    ) else {
        return;
    };
    assert_eq!(Level::from_system().unwrap(), Level::L128);
    let c = and();
    let (proof, outputs) = prove(&c, &[true, false]).unwrap();
    assert_eq!(proof.level(), Level::L128);
    verify(&c, &outputs, &proof).unwrap();
    // A stronger proof is still accepted.
    let (strong, outputs) = prove_at(Level::L256, &c, &[true, false]).unwrap();
    verify(&c, &outputs, &strong).unwrap();
}
