//! System crypto policy enforcement (Fedora/RHEL crypto-policies).
//!
//! The policy is read once per process from OpenSSL's configuration, so each
//! scenario re-runs its own test in a child process whose `OPENSSL_CONF`
//! points at a configuration with the policy's `system_default` lists.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use ml_dsa_blind::{Context, Error, ParameterSet, Requester, SigningKey};

const CHILD: &str = "ML_DSA_BLIND_POLICY_CHILD";
const DATA: &str = "ML_DSA_BLIND_POLICY_DATA";

/// In the parent, prepare data, re-run `test` in a child whose OpenSSL
/// configuration allows only `sigalgs`, and assert it passed; returns
/// `None`.  In the child, returns the data directory.
fn under_policy(test: &str, sigalgs: &str, prepare: impl FnOnce(&Path)) -> Option<PathBuf> {
    if std::env::var_os(CHILD).is_some() {
        return Some(PathBuf::from(std::env::var_os(DATA).unwrap()));
    }
    let dir =
        std::env::temp_dir().join(format!("ml-dsa-blind-policy-{test}-{}", std::process::id()));
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

/// A key the child's policy disables, made under the host's policy.
fn prepare_ml_dsa_65_key(dir: &Path) {
    let key = SigningKey::generate(ParameterSet::MlDsa65).unwrap();
    fs::write(dir.join("k65.pem"), key.to_pem().unwrap()).unwrap();
}

#[test]
fn cnsa_policy_allows_only_ml_dsa_87() {
    let Some(dir) = under_policy(
        "cnsa_policy_allows_only_ml_dsa_87",
        "?mldsa87:?ECDSA+SHA384",
        prepare_ml_dsa_65_key,
    ) else {
        return;
    };

    for set in [ParameterSet::MlDsa44, ParameterSet::MlDsa65] {
        assert!(matches!(
            SigningKey::generate(set),
            Err(Error::DisabledBySystemPolicy(s)) if s == set
        ));
    }
    assert_eq!(ParameterSet::preferred().unwrap(), ParameterSet::MlDsa87);

    // Falling back to the allowed parameter set works end to end.
    let signer = SigningKey::generate_preferred().unwrap();
    assert_eq!(
        signer.verifying_key().parameter_set(),
        ParameterSet::MlDsa87
    );
    let requester = Requester::new(signer.verifying_key().clone());
    let (request, pending) = requester.blind(b"m").unwrap();
    let signature = pending
        .finalize(&signer.blind_sign(&request).unwrap())
        .unwrap();
    signer
        .verifying_key()
        .verify(&Context::default(), b"m", &signature)
        .unwrap();

    // An existing ML-DSA-65 key can be loaded but neither signs, nor serves
    // requesters, nor verifies.
    let old = SigningKey::from_pem(&fs::read(dir.join("k65.pem")).unwrap()).unwrap();
    let requester = Requester::new(old.verifying_key().clone());
    assert!(matches!(
        requester.blind(b"m"),
        Err(Error::DisabledBySystemPolicy(ParameterSet::MlDsa65))
    ));
    assert!(matches!(
        old.blind_sign(&request),
        Err(Error::DisabledBySystemPolicy(ParameterSet::MlDsa65))
    ));
    assert!(matches!(
        old.verifying_key()
            .verify(&Context::default(), b"m", &signature),
        Err(Error::DisabledBySystemPolicy(ParameterSet::MlDsa65))
    ));
}

#[test]
fn no_pq_policy_allows_no_parameter_set() {
    let Some(_) = under_policy(
        "no_pq_policy_allows_no_parameter_set",
        "?ECDSA+SHA256:?ed25519",
        |_| {},
    ) else {
        return;
    };
    assert!(matches!(
        ParameterSet::preferred(),
        Err(Error::NoAllowedParameterSet)
    ));
    assert!(matches!(
        SigningKey::generate_preferred(),
        Err(Error::NoAllowedParameterSet)
    ));
}
