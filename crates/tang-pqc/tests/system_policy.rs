//! System crypto policy enforcement (Fedora/RHEL crypto-policies), tested
//! end to end.
//!
//! The policy is read once per process from OpenSSL's configuration, so each
//! scenario re-runs its own test in a child process whose `OPENSSL_CONF`
//! points at a configuration with the policy's `system_default` lists.
//! Artifacts the child's policy would refuse to create (e.g. a binding made
//! before the policy changed) are prepared by the parent and passed as files.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tang_pqc::{
    Binding, Error, ExchangeKeyPair, KemAlg, RecoveryRequest, Server, SignatureAlg,
    SignedAdvertisement, SigningKey, Thumbprint,
};

const CHILD: &str = "TANG_PQC_POLICY_CHILD";
const DATA: &str = "TANG_PQC_POLICY_DATA";

/// A CNSA 2.0-style policy: ML-DSA-87 and ML-KEM-1024 only.
const CNSA: (&str, &str) = (
    "?mldsa87:?ECDSA+SHA384",
    "?SecP384r1MLKEM1024:?mlkem1024:?secp384r1",
);
/// crypto-policies' `NO-PQ` module: no ML-DSA, no ML-KEM groups.
const NO_PQ: (&str, &str) = ("?ECDSA+SHA256:?ed25519", "*?X25519/*?secp256r1");

/// In the parent, prepare data with `prepare`, then re-run `test` in a child
/// under `policy` and assert it passed; returns `None`.  In the child,
/// returns the data directory.
fn under_policy(
    test: &str,
    (sigalgs, groups): (&str, &str),
    prepare: impl FnOnce(&Path),
) -> Option<PathBuf> {
    if std::env::var_os(CHILD).is_some() {
        return Some(PathBuf::from(std::env::var_os(DATA).unwrap()));
    }
    let dir = std::env::temp_dir().join(format!("tang-pqc-policy-{test}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("openssl.cnf");
    fs::write(
        &conf,
        format!(
            "openssl_conf = openssl_init\n\
             [openssl_init]\nssl_conf = ssl_module\n\
             [ssl_module]\nsystem_default = crypto_policy\n\
             [crypto_policy]\nSignatureAlgorithms = {sigalgs}\nGroups = {groups}\n"
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

fn write(dir: &Path, name: &str, data: impl AsRef<[u8]>) {
    fs::write(dir.join(name), data).unwrap();
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    fs::read(dir.join(name)).unwrap()
}

/// Keys of every strength, an ML-DSA-65-only advertisement and an
/// ML-KEM-768 binding, all made under the host's (permissive) policy.
fn prepare_mixed_keys(dir: &Path) {
    let k65 = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let k87 = SigningKey::generate(SignatureAlg::MlDsa87).unwrap();
    let kem768 = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let kem1024 = ExchangeKeyPair::generate(KemAlg::MlKem1024).unwrap();
    write(dir, "k65.jwk", k65.to_jwk().unwrap());
    write(dir, "k87.jwk", k87.to_jwk().unwrap());
    write(dir, "kem768.jwk", kem768.to_jwk().unwrap());
    write(dir, "kem1024.jwk", kem1024.to_jwk().unwrap());

    let thp65 = *k65.public().thumbprint();
    let old = Server::new(vec![k65], vec![kem768]).unwrap();
    let adv = old.advertisement().unwrap();
    write(dir, "adv65.json", adv.to_json());
    write(dir, "thp65", thp65.to_string());
    let (binding, _) = adv.verify(&thp65).unwrap().provision(None).unwrap();
    let (request, _) = binding
        .recovery_request(old.exchange_key(binding.kid()).unwrap())
        .unwrap();
    write(dir, "binding768", binding.to_bytes());
    write(dir, "request768", request.to_bytes());
}

fn load_signing(dir: &Path, name: &str) -> SigningKey {
    SigningKey::from_jwk(&read(dir, name)).unwrap()
}

fn load_exchange(dir: &Path, name: &str) -> ExchangeKeyPair {
    ExchangeKeyPair::from_jwk(&read(dir, name)).unwrap()
}

#[test]
fn cnsa_policy_falls_back_to_the_allowed_algorithms() {
    let Some(dir) = under_policy(
        "cnsa_policy_falls_back_to_the_allowed_algorithms",
        CNSA,
        prepare_mixed_keys,
    ) else {
        return;
    };

    // Explicit requests for disabled algorithms fail...
    assert!(matches!(
        SigningKey::generate(SignatureAlg::MlDsa65),
        Err(Error::DisabledBySystemPolicy("ML-DSA-65"))
    ));
    assert!(matches!(
        ExchangeKeyPair::generate(KemAlg::MlKem768),
        Err(Error::DisabledBySystemPolicy("ML-KEM-768"))
    ));
    // ...and library choices fall back to what remains.
    assert_eq!(SignatureAlg::preferred().unwrap(), SignatureAlg::MlDsa87);
    assert_eq!(KemAlg::preferred().unwrap(), KemAlg::MlKem1024);
    assert_eq!(
        SigningKey::generate_preferred().unwrap().public().alg(),
        SignatureAlg::MlDsa87
    );
    assert_eq!(
        ExchangeKeyPair::generate_preferred()
            .unwrap()
            .public()
            .alg(),
        KemAlg::MlKem1024
    );

    // A server holding keys of every strength signs with, and advertises,
    // only the allowed ones.
    let k87 = load_signing(&dir, "k87.jwk");
    let thp87 = *k87.public().thumbprint();
    let kem1024 = load_exchange(&dir, "kem1024.jwk");
    let kid1024 = *kem1024.public().kid();
    let server = Server::new(
        vec![load_signing(&dir, "k65.jwk"), k87],
        vec![load_exchange(&dir, "kem768.jwk"), kem1024],
    )
    .unwrap();
    let adv = server.advertisement().unwrap();
    assert_eq!(adv.advertised_signing_keys().unwrap(), vec![thp87]);
    let verified = adv.verify(&thp87).unwrap();
    assert_eq!(verified.exchange_keys().len(), 1);
    let (binding, key) = verified.provision(None).unwrap();
    assert_eq!(binding.kid(), &kid1024);
    let (request, pending) = binding
        .recovery_request(verified.exchange_key(&kid1024).unwrap())
        .unwrap();
    let recovered = pending.finish(&server.recover(&request).unwrap()).unwrap();
    assert_eq!(recovered.as_ref(), key.as_ref());

    // An advertisement signed only by a disabled key is refused.
    let thp65: Thumbprint = String::from_utf8(read(&dir, "thp65"))
        .unwrap()
        .parse()
        .unwrap();
    let adv65 = SignedAdvertisement::from_json(&read(&dir, "adv65.json")).unwrap();
    assert!(matches!(
        adv65.verify(&thp65),
        Err(Error::DisabledBySystemPolicy("ML-DSA-65"))
    ));

    // A binding made with ML-KEM-768 before the policy change is refused by
    // the client and by the server.
    let binding768 = Binding::from_bytes(&read(&dir, "binding768")).unwrap();
    let old_server = Server::new(
        vec![load_signing(&dir, "k87.jwk")],
        vec![load_exchange(&dir, "kem1024.jwk")],
    )
    .unwrap()
    .with_retired_keys(vec![load_exchange(&dir, "kem768.jwk")]);
    assert!(matches!(
        binding768.recovery_request(old_server.exchange_key(binding768.kid()).unwrap()),
        Err(Error::DisabledBySystemPolicy("ML-KEM-768"))
    ));
    let request768 = RecoveryRequest::from_bytes(&read(&dir, "request768")).unwrap();
    assert!(matches!(
        old_server.recover(&request768),
        Err(Error::DisabledBySystemPolicy("ML-KEM-768"))
    ));
}

#[test]
fn no_pq_policy_refuses_everything() {
    let Some(dir) = under_policy("no_pq_policy_refuses_everything", NO_PQ, prepare_mixed_keys)
    else {
        return;
    };

    assert!(matches!(
        SignatureAlg::preferred(),
        Err(Error::NoAllowedAlgorithm("ML-DSA"))
    ));
    assert!(matches!(
        KemAlg::preferred(),
        Err(Error::NoAllowedAlgorithm("ML-KEM"))
    ));
    assert!(SigningKey::generate_preferred().is_err());
    for alg in SignatureAlg::ALL {
        assert!(matches!(
            SigningKey::generate(alg),
            Err(Error::DisabledBySystemPolicy(_))
        ));
    }
    // Keys can still be loaded (to inspect or rotate them), but not used.
    assert!(matches!(
        Server::new(
            vec![load_signing(&dir, "k87.jwk")],
            vec![load_exchange(&dir, "kem1024.jwk")],
        ),
        Err(Error::NoAllowedAlgorithm(_))
    ));
    let thp65: Thumbprint = String::from_utf8(read(&dir, "thp65"))
        .unwrap()
        .parse()
        .unwrap();
    let adv65 = SignedAdvertisement::from_json(&read(&dir, "adv65.json")).unwrap();
    assert!(matches!(
        adv65.verify(&thp65),
        Err(Error::DisabledBySystemPolicy(_))
    ));
}
