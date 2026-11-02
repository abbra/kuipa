//! Every argument the usage header and the man page advertise must reach
//! the code that reads it: a flag missing from `parse_args` is refused as
//! "unknown argument" before the command runs.

use std::process::Command;

fn kuipad(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_kuipad"))
        .args(args)
        // A path that cannot exist: the command fails on the config, which
        // is proof the arguments parsed and the command started.
        .args(["--config", "/nonexistent/kuipad.json"])
        .output()
        .expect("kuipad runs");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn documented_arguments_are_accepted() {
    // Each case is the command and its documented options, as the usage
    // header spells them; none may be refused as unknown.
    for case in [
        "enrollment-string --head",
        "enrollment-string --days 1",
        "rotate-anchor --days 1",
        "rotate-keys --join --escrow --trust --signing",
        "establish-trust --invitation-file F --server S",
        "add-voucher-key --file F",
        "add-witness-key --file F",
        "prune-keys --join-days 1 --escrow-days 2",
    ] {
        let args: Vec<&str> = case.split_whitespace().collect();
        let stderr = kuipad(&args);
        assert!(!stderr.contains("unknown argument"), "{case}: {stderr}");
    }
}

#[test]
fn an_undocumented_argument_is_refused() {
    // The parser must not accept everything: that would make the test above
    // pass for the wrong reason.
    let stderr = kuipad(&["enrollment-string", "--nonsense"]);
    assert!(stderr.contains("unknown argument"), "{stderr}");
}
