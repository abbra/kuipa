//! Prints the benchmark profile's fixture sizes as JSON, for
//! `scripts/bench.sh` to record alongside criterion's results.
//!
//! With no arguments the profile comes from `KUIPA_BENCH_PROFILE`.

use kuipa_perf::Profile;

fn main() {
    let arg = std::env::args().nth(1);
    let profile = match arg.as_deref() {
        Some(name) => Profile::named(name).unwrap_or_else(|| panic!("unknown profile '{name}'")),
        None => Profile::from_env(),
    };
    println!("{}", profile.metadata());
}
