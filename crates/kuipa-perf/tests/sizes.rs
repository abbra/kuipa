//! Wire sizes behind `docs/src/reference/sizing.md`: how the advertisement
//! grows with the realm.  Not a regression test; run with
//!
//! ```sh
//! cargo test -p kuipa-perf --test sizes -- --ignored --nocapture
//! ```

use kuipa_perf::profile::Profile;
use kuipa_perf::realm::realm;

#[test]
#[ignore = "a measurement, printed for the sizing guide"]
fn advertisement_size_by_servers() {
    println!("servers (all anchors) | advertisement bytes");
    for servers in [1usize, 2, 4, 8, 16, 32] {
        let mut profile = Profile::named("production").expect("profile");
        profile.servers = servers;
        profile.attested = servers.saturating_sub(1).min(3);
        let r = realm(&profile);
        let json = r.advertisement(0).to_json();
        println!("{servers:>21} | {}", json.len());
    }
}
