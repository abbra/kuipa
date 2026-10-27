//! Rate limiting (§5.1): token buckets per host and per source address,
//! checked before any decapsulation or LDAP work.
//!
//! A bucket holds up to `burst` tokens and gains `per_minute` tokens a
//! minute; each request takes one.  Memory stays bounded: bucket keys are
//! truncated (so an attacker cannot store megabytes per entry), and the
//! tables evict — idle buckets first, then the least recently used —
//! beyond a fixed number of entries, never growing past that however many
//! distinct names or addresses a client sends.
//!
//! Requests that name no host (registration, seal operations, Tang
//! recovery) and arrive without a resolvable source share one bucket of
//! their own, so they are always limited: nothing reaches the handlers
//! unthrottled.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use serde::Deserialize;

/// One limit.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rate {
    /// Requests allowed at once.
    pub burst: f64,
    /// Requests allowed per minute after that.
    pub per_minute: f64,
}

/// The limits (`rate_limit` in the configuration).
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Per host FQDN (joins, rekeys, staging) or principal (recovery).
    pub per_host: Rate,
    /// Per client address, as httpd reports it in `X-Forwarded-For`.
    pub per_source: Rate,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_host: Rate {
                burst: 10.0,
                per_minute: 2.0,
            },
            per_source: Rate {
                burst: 60.0,
                per_minute: 30.0,
            },
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Most buckets kept per table (hosts, sources): the tables evict beyond
/// this, so memory cannot grow with the number of distinct keys a client
/// sends.  Generous for real realms and client populations.
const TABLE_CAP: usize = 10_000;

/// At most this many bytes of a bucket key are stored.  Keys arrive from
/// the network; truncating them bounds what a single entry can cost.
/// A host or principal name that matters is short; this only tells apart
/// buckets, and a truncation collision merely shares an allowance.
const KEY_LEN: usize = 128;

/// The bucket shared by every request that names no host and has no
/// resolvable source address.
const UNSOURCED: &str = "\0unsourced";

fn key(k: &str) -> &str {
    match k.char_indices().nth(KEY_LEN) {
        Some((i, _)) => &k[..i],
        None => k,
    }
}

#[derive(Debug, Default)]
struct Table {
    buckets: HashMap<String, Bucket>,
}

impl Table {
    fn take(&mut self, key: &str, rate: Rate, now: Instant) -> bool {
        // Cheap first pass: any table at the cap drops buckets that are
        // full again (idle), which is almost always enough.
        if self.buckets.len() >= TABLE_CAP {
            self.buckets.retain(|_, b| level(b, rate, now) < rate.burst);
        }
        // Still at the cap — a sustained flood of distinct names: evict
        // the least recently used until there is room.  The bucket being
        // taken now has the newest `at`, so it survives its own insertion.
        while self.buckets.len() >= TABLE_CAP {
            match self.buckets.iter().min_by_key(|(_, b)| b.at) {
                Some((oldest, _)) if oldest != key => {
                    let oldest = oldest.clone();
                    self.buckets.remove(&oldest);
                }
                _ => break,
            }
        }
        let bucket = self.buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: rate.burst,
            at: now,
        });
        bucket.tokens = level(bucket, rate, now);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

fn level(b: &Bucket, rate: Rate, now: Instant) -> f64 {
    let minutes = now.duration_since(b.at).as_secs_f64() / 60.0;
    (b.tokens + minutes * rate.per_minute).min(rate.burst)
}

/// What a refusal was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limited {
    /// Too many requests for this host.
    Host,
    /// Too many requests from this source.
    Source,
}

/// The rate limiter.
#[derive(Debug, Default)]
pub struct Limiter {
    limits: Limits,
    hosts: Mutex<Table>,
    sources: Mutex<Table>,
}

impl Limiter {
    /// A limiter with `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Admit one request for `host` from `source` (if known).
    ///
    /// # Errors
    ///
    /// Which limit refused it.  A request refused for its source does not
    /// use up its host's allowance.
    pub fn check(&self, host: &str, source: Option<&str>) -> Result<(), Limited> {
        self.check_at(host, source, Instant::now())
    }

    /// Take a token from `source`'s bucket only: for requests that name no
    /// host (Tang recovery, registration, seal operations).  `None`
    /// limits through the shared unsourced bucket rather than not at all.
    ///
    /// # Errors
    ///
    /// [`Limited::Source`] when it is empty.
    pub fn check_source(&self, source: Option<&str>) -> Result<(), Limited> {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        let key = key(source.unwrap_or(UNSOURCED));
        if sources.take(key, self.limits.per_source, Instant::now()) {
            Ok(())
        } else {
            Err(Limited::Source)
        }
    }

    fn check_at(&self, host: &str, source: Option<&str>, now: Instant) -> Result<(), Limited> {
        if let Some(source) = source {
            let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
            if !sources.take(key(source), self.limits.per_source, now) {
                return Err(Limited::Source);
            }
        }
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        if hosts.take(key(&host.to_ascii_lowercase()), self.limits.per_host, now) {
            Ok(())
        } else {
            Err(Limited::Host)
        }
    }

    /// The state of both tables, for tests.
    #[cfg(test)]
    fn sizes(&self) -> (usize, usize) {
        (
            self.hosts.lock().unwrap().len(),
            self.sources.lock().unwrap().len(),
        )
    }
}

/// The client address from the `X-Forwarded-For` value httpd sets: the
/// last entry is the one httpd itself saw, earlier ones are what the
/// client claimed.
#[must_use]
pub fn forwarded_source(header: Option<&str>) -> Option<String> {
    header?
        .rsplit(',')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limiter(host: (f64, f64), source: (f64, f64)) -> Limiter {
        Limiter::new(Limits {
            per_host: Rate {
                burst: host.0,
                per_minute: host.1,
            },
            per_source: Rate {
                burst: source.0,
                per_minute: source.1,
            },
        })
    }

    #[test]
    fn buckets_drain_and_refill() {
        let l = limiter((2.0, 1.0), (100.0, 100.0));
        let t = Instant::now();
        assert_eq!(l.check_at("web1", Some("a"), t), Ok(()));
        assert_eq!(
            l.check_at("WEB1", Some("b"), t),
            Ok(()),
            "hosts are case-insensitive"
        );
        assert_eq!(l.check_at("web1", Some("c"), t), Err(Limited::Host));
        assert_eq!(l.check_at("web2", Some("a"), t), Ok(()), "per host");
        // One token a minute.
        assert_eq!(
            l.check_at("web1", None, t + Duration::from_secs(30)),
            Err(Limited::Host)
        );
        assert_eq!(
            l.check_at("web1", None, t + Duration::from_secs(61)),
            Ok(())
        );
    }

    #[test]
    fn sources_are_limited_without_using_host_allowance() {
        let l = limiter((10.0, 1.0), (1.0, 1.0));
        let t = Instant::now();
        assert_eq!(l.check_at("web1", Some("198.51.100.7"), t), Ok(()));
        for host in ["web2", "web3", "web4"] {
            assert_eq!(
                l.check_at(host, Some("198.51.100.7"), t),
                Err(Limited::Source)
            );
        }
        assert_eq!(l.check_at("web2", Some("198.51.100.8"), t), Ok(()));
    }

    #[test]
    fn unsourced_requests_share_one_bucket() {
        // The per-source limit of the shared bucket bites for requests
        // without a resolvable source address: no unlimited path remains.
        let l = limiter((1000.0, 1000.0), (2.0, 1.0));
        let t = Instant::now();
        assert_eq!(l.check_source(None), Ok(()));
        assert_eq!(l.check_source(None), Ok(()));
        assert_eq!(
            l.check_source(None),
            Err(Limited::Source),
            "no source is the shared bucket, not no limit"
        );
        // The same bucket serves hostless requests with and without a
        // source name... no: a named source has its own.
        assert_eq!(l.check_at("web", Some("s"), t), Ok(()));
        assert_eq!(l.check_at("web", None, t), Ok(()));
    }

    #[test]
    fn hostless_with_source_is_limited_per_source() {
        let l = limiter((1000.0, 1000.0), (1.0, 0.0));
        assert_eq!(l.check_source(Some("198.51.100.7")), Ok(()));
        assert_eq!(l.check_source(Some("198.51.100.7")), Err(Limited::Source));
        assert_eq!(l.check_source(Some("198.51.100.8")), Ok(()));
    }

    #[test]
    fn table_size_is_capped_under_a_flood_of_distinct_keys() {
        let l = limiter((10.0, 0.0), (1000.0, 1000.0));
        let t = Instant::now();
        // Far more distinct keys than TABLE_CAP: the table must not grow
        // past the cap, and admission must keep working.
        for i in 0..(TABLE_CAP * 3) {
            let _ = l.check_at(&format!("h{i}.example.test"), None, t);
        }
        let (hosts, _) = l.sizes();
        assert!(hosts <= TABLE_CAP, "table grew to {hosts}");
        // The most recent keys still have buckets: one of the last few
        // is admitted (burst 10), an early one was evicted.
        let mut admitted = 0;
        for i in 0..10 {
            if l.check_at(&format!("h{}.example.test", TABLE_CAP * 3 - 1 - i), None, t)
                .is_ok()
            {
                admitted += 1;
            }
        }
        assert!(admitted > 0, "recent keys lost their buckets");
        assert!(
            l.check_at("h0.example.test", None, t).is_ok(),
            "an evicted key is simply admitted again — memory is bounded, not correctness"
        );
    }

    #[test]
    fn long_keys_are_truncated_not_stored() {
        let l = limiter((1.0, 0.0), (1000.0, 1000.0));
        let t = Instant::now();
        let long = "h".repeat(60_000);
        assert_eq!(l.check_at(&long, None, t), Ok(()));
        // A second 60 kB key, differing only past the truncation point,
        // shares the first's bucket: bounded memory, shared allowance.
        assert_eq!(
            l.check_at(&format!("{long}x"), None, t),
            Err(Limited::Host),
            "keys differing past the stored prefix share a bucket"
        );
        let (hosts, _) = l.sizes();
        assert_eq!(hosts, 1);
    }

    #[test]
    fn idle_buckets_are_dropped() {
        let l = limiter((1.0, 60.0), (1000.0, 1000.0));
        let t = Instant::now();
        for i in 0..=TABLE_CAP {
            let _ = l.check_at(&format!("h{i}"), None, t);
        }
        let later = t + Duration::from_secs(120);
        let _ = l.check_at("new", None, later);
        let (hosts, _) = l.sizes();
        assert!(hosts < 10, "{hosts} buckets survived the refill");
    }

    #[test]
    fn source_from_forwarded_for() {
        assert_eq!(forwarded_source(None), None);
        assert_eq!(
            forwarded_source(Some("203.0.113.1")).as_deref(),
            Some("203.0.113.1")
        );
        assert_eq!(
            forwarded_source(Some("10.0.0.1, 203.0.113.1")).as_deref(),
            Some("203.0.113.1"),
            "the entry httpd added, not what the client claimed"
        );
        assert_eq!(forwarded_source(Some("  ")), None);
    }
}
