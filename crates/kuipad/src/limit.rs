//! Rate limiting (§5.1): token buckets per host and per source address,
//! checked before any decapsulation or LDAP work.
//!
//! A bucket holds up to `burst` tokens and gains `per_minute` tokens a
//! minute; each request takes one.  Idle buckets (full again) are dropped
//! when the table grows, so memory stays bounded.

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

/// Buckets beyond which idle ones are dropped.
const PRUNE_ABOVE: usize = 10_000;

#[derive(Debug, Default)]
struct Table {
    buckets: HashMap<String, Bucket>,
}

impl Table {
    fn take(&mut self, key: &str, rate: Rate, now: Instant) -> bool {
        if self.buckets.len() > PRUNE_ABOVE {
            self.buckets.retain(|_, b| level(b, rate, now) < rate.burst);
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
    /// host (Tang recovery).
    ///
    /// # Errors
    ///
    /// [`Limited::Source`] when it is empty.
    pub fn check_source(&self, source: &str) -> Result<(), Limited> {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        if sources.take(source, self.limits.per_source, Instant::now()) {
            Ok(())
        } else {
            Err(Limited::Source)
        }
    }

    fn check_at(&self, host: &str, source: Option<&str>, now: Instant) -> Result<(), Limited> {
        if let Some(source) = source {
            let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
            if !sources.take(source, self.limits.per_source, now) {
                return Err(Limited::Source);
            }
        }
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        if hosts.take(&host.to_ascii_lowercase(), self.limits.per_host, now) {
            Ok(())
        } else {
            Err(Limited::Host)
        }
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
    use std::time::Duration;

    use super::*;

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
    fn idle_buckets_are_dropped() {
        let l = limiter((1.0, 60.0), (1000.0, 1000.0));
        let t = Instant::now();
        for i in 0..=PRUNE_ABOVE {
            let _ = l.check_at(&format!("h{i}"), None, t);
        }
        let later = t + Duration::from_secs(120);
        let _ = l.check_at("new", None, later);
        assert!(l.hosts.lock().unwrap().buckets.len() < 10);
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
