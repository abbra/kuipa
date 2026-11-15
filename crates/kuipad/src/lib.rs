//! `kuipad`, the kuipa server daemon: post-quantum enrollment for FreeIPA.

pub mod config;
pub mod directory;
mod getkeytab;
pub mod http;
pub mod keys;
pub mod keystore;
pub mod ledger;
pub mod limit;
pub mod peers;
pub mod tang;
pub mod trust;

/// The error every fallible operation here boxes.
pub(crate) type Error = Box<dyn std::error::Error + Send + Sync>;

/// Lock `m`, ignoring poisoning: the guarded state stays consistent across a
/// panicking holder.
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
