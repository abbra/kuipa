//! Human text a tool prints outside its labelled rows.

use synta::GeneralizedTime;

/// A Unix time as `YYYY-MM-DD HH:MM:SS UTC`, for a person reading a
/// tool's output; `None` when the time is out of range, so the caller
/// can print the seconds instead.
///
/// The civil-date arithmetic is `synta`'s, as everywhere in the
/// workspace.
#[must_use]
pub fn date(secs: u64) -> Option<String> {
    GeneralizedTime::from_unix(i64::try_from(secs).unwrap_or(i64::MAX)).map(|t| {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            t.year, t.month, t.day, t.hour, t.minute, t.second
        )
    })
}

#[cfg(test)]
mod tests {
    use super::date;

    /// The epoch itself, a leap second's day and a date past 2038, from
    /// `date -u`: what a person reads must be the calendar, not the
    /// clock counter.
    #[test]
    fn unix_times_print_as_utc_calendar_dates() {
        assert_eq!(date(0).as_deref(), Some("1970-01-01 00:00:00 UTC"));
        assert_eq!(
            date(1_709_251_199).as_deref(),
            Some("2024-02-29 23:59:59 UTC")
        );
        assert_eq!(
            date(1_792_672_496).as_deref(),
            Some("2026-10-22 12:34:56 UTC")
        );
    }

    /// A time past the calendar synta holds has no date: the caller
    /// prints the seconds.
    #[test]
    fn past_the_calendar_there_is_no_date() {
        assert!(date(u64::MAX).is_none());
        assert!(
            date(i64::MAX as u64 + 1).is_none(),
            "a u64 that overflows i64::MAX must not wrap to a date"
        );
    }
}
