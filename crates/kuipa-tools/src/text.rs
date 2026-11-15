//! Human text a tool prints: dates, and the labelled rows.

use serde_json::Value;
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

/// Server-supplied strings print as given except for control
/// characters: a malicious server must not drive the terminal with
/// escape sequences smuggled into an anchor, root or leaf string.
#[must_use]
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '…' } else { c })
        .collect()
}

/// The rows of one block: labels are ours, values are the flow's.  Labels
/// are right-aligned to one column, so the values line up under it while
/// each row still reads `label: value` — `grep` for a label and its value
/// matches whatever else the block contains.  `Null` and a false flag are
/// not shown; an empty name or list says `none`, a list of names goes on
/// one line.
#[derive(Default)]
pub struct Rows {
    /// Columns of indent before every row.
    pub indent: usize,
    width: usize,
    lines: Vec<(String, String)>,
}

impl Rows {
    /// Rows indented by `indent` columns.
    #[must_use]
    pub fn indented(indent: usize) -> Self {
        Self {
            indent,
            ..Self::default()
        }
    }

    pub fn row(&mut self, label: &str, value: impl AsRef<str>) {
        self.width = self.width.max(label.len());
        self.lines
            .push((label.to_string(), sanitize(value.as_ref())));
    }

    pub fn field(&mut self, label: &str, value: &Value) {
        if matches!(value, Value::Null | Value::Bool(false)) {
            return;
        }
        let text = match value {
            Value::Bool(true) => "yes".to_string(),
            Value::String(s) if s.is_empty() => "none".to_string(),
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Array(items) if items.iter().all(Value::is_string) => {
                let names: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
                if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(", ")
                }
            }
            other => other.to_string(),
        };
        self.row(label, text);
    }

    /// A duration a flow measured against this host's clock, with its unit.
    pub fn left(&mut self, label: &str, value: &Value, unit: &str) {
        if value.is_null() {
            return;
        }
        self.row(
            label,
            format!("{} {unit} left", value.as_u64().unwrap_or_default()),
        );
    }

    /// A Unix time a flow recorded, as a date.  `synta`'s `GeneralizedTime`
    /// does the civil-date arithmetic, in UTC.
    pub fn until(&mut self, label: &str, value: &Value) {
        let Some(secs) = value.as_u64() else { return };
        let text = date(secs).unwrap_or_else(|| secs.to_string());
        self.row(label, text);
    }

    /// A file on this host.
    pub fn path(&mut self, label: &str, path: &std::path::Path) {
        self.row(label, path.display().to_string());
    }

    /// Rows are only printed once the block is complete: the column width
    /// is the widest label it holds.  On a terminal the labels are
    /// emphasised, as `clap` emphasises its help; the padding is written
    /// before the escape codes, so the column is identical either way.
    pub fn print(&self) {
        if emphasise() {
            for (label, value) in &self.lines {
                println!(
                    "{:>indent$}{}\x1b[1m{label}\x1b[0m: {value}",
                    "",
                    " ".repeat(self.width - label.len()),
                    indent = self.indent,
                );
            }
        } else {
            for (label, value) in &self.lines {
                println!(
                    "{:>indent$}{:>width$}: {value}",
                    "",
                    label,
                    indent = self.indent,
                    width = self.width,
                );
            }
        }
    }
}

/// Whether to emphasise labels: `anstream`'s decision, the same one `clap`
/// applies to its own help (`$NO_COLOR`, `$CLICOLOR`, `$CLICOLOR_FORCE`,
/// `$TERM`, whether standard output is a terminal), so `kuipa --help` and a
/// rendered block agree on where emphasis goes.  Anything that is not an
/// ANSI terminal — a pipe, a Windows wincon console — gets plain labels.
fn emphasise() -> bool {
    anstream::AutoStream::choice(&std::io::stdout()) == anstream::ColorChoice::Always
}

#[cfg(test)]
mod tests {
    use super::{date, sanitize};

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

    #[test]
    fn control_characters_never_reach_the_terminal() {
        assert_eq!(sanitize("thp\u{1b}[2J\u{7}root\nleaf"), "thp…[2J…root…leaf");
        assert_eq!(sanitize("plain 43-char anchor"), "plain 43-char anchor");
    }
}
