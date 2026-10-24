//! `kuipa-audit`: read-only reports on a realm's claim logs
//! (DESIGN-claim-logs.md §5) and transparency logs (DESIGN-tlog.md §7).
//!
//! ```text
//! kuipa-audit claim-log  --server S --anchor THP [--from N]
//!                          one anchor's claim-log page, decoded
//! kuipa-audit coverage   --server S [--anchor THP…]
//!                          [--pinned-head "THP SIZE ROOT"…]
//!                          what the pinned heads cover, and whether
//!                          the server's log extends them
//! kuipa-audit split-view --server S1 --server S2…
//!                          the heads each server answers, and where
//!                          they disagree
//! kuipa-audit tlog       --server S [--anchor THP…] [--state FILE]
//!                          a server's whole transparency log, replayed
//!                          against its signed head (DESIGN-tlog.md §5)
//! ```
//!
//! The tool fetches only public endpoints and writes nothing: it is
//! `curl` plus the tree math; only `tlog --state` writes, to the file it
//! names.  `--json` prints the report as one JSON object instead of rows.
//! Exit status: 0 a clean report, 1 an error, 2 a report that found a
//! split view or a forked transparency log.

use std::process::ExitCode;

use clap::Parser;
use kuipa_tools::audit;

#[derive(Parser)]
#[command(
    name = "kuipa-audit",
    about = "Read-only reports on a realm's claim logs and transparency logs.",
    after_help = "The tool fetches only public endpoints (the advertisement, the anchor log \
and the claim-log pages) and checks what it fetches against heads — pinned or given. \
It holds no keys and writes nothing."
)]
struct Cli {
    /// Print the report as one JSON object instead of rows.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// One anchor's claim-log page, decoded.
    ClaimLog {
        /// The server to ask.
        #[arg(long)]
        server: String,
        /// The anchor whose claim log.
        #[arg(long)]
        anchor: String,
        /// The leaf index to start after (default 0).
        #[arg(long)]
        from: Option<u64>,
    },
    /// What the pinned heads cover, and whether the server's log
    /// extends them.
    Coverage {
        /// The server to ask.
        #[arg(long)]
        server: String,
        /// Only these anchors (default: every pinned one).
        #[arg(long)]
        anchor: Vec<String>,
        /// A head to check, as `<thumbprint> <size> <root>`; repeatable.
        /// Default: this host's pinned windows.
        #[arg(long, value_name = "THP SIZE ROOT")]
        pinned_head: Vec<String>,
    },
    /// The heads each server answers for the realm's anchors, and
    /// where they disagree.
    SplitView {
        /// The servers to ask (at least one).
        #[arg(long)]
        server: Vec<String>,
    },
    /// A server's whole transparency log: its head checked against the
    /// signing key its verified advertisement names, every leaf replayed.
    Tlog {
        /// The server to ask.
        #[arg(long)]
        server: String,
        /// Anchors to verify the advertisement with; repeatable.
        /// Default: this host's pinned anchors.
        #[arg(long)]
        anchor: Vec<String>,
        /// Record the verified head in this file, and require the next
        /// run's log to extend it.
        #[arg(long, value_name = "FILE")]
        state: Option<std::path::PathBuf>,
        /// A witness's public JWK file whose cosignatures to count;
        /// repeatable.
        #[arg(long, value_name = "JWK")]
        witness: Vec<std::path::PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (value, clean) = match &cli.command {
        Command::ClaimLog {
            server,
            anchor,
            from,
        } => match audit::claim_log(server, anchor, from.unwrap_or(0)) {
            Ok(v) => (v, true),
            Err(e) => {
                eprintln!("kuipa-audit claim-log: {e}");
                return ExitCode::FAILURE;
            }
        },
        Command::Coverage {
            server,
            anchor,
            pinned_head,
        } => match heads(pinned_head) {
            Ok(heads) => match audit::coverage(server, &heads) {
                Ok(v) => {
                    let clean = audit::clean(&v);
                    if let Some(only) = filtered(&v, anchor) {
                        (only, clean)
                    } else {
                        (v, clean)
                    }
                }
                Err(e) => {
                    eprintln!("kuipa-audit coverage: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Err(e) => {
                eprintln!("kuipa-audit coverage: {e}");
                return ExitCode::FAILURE;
            }
        },
        Command::Tlog {
            server,
            anchor,
            state,
            witness,
        } => match tlog(server, anchor, witness, state.as_deref()) {
            Ok(report) => report,
            Err(status) => return status,
        },
        Command::SplitView { server } => {
            if server.is_empty() {
                eprintln!("kuipa-audit split-view: --server is required (repeat for each)");
                return ExitCode::from(2);
            }
            match audit::split_view(server) {
                Ok(v) => {
                    let clean = audit::clean(&v);
                    (v, clean)
                }
                Err(e) => {
                    eprintln!("kuipa-audit split-view: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
    };
    if cli.json {
        println!("{value}");
    } else {
        render(&cli.command, &value);
    }
    if clean {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

/// `kuipa-audit tlog`: the report and whether it is clean, or the exit
/// status for bad arguments (2) or a failed audit (1), reported.
fn tlog(
    server: &str,
    anchor: &[String],
    witness: &[std::path::PathBuf],
    state: Option<&std::path::Path>,
) -> Result<(serde_json::Value, bool), ExitCode> {
    let witnesses: Result<Vec<tang_pqc::VerifyingKey>, String> = witness
        .iter()
        .map(|p| {
            std::fs::read(p)
                .map_err(|e| e.to_string())
                .and_then(|b| tang_pqc::VerifyingKey::from_jwk_json(&b).map_err(|e| e.to_string()))
                .map_err(|e| format!("{}: {e}", p.display()))
        })
        .collect();
    let witnesses = witnesses.map_err(|e| {
        eprintln!("kuipa-audit tlog: {e}");
        ExitCode::from(2)
    })?;
    let anchors: Vec<tang_pqc::Thumbprint> = anchor
        .iter()
        .map(|a| a.parse())
        .collect::<Result<_, _>>()
        .map_err(|_| {
            eprintln!("kuipa-audit tlog: bad --anchor thumbprint");
            ExitCode::from(2)
        })?;
    let v = audit::tlog(server, &anchors, &witnesses, state).map_err(|e| {
        eprintln!("kuipa-audit tlog: {e}");
        ExitCode::FAILURE
    })?;
    let clean = !v["state"]
        .as_str()
        .unwrap_or_default()
        .starts_with("forked");
    Ok((v, clean))
}

/// Parse `--pinned-head "THP SIZE ROOT"` arguments.
fn heads(given: &[String]) -> Result<Vec<(tang_pqc::Thumbprint, u64, [u8; 32])>, String> {
    let mut out = Vec::new();
    for g in given {
        let mut fields = g.split_whitespace();
        let (Some(a), Some(s), Some(r)) = (fields.next(), fields.next(), fields.next()) else {
            return Err(format!(
                "--pinned-head needs \"<thumbprint> <size> <root>\": {g:?}"
            ));
        };
        let anchor: tang_pqc::Thumbprint =
            a.parse().map_err(|_| format!("bad thumbprint in {g:?}"))?;
        let size: u64 = s.parse().map_err(|_| format!("bad size in {g:?}"))?;
        let root: tang_pqc::Thumbprint = r.parse().map_err(|_| format!("bad root in {g:?}"))?;
        out.push((anchor, size, *root.as_bytes()));
    }
    Ok(out)
}

/// Keep only the anchors asked for, when any were.
fn filtered(value: &serde_json::Value, only: &[String]) -> Option<serde_json::Value> {
    if only.is_empty() {
        return None;
    }
    let mut out = value.clone();
    if let Some(rows) = out
        .get_mut("anchors")
        .and_then(serde_json::Value::as_array_mut)
    {
        rows.retain(|r| {
            r["anchor"]
                .as_str()
                .is_some_and(|a| only.iter().any(|o| o.eq_ignore_ascii_case(a)))
        });
    }
    Some(out)
}

/// The labelled-rows text the other tools use, kept plain: the audit
/// is a report, read by a person or a pipe.
fn render(command: &Command, value: &serde_json::Value) {
    let get = |k: &str| value.get(k).cloned().unwrap_or(serde_json::Value::Null);
    let mut rows = Rows::default();
    match command {
        Command::ClaimLog { .. } => {
            rows.field("server", &get("server"));
            rows.field("anchor", &get("anchor"));
            rows.field("leaves", &get("size"));
            rows.field("root", &get("root"));
            rows.until("vouch expires", &get("exp"));
            let leaves = get("leaves").as_array().map_or(0, Vec::len);
            rows.row("leaf count", leaves.to_string());
            rows.print();
            for (i, leaf) in get("leaves")
                .as_array()
                .map(|a| a.iter())
                .unwrap_or_default()
                .enumerate()
            {
                println!("  {:>4}  {}", i + 1, sanitize(leaf.as_str().unwrap_or("")));
            }
        }
        Command::Coverage { .. } => {
            rows.field("server", &get("server"));
            rows.print();
            for a in get("anchors")
                .as_array()
                .map(|a| a.iter())
                .unwrap_or_default()
            {
                let mut r = Rows::default();
                r.field("anchor", &a["anchor"]);
                r.field("state", &a["state"]);
                if let Some(pinned) = a.get("pinned") {
                    r.row("pinned", format_head(pinned));
                }
                if let Some(served) = a.get("served") {
                    r.row("served", format_head(served));
                }
                r.print();
            }
        }
        Command::Tlog { .. } => {
            rows.field("server", &get("server"));
            rows.field("log", &get("log"));
            rows.field("state", &get("state"));
            if get("size").is_u64() {
                rows.row("head", format_head(value));
                rows.until("signed", &get("time"));
            }
            if let Some(p) = value.get("previous") {
                rows.row("recorded", format_head(p));
            }
            if let Some(w) = get("witnesses").as_array() {
                rows.row("cosigned by", w.len().to_string());
            }
            if let Some(kinds) = get("kinds").as_object() {
                let list: Vec<String> = kinds.iter().map(|(k, n)| format!("{k} {n}")).collect();
                rows.row("leaves", list.join(", "));
            }
            rows.print();
        }
        Command::SplitView { .. } => {
            rows.print();
            for d in get("disagreements")
                .as_array()
                .map(|a| a.iter())
                .unwrap_or_default()
            {
                let mut r = Rows::default();
                r.field("anchor", &d["anchor"]);
                r.print();
                for side in d["sides"].as_array().map(|a| a.iter()).unwrap_or_default() {
                    println!(
                        "    {} answers {}",
                        side["server"].as_str().unwrap_or("?"),
                        format_head(&side["head"])
                    );
                }
            }
            let n = get("disagreements").as_array().map_or(0, Vec::len);
            println!(
                "{}",
                if n == 0 {
                    "no disagreements: every server answers the same heads"
                } else {
                    "split view: servers disagree on the heads above"
                }
            );
        }
    }
}

fn format_head(head: &serde_json::Value) -> String {
    format!(
        "{} leaves, root {}",
        head["size"].as_u64().unwrap_or(0),
        sanitize(head["root"].as_str().unwrap_or("?"))
    )
}

/// Server-supplied strings print as given except for control
/// characters: a malicious server must not drive the auditor's
/// terminal with escape sequences smuggled into an anchor, root or
/// leaf string.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '…' } else { c })
        .collect()
}

/// The plain labelled rows the other tools print: label, two spaces,
/// value; the width of the widest label.
#[derive(Default)]
struct Rows {
    width: usize,
    lines: Vec<(String, String)>,
}

impl Rows {
    fn row(&mut self, label: &str, value: String) {
        self.width = self.width.max(label.len());
        self.lines.push((label.to_string(), value));
    }

    fn field(&mut self, label: &str, value: &serde_json::Value) {
        if matches!(value, serde_json::Value::Null) {
            return;
        }
        let text = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            other => other.to_string(),
        };
        self.row(label, sanitize(&text));
    }

    /// A Unix time a row names, as a date: `vouch expires` is read by a
    /// person deciding whether to trust a log, not by a clock.  Out of
    /// range the seconds are kept, and anything else prints as it is.
    fn until(&mut self, label: &str, value: &serde_json::Value) {
        if value.is_null() {
            return;
        }
        let text = match value.as_u64() {
            Some(secs) => kuipa_tools::text::date(secs).unwrap_or_else(|| secs.to_string()),
            None => value.to_string(),
        };
        self.row(label, sanitize(&text));
    }

    fn print(&self) {
        for (label, value) in &self.lines {
            println!("{label:width$}  {value}", width = self.width);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn control_characters_never_reach_the_terminal() {
        assert_eq!(sanitize("thp\u{1b}[2J\u{7}root\nleaf"), "thp…[2J…root…leaf");
        assert_eq!(sanitize("plain 43-char anchor"), "plain 43-char anchor");
    }
}
