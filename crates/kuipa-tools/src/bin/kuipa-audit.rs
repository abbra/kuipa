//! `kuipa-audit`: read-only reports on a realm's claim logs
//! (DESIGN-claim-logs.md §5).
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
//! ```
//!
//! The tool fetches only public endpoints and writes nothing: it is
//! `curl` plus the tree math.  `--json` prints the report as one JSON
//! object instead of rows.  Exit status: 0 a clean report, 1 an error,
//! 2 a report that found a split view.

use std::process::ExitCode;

use clap::Parser;
use kuipa_tools::audit;

#[derive(Parser)]
#[command(
    name = "kuipa-audit",
    about = "Read-only reports on a realm's claim logs.",
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
            rows.field("vouch expires", &get("exp"));
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
