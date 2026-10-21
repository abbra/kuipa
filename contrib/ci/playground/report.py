#!/usr/bin/env python3
"""Render the playground session (session.sh's output) as a report.

Usage:
    report.py OUT --html REPORT.html [--summary] [--commit SHA]

OUT is the directory session.sh wrote: session.env, steps/NNN/{meta.env,
command, stdout, stderr, server.log, expect, missing} and, when
local-ci.sh copied it, servers.log (the servers' whole log).  --html writes
a self-contained page (no external assets, light and dark); --summary
prints a Markdown fragment for the GitHub Actions job summary: the step
table and the failed steps' output.  It names the artifact that holds the
HTML report; the workflow adds the artifact's link after uploading it,
since the URL only exists then.

--svg DIR adds the animated terminal captures terminal.py and
render-terminal.mjs wrote under DIR (one SVG per session section),
embedded inline in each section's heading: the capture plays once when
scrolled into view, with a replay button.  Without --svg the page is
unchanged.
"""

import argparse
import datetime
import html
import json
import os
import re
import sys

LEVEL = re.compile(r"^(\s*\d+\.\d+s)\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s(.*)$")


def esc(value):
    return html.escape(str(value), quote=True)


def md(value):
    """Text for a Markdown table cell: HTML-escaped, quotes kept, pipes escaped."""
    return html.escape(str(value), quote=False).replace("|", "\\|")


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def parse_env(path):
    env = {}
    for line in read(path).splitlines():
        key, sep, value = line.partition("=")
        if sep:
            env[key] = value
    return env


def load(out):
    steps = []
    steps_dir = os.path.join(out, "steps")
    for name in sorted(os.listdir(steps_dir)):
        d = os.path.join(steps_dir, name)
        meta = parse_env(os.path.join(d, "meta.env"))
        steps.append(
            {
                "n": int(name),
                "section": meta.get("section", ""),
                "section_text": meta.get("section_text", ""),
                "title": meta.get("title", name),
                "expected": meta.get("expected", "0"),
                "status": meta.get("status", "?"),
                "passed": meta.get("passed") == "1",
                "ms": int(meta.get("ms", "0") or 0),
                "command": read(os.path.join(d, "command")).rstrip("\n"),
                "stdout": read(os.path.join(d, "stdout")),
                "stderr": read(os.path.join(d, "stderr")),
                "server": read(os.path.join(d, "server.log")),
                "expect": read(os.path.join(d, "expect")).splitlines(),
                "missing": read(os.path.join(d, "missing")).splitlines(),
                "timed_out": meta.get("timed_out") == "1",
                "timeout": meta.get("timeout", ""),
            }
        )
    sections = []
    for step in steps:
        if not sections or sections[-1]["title"] != step["section"]:
            sections.append(
                {"title": step["section"], "text": step["section_text"], "steps": []}
            )
        sections[-1]["steps"].append(step)
    return {
        "session": parse_env(os.path.join(out, "session.env")),
        "servers_log": read(os.path.join(out, "servers.log")),
        "steps": steps,
        "sections": sections,
    }


def seconds(ms):
    return f"{ms / 1000:.2f} s" if ms >= 1000 else f"{ms} ms"


def failed_text(count):
    return f"{count} step{'' if count == 1 else 's'} failed"


def expected_text(expected):
    return "non-zero" if expected == "fail" else expected


def trace_html(text):
    """The trace with each line's level highlighted and its time dimmed."""
    lines = []
    for line in text.splitlines():
        m = LEVEL.match(line)
        if m:
            t, level, rest = m.groups()
            lines.append(
                f'<span class="ln"><span class="t">{esc(t.strip())}</span> '
                f'<span class="lv {level.lower()}">{level:<5}</span> {esc(rest)}</span>'
            )
        else:
            lines.append(f'<span class="ln">{esc(line)}</span>')
    return "".join(lines)


def block(label, body, *, open_=False, raw=False, cls="", count=None):
    if not body.strip():
        return ""
    content = body if raw else esc(body.rstrip("\n"))
    if count is None:
        count = body.rstrip("\n").count("\n") + 1
    return (
        f'<details class="out {cls}"{" open" if open_ else ""}>'
        f'<summary>{esc(label)} <span class="count">{count} line'
        f'{"" if count == 1 else "s"}</span></summary>'
        f"<pre>{content}</pre></details>"
    )


def status_text(step):
    """The exit status as the report shows it, with what was expected."""
    if step["timed_out"]:
        return f"timed out after {step['timeout']} s"
    text = f"exit {step['status']}"
    if not step["passed"] or step["expected"] != "0":
        text += f" (expected {expected_text(step['expected'])})"
    return text


def expect_html(step):
    """The output the step had to show, each marked found or missing."""
    if not step["expect"]:
        return ""
    items = "".join(
        f'<li class="{"missing" if text in step["missing"] else "found"}">'
        f'<span class="mark">{"✗" if text in step["missing"] else "✓"}</span>'
        f"<code>{esc(text)}</code></li>"
        for text in step["expect"]
    )
    return f'<ul class="expect" aria-label="Expected in the output">{items}</ul>'


def load_captures(svg_dir):
    """The section captures under SVG_DIR, keyed by section index."""
    if not svg_dir:
        return {}
    try:
        manifest = json.loads(read(os.path.join(svg_dir, "manifest.json")))
    except (json.JSONDecodeError, OSError):
        return {}
    captures = {}
    for entry in manifest.get("captures", []):
        svg = read(os.path.join(svg_dir, entry["file"]))
        if svg.startswith("<svg"):
            captures[entry["index"]] = svg
    return captures


def capture_html(index, svg):
    """One capture, inline, playing when scrolled into view.

    The SVG is SMIL + CSS animation that ends on a static frame, so it is
    left alone on load and restarted by re-inserting it — the same markup,
    a fresh element, the animation clock back at zero.  Without
    JavaScript (or after the page is printed) the last frame shows.
    """
    return f"""
<figure class="capture" data-capture>
  <div class="frame">{svg}</div>
  <button type="button" class="replay" title="Play the capture again">↻ replay</button>
</figure>"""


def render_step(step):
    state = "pass" if step["passed"] else "fail"
    trace = trace_html(step["stderr"]) if step["stderr"].strip() else ""
    return f"""
<article class="step {state}" id="step-{step['n']}">
  <header>
    <span class="num">{step['n']}</span>
    <h3>{esc(step['title'])}</h3>
    <span class="badge {state}">{'PASS' if step['passed'] else 'FAIL'}</span>
  </header>
  <div class="facts"><span>{esc(status_text(step))}</span><span>{seconds(step['ms'])}</span></div>
  <pre class="cmd"><span class="prompt">$</span> {esc(step['command'])}</pre>
  {expect_html(step)}
  {block('Output', step['stdout'], open_=True)}
  {block('Trace (standard error)', trace, open_=not step['passed'], raw=True, cls='trace', count=len(step['stderr'].splitlines()))}
  {block('Server log during this step', step['server'], cls='server')}
</article>"""


CSS = """
:root { color-scheme: light dark;
  --bg: #f7f7f5; --card: #ffffff; --ink: #1d1f23; --muted: #6a6f78;
  --line: #e2e2dd; --code: #f1f1ee; --accent: #3b5bdb;
  --pass: #2f9e44; --pass-bg: #e6f4ea; --fail: #d6336c; --fail-bg: #fde8ef;
  --trace: #868e96; --debug: #1c7ed6; --info: #2f9e44; --warn: #e8590c; --error: #d6336c; }
@media (prefers-color-scheme: dark) { :root {
  --bg: #15171a; --card: #1d2024; --ink: #e6e6e3; --muted: #9aa0a8;
  --line: #2e3238; --code: #24282d; --accent: #8ea4ff;
  --pass: #51cf66; --pass-bg: #1f3326; --fail: #f06595; --fail-bg: #3a1f29;
  --trace: #868e96; --debug: #74c0fc; --info: #69db7c; --warn: #ffa94d; --error: #f783ac; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
.wrap { max-width: 72rem; margin: 0 auto; padding: 2rem 1rem 4rem;
  display: grid; grid-template-columns: 15rem minmax(0, 1fr); gap: 2rem; }
@media (max-width: 60rem) { .wrap { grid-template-columns: minmax(0, 1fr); }
  nav { position: static; max-height: none; order: 2; } }
h1 { font-size: 1.7rem; margin: 0 0 .2rem; letter-spacing: -.01em; }
.sub { color: var(--muted); margin: 0 0 1rem; }
.mono, pre, code { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
.overall { display: flex; flex-wrap: wrap; gap: .6rem 1.4rem; align-items: center;
  background: var(--card); border: 1px solid var(--line); border-radius: .7rem;
  padding: .9rem 1.1rem; margin-bottom: 1.6rem; }
.overall .verdict { font-weight: 700; font-size: 1.05rem; padding: .2rem .7rem; border-radius: .4rem; }
.overall .verdict.pass { background: var(--pass-bg); color: var(--pass); }
.overall .verdict.fail { background: var(--fail-bg); color: var(--fail); }
.overall dl { display: flex; flex-wrap: wrap; gap: .3rem 1.4rem; margin: 0; }
.overall dt { color: var(--muted); font-size: .8rem; }
.overall dd { margin: 0; font-weight: 600; }
nav { position: sticky; top: 1rem; align-self: start; max-height: calc(100vh - 2rem); overflow: auto; }
nav h2 { font-size: .75rem; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin: .2rem 0 .6rem; }
nav ol { list-style: none; margin: 0 0 1rem; padding: 0; }
nav li a { display: flex; gap: .5rem; align-items: baseline; color: var(--ink);
  text-decoration: none; padding: .15rem .3rem; border-radius: .3rem; font-size: .88rem; }
nav li a:hover { background: var(--code); }
nav .sec { margin: .9rem 0 .25rem .3rem; font-size: .92rem; font-weight: 600; }
nav .sec a { color: var(--ink); text-decoration: none; }
nav .sec a:hover { color: var(--accent); }
.dot { width: .55rem; height: .55rem; border-radius: 50%; flex: none; transform: translateY(-.05rem); }
.dot.pass { background: var(--pass); } .dot.fail { background: var(--fail); }
section.group { margin-bottom: 2.2rem; }
section.group > h2 { font-size: 1.2rem; margin: 0 0 .25rem; }
section.group > p { color: var(--muted); margin: 0 0 .9rem; max-width: 52rem; }
.step { background: var(--card); border: 1px solid var(--line); border-left: 4px solid var(--pass);
  border-radius: .6rem; padding: .8rem 1rem; margin-bottom: .9rem; }
.step.fail { border-left-color: var(--fail); }
.step header { display: flex; align-items: center; gap: .6rem; }
.step h3 { font-size: 1rem; margin: 0; flex: 1; }
.num { font: 600 .75rem ui-monospace, monospace; color: var(--muted); background: var(--code);
  border-radius: .3rem; padding: .05rem .4rem; }
.badge { font-size: .7rem; font-weight: 700; letter-spacing: .04em; padding: .1rem .5rem; border-radius: .3rem; }
.badge.pass { background: var(--pass-bg); color: var(--pass); }
.badge.fail { background: var(--fail-bg); color: var(--fail); }
.facts { display: flex; gap: 1rem; color: var(--muted); font-size: .8rem; margin: .2rem 0 .5rem; }
pre { background: var(--code); border-radius: .4rem; padding: .6rem .8rem; margin: .3rem 0;
  overflow-x: auto; font-size: .8rem; line-height: 1.45; white-space: pre; }
pre.cmd { font-size: .85rem; white-space: pre-wrap; word-break: break-word; }
.prompt { color: var(--accent); user-select: none; }
details.out { margin: .35rem 0; }
details.out summary { cursor: pointer; font-size: .85rem; font-weight: 600; color: var(--ink); }
details.out summary .count { color: var(--muted); font-weight: 400; font-size: .78rem; margin-left: .3rem; }
details.trace pre, details.server pre { max-height: 28rem; }
details.trace pre { white-space: pre-wrap; overflow-wrap: anywhere; }
details.trace .ln { display: block; padding-left: 10.5em; text-indent: -10.5em; }
.t { color: var(--muted); }
.lv { font-weight: 700; }
.lv.trace { color: var(--trace); } .lv.debug { color: var(--debug); } .lv.info { color: var(--info); }
.lv.warn { color: var(--warn); } .lv.error { color: var(--error); }
footer { color: var(--muted); font-size: .8rem; margin-top: 2rem; }
ul.expect { list-style: none; margin: .3rem 0 .4rem; padding: 0; font-size: .82rem; }
ul.expect li { display: flex; gap: .45rem; align-items: baseline; }
ul.expect .mark { font-weight: 700; width: 1em; }
ul.expect .found .mark { color: var(--pass); }
ul.expect .missing .mark { color: var(--fail); }
ul.expect .missing code { color: var(--fail); }
figure.capture { margin: 0 0 1rem; }
figure.capture .frame { border-radius: .6rem; overflow: hidden; }
figure.capture svg { display: block; width: 100%; height: auto; }
figure.capture .replay { margin-top: .35rem; font: 600 .78rem system-ui, sans-serif;
  color: var(--muted); background: none; border: 1px solid var(--line);
  border-radius: .4rem; padding: .15rem .6rem; cursor: pointer; }
figure.capture .replay:hover { color: var(--ink); background: var(--code); }
"""


CAPTURE_SCRIPT = """<script>
// Restart a capture: replace the SVG with a copy of itself, which resets
// every SMIL/CSS clock to zero.  A capture plays once, when it first
// scrolls into view; the button plays it again.
(function () {
  function play(figure) {
    var frame = figure.querySelector('.frame');
    var svg = frame.querySelector('svg');
    if (!svg) return;
    var fresh = svg.cloneNode(true);
    frame.replaceChild(fresh, svg);
    var t = fresh.getCurrentTime ? fresh.getCurrentTime() : 0;
    try { fresh.beginElement && fresh.beginElement(); } catch (e) {}
    try { fresh.setCurrentTime && fresh.setCurrentTime(0); } catch (e) {}
  }
  var figures = Array.prototype.slice.call(document.querySelectorAll('[data-capture]'));
  figures.forEach(function (figure) {
    var button = figure.querySelector('.replay');
    if (button) button.addEventListener('click', function () { play(figure); });
    var seen = false;
    if (!('IntersectionObserver' in window)) return;
    new IntersectionObserver(function (entries, obs) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting && !seen) {
          seen = true;
          play(figure);
          obs.disconnect();
        }
      });
    }, { threshold: 0.35 }).observe(figure);
  });
})();
</script>"""


def render_html(data, commit, captures):
    steps = data["steps"]
    session = data["session"]
    passed = sum(1 for s in steps if s["passed"])
    ok = bool(steps) and passed == len(steps)
    total_ms = sum(s["ms"] for s in steps)
    generated = (
        datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    )

    nav = []
    for sec_n, sec in enumerate(data["sections"], start=1):
        nav.append(f'<div class="sec"><a href="#section-{sec_n}">{esc(sec["title"])}</a></div><ol>')
        for s in sec["steps"]:
            state = "pass" if s["passed"] else "fail"
            nav.append(
                f'<li><a href="#step-{s["n"]}"><span class="dot {state}"></span>'
                f'{esc(s["title"])}</a></li>'
            )
        nav.append("</ol>")

    body = []
    sections_with_captures = set()
    for i, sec in enumerate(data["sections"], start=1):
        capture = captures.get(i)
        if capture:
            sections_with_captures.add(i)
        body.append(
            f'<section class="group" id="section-{i}"><h2>{esc(sec["title"])}</h2>'
            f'<p>{esc(sec["text"])}</p>'
            + (capture_html(i, capture) if capture else "")
            + "".join(render_step(s) for s in sec["steps"])
            + "</section>"
        )

    facts = [
        ("Steps", f"{passed} / {len(steps)} passed"),
        ("Time in steps", seconds(total_ms)),
        ("Realm", session.get("realm", "")),
        ("Trusted realm", session.get("trusted_realm", "")),
    ]
    if commit:
        facts.append(("Commit", commit[:12]))
    facts_html = "".join(f"<div><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in facts)
    verdict = "All steps passed" if ok else failed_text(len(steps) - passed)

    setup = "\n".join(
        f"{k}: {session[k]}" for k in ("servers", "anchor", "trace") if k in session
    )
    servers_log = block("The servers' whole log", data["servers_log"], cls="server")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kuipa playground report</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<nav>
  <h2>Steps</h2>
  {''.join(nav)}
</nav>
<main>
  <h1>kuipa playground session</h1>
  <p class="sub">A scripted session in the throwaway playground realm, with tracing on.
     Generated {esc(generated)}.</p>
  <div class="overall">
    <span class="verdict {'pass' if ok else 'fail'}">{esc(verdict)}</span>
    <dl>{facts_html}</dl>
  </div>
  <section class="group">
    <h2>Playground</h2>
    <p>An MIT KDC for each realm and two IPA servers, ipa1 and ipa2, running the daemon's
       HTTP router; each host has its own root directory. Thumbprints, ports and timings
       differ in every run.</p>
    <pre>{esc(setup)}</pre>
    {servers_log}
  </section>
  {''.join(body)}
  <footer>Rendered by contrib/ci/playground/report.py from contrib/ci/playground/session.sh.</footer>
</main>
</div>
{CAPTURE_SCRIPT if sections_with_captures else ""}
</body>
</html>
"""


def render_summary(data, artifact):
    steps = data["steps"]
    passed = sum(1 for s in steps if s["passed"])
    ok = bool(steps) and passed == len(steps)
    lines = [
        "## kuipa playground session",
        "",
        f"**{'✅ All steps passed' if ok else '❌ ' + failed_text(len(steps) - passed)}**"
        f" ({passed}/{len(steps)}). The full report, with every step's output and trace,"
        f" is this run's `{artifact}` artifact.",
        "",
        "| # | Section | Step | Result | Status | Time |",
        "|---:|---|---|---|---:|---:|",
    ]
    for s in steps:
        mark = "✅" if s["passed"] else "❌"
        lines.append(
            f"| {s['n']} | {md(s['section'])} | {md(s['title'])} | {mark}"
            f" | {md(status_text(s))} | {seconds(s['ms'])} |"
        )
    failed = [s for s in steps if not s["passed"]]
    for s in failed:
        lines += [
            "",
            f"<details><summary>❌ {md(s['title'])}</summary>",
            "",
            *(f"Missing from the output: `{md(t)}`" for t in s["missing"]),
            "",
            f"<pre>$ {esc(s['command'])}\n\n{esc(s['stdout'][-3000:])}\n{esc(s['stderr'][-3000:])}</pre>",
            "",
            "</details>",
        ]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("--html")
    ap.add_argument("--svg", help="directory of terminal captures (from render-terminal.mjs) to embed")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--commit", default="")
    ap.add_argument("--artifact", default="kuipa-playground-report")
    args = ap.parse_args()
    data = load(args.out)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(data, args.commit, load_captures(args.svg)))
        print(f"[playground-report] wrote {args.html}", file=sys.stderr)
    if args.summary:
        sys.stdout.write(render_summary(data, args.artifact))
    return 0


if __name__ == "__main__":
    sys.exit(main())
