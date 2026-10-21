#!/usr/bin/env python3
"""Turn the recorded playground session into animated terminal captures.

Usage:
    terminal.py OUT [--json SPEC.json] [--max-chars N] [--max-lines N]

OUT is the directory session.sh wrote (see report.py).  The JSON spec
written to stdout or --json describes one terminal capture per session
section, in the shape render-terminal.mjs consumes: for each section, a
title and a list of sequences — a typed command line (with the prompt the
playground shell would show, `[kuipa HOST] $`), then its output lines —
plus the per-capture timing.  Output that would flood the capture is
capped (the middle lines of long steps collapse to a `… N more lines`
marker), expected text is highlighted green, error lines red.

The captures are renderings of what the session already recorded, so
they are deterministic: no replay, no second run of the playground.
"""

import argparse
import json
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from report import load  # noqa: E402  (the loader report.py renders from)

# svg-terminal's inline markup: [[fg:red]]…[[/fg]].  Real output that
# contains the opening tag must be defused or it would style itself.
MARKUP_OPEN = "[["

# A trace line from KUIPA_TRACE: leading elapsed time, then the level.
TRACE = re.compile(r"^\s*\d+(?:\.\d+)?s\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s")

# Commands that switch the host the shell acts as; the capture's prompt
# follows along, the way the playground's PS1 does.
HOST_SWITCH = re.compile(r"\b(?:pq_host|pq_enroll|pq_password|pq_offline|pq_voucher)\s+(\w+)")

# Text that marks an output line as an error (case-insensitive).
ERROR_WORDS = re.compile(
    r"\b(?:error|failed|failure|refused|unreachable|refuse|missing|wrong|"
    r"no server|cannot|timed out)\b", re.I
)

MAX_CHARS_DEFAULT = 100  # wrap width for output lines
MAX_LINES_DEFAULT = 14  # lines shown per step before collapsing the middle


def slugify(title):
    """A filename-safe, stable slug for a section title."""
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug[:48] or "section"


def host_of(command):
    """The host the shell acts as after COMMAND, or None if it stays."""
    m = HOST_SWITCH.search(command)
    return m.group(1) if m else None


def defuse(line):
    """Make a line safe for svg-terminal's [[…]] markup."""
    return line.replace(MARKUP_OPEN, "[ [", 1) if MARKUP_OPEN in line else line


def wrap(text, width):
    """Wrap one line at WIDTH characters, continuing at its indentation."""
    if len(text) <= width:
        return [text]
    indent = re.match(r"\s*", text).group(0)
    if len(indent) >= width:
        indent = ""
    out = []
    while text:
        cut = text[:width]
        if len(text) > width:
            split = cut.rfind(" ")
            if split > len(indent):
                cut = cut[:split]
        out.append(cut)
        text = text[len(cut):].lstrip()
        if text:
            text = indent + text
    return out


def markup_line(line, expect, failed):
    """One output line as svg-terminal markup, with what it proves colored.

    Green: text the step required in its output (the `expect` lines).
    Red: trace ERROR lines, and the tail of a failed step.
    """
    line = defuse(line)
    if any(e and e in line for e in expect):
        return f"[[fg:green]]{line}[[/fg]]"
    if TRACE.match(line) and "ERROR" in TRACE.match(line).group(1):
        return f"[[fg:red]]{line}[[/fg]]"
    if failed and not TRACE.match(line) and ERROR_WORDS.search(line):
        return f"[[fg:red]]{line}[[/fg]]"
    return line


def step_body(step):
    """The lines a step's capture shows, standard output first.

    Standard output is what a terminal shows under the command; when a
    step wrote none, its standard error is — the trace (KUIPA_TRACE) is
    where kuipa's tools narrate what they do, so a silent step still
    shows its last few trace lines rather than nothing.  A failed step
    ends with its error output: the reason it failed is what a person
    scrolling the capture wants to see.
    """
    stdout, stderr = step["stdout"].rstrip("\n"), step["stderr"].rstrip("\n")
    if not step["passed"]:
        body = stdout
        if stderr:
            body = f"{body}\n{stderr}" if body else stderr
        return body
    if stdout:
        return stdout
    # A passed step that printed nothing to standard output: show the
    # tail of its trace, dimmed as trace lines by markup_line.
    return "\n".join(stderr.splitlines()[-3:]) if stderr else ""


def step_sequences(step, max_chars, max_lines):
    """The sequences for one step: a typed command, then capped output.

    Failed steps show the tail of their error output instead of the head
    of their standard output: the reason a step failed is what a person
    scrolling the capture wants to see.
    """
    seq = []
    lines = step_body(step).splitlines()
    shown = lines
    marker = None
    if len(lines) > max_lines:
        head = max(1, max_lines // 3)
        tail = max(1, max_lines - head - 1)
        shown = lines[:head] + lines[-tail:]
        marker = len(lines) - head - tail
    out = []
    for line in shown:
        # Mark up the line as a whole, then wrap: a highlight covers every
        # piece the wrap splits it into, so a sentence stays one color.
        marked = markup_line(line, step["expect"], not step["passed"])
        color = re.match(r"^\[\[fg:(\w+)\]\]", marked)
        for piece in wrap(marked, max_chars + (len(marked) - len(line))):
            if color:
                piece = re.sub(r"^\[\[fg:\w+\]\]|\[\[/fg\]\]$", "", piece)
                piece = f"[[fg:{color.group(1)}]]{piece}[[/fg]]"
            out.append(piece)
    if out and not step["passed"]:
        # A failed step ends with the tool's verdict on what went wrong;
        # it is always red, whatever words it uses.
        if not out[-1].startswith("[["):
            out[-1] = f"[[fg:red]]{out[-1]}[[/fg]]"
    if marker:
        out.append(f"[[dim]]… {marker} more line{'s' if marker != 1 else ''} (see the report)[[/dim]]")
    if out:
        seq.append({"type": "output", "content": "\n".join(out)})
    return seq


def command_sequences(command, prompt, max_chars):
    """A command as typed sequences: the line with its prompt, and the
    continuation lines a wrap at MAX_CHARS makes, typed like bash shows
    them (after the prompt's width, as its PS2 continuation would be).

    svg-terminal types each sequence on its own line and clips what runs
    past the window, so an unwrapped long command would simply lose its
    end; splitting keeps every character typed and visible.
    """
    pieces = wrap(command, max_chars)
    seqs = [{"type": "command", "content": pieces[0], "prompt": prompt}]
    # The continuation needs the prompt's width kept free, or the typed
    # text would start under where the prompt ends.
    cont_pad = " " * (len(prompt) - 2) if len(prompt) > 2 else ""
    for piece in pieces[1:]:
        seqs.append(
            {"type": "command", "content": f"{cont_pad}> {piece}", "prompt": ""}
        )
    return seqs


def section_spec(index, section, max_chars, max_lines):
    """One capture: the section's steps as a terminal session."""
    host = None
    sequences = []
    for step in section["steps"]:
        new_host = host_of(step["command"])
        prompt = f"[kuipa {new_host}] $ " if new_host else (
            f"[kuipa {host}] $ " if host else "$ "
        )
        if new_host:
            host = new_host
        cmd_seqs = command_sequences(step["command"], prompt, max_chars)
        sequences.extend(cmd_seqs)
        sequences.extend(step_sequences(step, max_chars, max_lines))
    return {
        "index": index,
        "slug": slugify(section["title"]),
        "title": section["title"],
        "text": section["text"],
        "sequences": sequences,
    }


def build(out_dir, max_chars, max_lines):
    data = load(out_dir)
    return [
        section_spec(i + 1, sec, max_chars, max_lines)
        for i, sec in enumerate(data["sections"])
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", help="the directory session.sh wrote")
    ap.add_argument("--json", help="write the spec here instead of stdout")
    ap.add_argument("--max-chars", type=int, default=MAX_CHARS_DEFAULT,
                    help=f"wrap output lines at this width (default {MAX_CHARS_DEFAULT})")
    ap.add_argument("--max-lines", type=int, default=MAX_LINES_DEFAULT,
                    help=f"lines shown per step before the middle collapses (default {MAX_LINES_DEFAULT})")
    args = ap.parse_args()
    spec = build(args.out, args.max_chars, args.max_lines)
    payload = json.dumps(spec, indent=1)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
        print(f"[playground-terminal] wrote {args.json} ({len(spec)} sections)", file=sys.stderr)
    else:
        sys.stdout.write(payload + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
