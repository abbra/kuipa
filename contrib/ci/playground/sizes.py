#!/usr/bin/env python3
"""Request and response sizes per route, from a playground report.

The client's traces log every HTTP exchange as "GET …/ipa/ku/<route> (N
bytes)" followed by "200 OK: M bytes"; this pairs them and prints, per
route, how many there were and the smallest, median and largest request
and response.  docs/src/reference/sizing.md is built on its output.

Usage: sizes.py [kuipa-playground-report/index.html] [--steps]
  --steps  also print each step's totals and requests per route
"""
import collections
import html
import re
import sys


def steps(report: str):
    """(number, title, [(route, request bytes, response bytes)]) per step."""
    for m in re.finditer(r'<article class="step[^"]*" id="step-(\d+)">(.*?)</article>', report, re.S):
        body = m.group(2)
        title = html.unescape(re.search(r"<h3>(.*?)</h3>", body).group(1))
        trace = re.search(r'<details class="out trace"><summary>.*?</summary><pre>(.*?)</pre>', body, re.S)
        exchanges = []
        if trace:
            pending = []
            for line in html.unescape(re.sub(r"<[^>]+>", "\n", trace.group(1))).split("\n"):
                req = re.search(r"\b(?:GET|POST) \S*?/ipa/ku/([a-z\-]+)\S* \((\d+) bytes\)", line)
                if req:
                    pending.append((req.group(1), int(req.group(2))))
                    continue
                rsp = re.search(r"\d{3} [A-Za-z ]+: (\d+) bytes", line)
                if rsp and pending:
                    route, size = pending.pop(0)
                    exchanges.append((route, size, int(rsp.group(1))))
        yield int(m.group(1)), title, exchanges


def summary(values):
    values = sorted(values)
    return f"{values[0]}/{values[len(values) // 2]}/{values[-1]}"


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = args[0] if args else "kuipa-playground-report/index.html"
    with open(path) as f:
        report = f.read()
    per_route = collections.defaultdict(list)
    for n, title, exchanges in steps(report):
        for route, up, down in exchanges:
            per_route[route].append((up, down))
        if "--steps" in sys.argv and exchanges:
            count = collections.Counter(r for r, _, _ in exchanges)
            up = sum(u for _, u, _ in exchanges)
            down = sum(d for _, _, d in exchanges)
            print(f"{n:>3} up {up:>7} down {down:>7} {dict(count)} | {title}")
    print(f"{'route':<12} {'count':>5}  {'request min/median/max':<24} response min/median/max")
    for route, v in sorted(per_route.items()):
        print(f"{route:<12} {len(v):>5}  {summary([u for u, _ in v]):<24} {summary([d for _, d in v])}")


if __name__ == "__main__":
    main()
