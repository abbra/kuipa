#!/usr/bin/env python3
"""Report lemmas that can only hold vacuously.

A trace formula can refer only to action facts (the facts a rule puts in its
`--[ ... ]->` label). A fact that appears only in a rule's premises or
conclusions is observable at no trace index, so a lemma whose antecedent is such
a fact at `@ t` is vacuously true and reports as verified.

Usage: contrib/ci/vacuity-check.py THEORY.spthy...
Exit status 1 if any lemma is flagged.
"""
import re
import sys

ACTION = re.compile(r"--\[(.*?)\]->", re.S)
HEAD = re.compile(r"([A-Z][A-Za-z0-9_]*)\s*\([^)]*\)\s*@[a-z]")
LEMMA = re.compile(r"(?m)^lemma\s+(\w+)[^\n]*:?\s*(all-traces\s*|exists-trace\s*)?\"(.*?)\"", re.S)


# A trace formula can refer only to action facts. K is the attacker-knowledge
# action emitted by the built-in deduction rule, so a secrecy lemma over K(x) @ j
# is not vacuous. In/Out/Fr are ordinary facts, never actions: a witness over one
# of them is unreachable and its lemma is refuted (verified on a two-rule
# theory: a witness over a conclusion-only Tok(y) reports "no trace found", the
# same lemma over an action fact verifies).
BUILTIN_ACTIONS = {"K"}


def check(path):
    src = open(path).read()
    actions = set(BUILTIN_ACTIONS)
    for m in ACTION.finditer(src):
        actions.update(re.findall(r"([A-Z][A-Za-z0-9_]*)\s*\(", m.group(1)))
    flagged = []
    for name, kind, body in LEMMA.findall(src):
        unknown = sorted({h for h in HEAD.findall(body) if h not in actions})
        if unknown:
            # all-traces: the antecedent is unsatisfiable, so the lemma holds
            # vacuously. exists-trace: the witness is unreachable, so it fails.
            how = "witness unreachable via" if "exists-trace" in kind else "vacuous via"
            flagged.append((name, how, unknown))
    return flagged


bad = 0
for path in sys.argv[1:]:
    for name, how, heads in check(path):
        print(f"{path}: {name} {how} non-action facts {heads}")
        bad = 1
sys.exit(bad)
