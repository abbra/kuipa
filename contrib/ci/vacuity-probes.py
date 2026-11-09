#!/usr/bin/env python3
"""vacuity-probes.py -- is an open lemma's antecedent reachable at all?

A universal lemma "All x. P(x) ==> Q(x)" says nothing when no trace satisfies P.
vacuity-check.py catches the other failure mode (a lemma keyed on a fact that is
not an action fact, observable at no index). This catches the remaining one: a
lemma over real action facts whose antecedent may be unsatisfiable. When a proof
times out, the status of such a lemma is unknown -- it is neither established nor
known to be vacuous, and the difference matters for what the file claims.

For every lemma given (or every lemma matching -k), this writes an exists-trace
asking only for the antecedent:

    lemma name [use_induction]:
      "All x. A(x) ==> Q(x)"
    ->
    lemma probe_name: exists-trace
      "Ex x. A(x)"

Run the result with contrib/ci/proofs.sh:

    ok    the antecedent is reachable, so the lemma carries real content
    FALSE no trace satisfies the antecedent -- the lemma holds VACUOUSLY, and its
          proof status is uninteresting; say so in the header instead of leaving
          it as an open obligation
    OPEN  unknown (search exhausted the limit)

Usage: vacuity-probes.py [-k REGEX] [-o OUT.spthy] THEORY.spthy
Exit 0 if any probe was generated, 1 if none (e.g. all targets are witnesses).
"""
import argparse
import pathlib
import re
import sys

LEMMA = re.compile(r'(?m)^lemma\s+([A-Za-z_]\w*)([^\n]*)$')
WITNESS = re.compile(r'exists-trace')


def read_lemma(src, start):
    """Return (name, attrs, formula, formula_span) for the lemma at `start`.

    The formula's opening quote may sit on the lemma's own header line
    ("lemma w: exists-trace \\"Ex …\\"") or on a following line; a lemma with no
    formula at all (or none before the theory's `end`) is skipped.
    """
    m = LEMMA.match(src, start)
    if not m:
        return None
    head = src[m.start():m.end()]
    if '"' in head:
        q = m.start() + head.index('"')
    else:
        q = src.find('"', m.end())
    theory_end = re.search(r'(?m)^end\s*$', src[m.end():])
    if q < 0 or (theory_end and m.end() + theory_end.start() < q):
        return None
    i = q + 1
    while i < len(src) and src[i] != '"':
        i += 1
    if i >= len(src):
        return None
    return m.group(1), m.group(2), src[q + 1:i], (q, i + 1)


def split_top(formula, sep):
    """Split on the first top-level occurrence of sep (ignoring nesting).

    Only parentheses and square brackets count for nesting: '<' and '>' are both
    tuple delimiters and comparison operators ('#i < #j'), and every tuple in a
    guarded formula sits inside a function's parentheses, so angle brackets would
    be counted twice and never closed.
    """
    depth = 0
    j = 0
    while j < len(formula):
        c = formula[j]
        if c in '([':
            depth += 1
        elif c in ')]':
            depth -= 1
        elif depth == 0 and formula.startswith(sep, j):
            return formula[:j], formula[j + len(sep):]
        j += 1
    return None, None


def split_disjuncts(formula):
    """Every top-level disjunct of the antecedent, in order."""
    out, rest = [], formula
    while True:
        left, right = split_top(rest, '|')
        if right is None:
            out.append(rest)
            return out
        out.append(left)
        rest = right


BINDER = re.compile(r'^\s*All\s+(.*?)\.\s', re.S)


def probes_for(name, src, start):
    """[(probe_name, binder, antecedent)] for one lemma; [] if not applicable."""
    lemma = read_lemma(src, start)
    if not lemma:
        return []
    lname, attrs, formula, (q, _) = lemma
    between = src[LEMMA.match(src, start).end():q]
    if 'exists-trace' in attrs or 'exists-trace' in between:
        return []                       # already a witness: no antecedent
    m = BINDER.match(formula)
    if not m:
        return []                       # no quantifier prefix to re-bind
    binder = m.group(1).strip()
    body = formula[m.end():]
    ante, cons = split_top(body, '==>')
    if cons is None:
        ante = body                     # no implication: ask for the formula itself
    ante = ante.strip()
    disjuncts = split_disjuncts(ante)
    if len(disjuncts) == 1:
        return [(f'probe_{name}', binder, disjuncts[0])]
    return [(f'probe_{name}_d{i}', binder, d.strip())
            for i, d in enumerate(disjuncts, 1)]


def self_test():
    """Parser regression checks (no prover). Run: vacuity-probes.py --self-test"""
    src = '''theory t
begin
rule a: [ Fr(~x) ] --[ Aa(~x) ]-> [ Bb(~x) ]
lemma w_same_line: exists-trace "Ex x #i. Aa(x) @i"
lemma multi:
  "All x #i #j. Aa(x) @i & Bb(x) @j & #i < #j ==> not (#j < #i)"
lemma disj:
  "All x #i. Aa(x) @i | Bb(x) @i ==> Ex #k. Aa(x) @k"
lemma no_conclusion:
  "All x #i. Aa(x) @i"
end
'''
    def chk(cond, what):
        if not cond:
            raise AssertionError(what)

    got = {}
    for m in LEMMA.finditer(src):
        for name, binder, ante in probes_for(m.group(1), src, m.start()):
            got[name.replace('probe_', '')] = (binder, ' '.join(ante.split()))
    chk('w_same_line' not in got, 'a witness lemma must not be probed')
    # '#i < #j' must not be counted as nesting, or the ==> is never found.
    chk(got['multi'] == ('x #i #j', 'Aa(x) @i & Bb(x) @j & #i < #j'),
        f'antecedent of a guarded comparison split wrong: {got.get("multi")}')
    d = sorted(v[1] for k, v in got.items() if k.startswith('disj'))
    chk(d == ['Aa(x) @i', 'Bb(x) @i'], f'disjuncts not split: {d}')
    chk(got['no_conclusion'] == ('x #i', 'Aa(x) @i'),
        'a lemma with no ==> should ask for the whole body')

    # A formula with no quote before `end` (a stub) must be skipped, not crash.
    stub = 'theory s\nbegin\nlemma bad:\nend\n'
    for m in LEMMA.finditer(stub):
        chk(probes_for(m.group(1), stub, m.start()) == [], 'stub lemma must be skipped')
    print('self-test ok')
    return 0


def main():
    if sys.argv[1:] == ['--self-test']:
        return self_test()
    ap = argparse.ArgumentParser()
    ap.add_argument('-k', dest='filter', default='', help='lemma name regex')
    ap.add_argument('-o', dest='out', help='output theory (default THEORYY-probes.spthy)')
    ap.add_argument('theory')
    a = ap.parse_args()

    path = pathlib.Path(a.theory)
    src = path.read_text()
    starts = [m.start() for m in LEMMA.finditer(src)]
    picked = []
    for s in starts:
        name = LEMMA.match(src, s).group(1)
        if a.filter and not re.search(a.filter, name):
            continue
        picked.append((name, s))

    out_path = pathlib.Path(a.out) if a.out else path.with_name(path.stem + '-probes.spthy')
    blocks, skipped = [], []
    for name, s in picked:
        got = probes_for(name, src, s)
        if not got:
            skipped.append(name)
            continue
        for pname, binder, ante in got:
            one = ' '.join(ante.split())
            blocks.append(
                f'// antecedent reachability for {name}\n'
                f'lemma {pname}: exists-trace\n'
                f'  "Ex {binder}. {one}"')
    if not blocks:
        print(f'no antecedent probes generated from {path}')
        return 1

    end = src.rindex('end')
    theory = re.search(r'(?m)^theory\s+(\w+)', src)
    patched = (src[:end] + '\n'.join(blocks) + '\n' + src[end:])
    if theory:
        patched = patched.replace(
            f'theory {theory.group(1)}', f'theory {theory.group(1)}_probe', 1)
    out_path.write_text(patched)
    print(f'{out_path}: {len(blocks)} antecedent-reachability probes from '
          f'{len(picked)} lemmas')
    if skipped:
        print('not probed (witness or no All-prefix):', ' '.join(skipped))
    print('read the verdicts as: ok = the antecedent is reachable; '
          'FALSE = the lemma is vacuous; OPEN = unknown at that limit.')
    print('proofs.sh keys its per-theory flags to the BASENAME, so copy this to '
          'a scratch directory under the original file name before proving.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
