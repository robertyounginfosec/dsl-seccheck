"""Differential oracle for the path-sensitive checks.

A brute-force path enumerator, independent of the worklist engine, replays
every execution path of a spec under the language's defined semantics and
records the violations it meets. The engine must agree exactly, on every
example spec, for every path-sensitive check (C2, C4, C5, C6). Structural
checks (C1, C3) have no path dimension and are excluded.

Two scope notes:

- The oracle implements the language's DEFINED timeout-edge semantics
  (facts as of the timeout's position). It validates the engine against
  the language definition, not against physical blocking behavior; the
  gap between the two is characterized separately
  (test_timeout_taint_over_approximation_is_intended_over_reporting).
- Enumeration is exact for the example corpus, which is acyclic. Caps on
  depth and path count fail the test loudly if the corpus ever stops
  being trivially enumerable, rather than silently truncating.
"""
from pathlib import Path

import pytest

from dsl_seccheck import parse
from dsl_seccheck import engine as eng
from dsl_seccheck.checks import AuthDomain, TaintDomain, VerifiedDomain
from dsl_seccheck.model import (
    Assign,
    Authenticate,
    Goto,
    Receive,
    Send,
    Sink,
    Timeout,
    Verify,
    bare_var_names,
    live_actions,
    var_names,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
PATH_CAP = 10_000
DEPTH_CAP = 60


def oracle_findings(spec) -> set[tuple[str, str, int]]:
    found: set[tuple[str, str, int]] = set()
    paths = 0

    def walk(state_name, taint, unverified, authed, secrets, depth) -> None:
        nonlocal paths
        assert depth < DEPTH_CAP, "oracle depth cap hit; corpus not enumerable"
        paths += 1
        assert paths < PATH_CAP, "oracle path cap hit; corpus not enumerable"

        st = spec.states[state_name]
        if st.trusted and not authed:
            found.add(("C5", st.name, st.line))

        taint = set(taint)
        unverified = set(unverified)
        secrets = set(secrets)
        branches: list[tuple[str, tuple]] = []

        def snapshot(authed_now):
            return (set(taint), set(unverified), authed_now, set(secrets))

        def record_uses(expr, line):
            for n in var_names(expr):
                if n in unverified:
                    found.add(("C2", st.name, line))

        def record_disclosure(expr, line):
            if not authed:
                for n in var_names(expr):
                    if n in secrets:
                        found.add(("C4", st.name, line))

        for a in live_actions(st):
            if isinstance(a, Receive):
                taint |= set(a.fields)
                unverified |= set(a.fields)
            elif isinstance(a, Send):
                record_uses(a.expr, a.line)
                record_disclosure(a.expr, a.line)
            elif isinstance(a, Assign):
                record_uses(a.expr, a.line)
                if any(n in secrets for n in var_names(a.expr)):
                    secrets.add(a.target)
                else:
                    secrets.discard(a.target)
                if any(n in taint for n in bare_var_names(a.expr)):
                    taint.add(a.target)
                else:
                    taint.discard(a.target)
                unverified.discard(a.target)
            elif isinstance(a, Sink):
                record_uses(a.expr, a.line)
                record_disclosure(a.expr, a.line)
                for n in bare_var_names(a.expr):
                    if n in taint:
                        found.add(("C6", st.name, a.line))
            elif isinstance(a, Timeout):
                branches.append((a.target, snapshot(authed)))
            elif isinstance(a, Verify):
                if a.fail_target:
                    branches.append((a.fail_target, snapshot(authed)))
                unverified.discard(a.var)
                if a.ok_target:
                    branches.append((a.ok_target, snapshot(authed)))
            elif isinstance(a, Authenticate):
                if a.fail_target:
                    branches.append((a.fail_target, snapshot(authed)))
                if a.ok_target:
                    branches.append((a.ok_target, snapshot(True)))
                else:
                    authed = True
            elif isinstance(a, Goto):
                branches.append((a.target, snapshot(authed)))

        for target, (t, u, au, se) in branches:
            walk(target, t, u, au, se, depth + 1)

    walk(spec.initial, set(), set(), False, set(spec.secrets), 0)
    return found


def engine_findings(spec) -> set[tuple[str, str, int]]:
    found: set[tuple[str, str, int]] = set()
    for domain in (AuthDomain(spec), VerifiedDomain(spec), TaintDomain(spec)):
        for f in eng.run(spec, domain):
            found.add((f.check, f.state, f.line))
    return found


@pytest.mark.parametrize(
    "path", sorted(EXAMPLES.glob("*.dsl")), ids=lambda p: p.name
)
def test_engine_matches_brute_force_oracle(path: Path) -> None:
    spec = parse(path.read_text(encoding="utf-8"))
    assert engine_findings(spec) == oracle_findings(spec)
