"""Differential oracles for the checks.

Two independent reimplementations, compared against the engine and the
structural checks on every example spec:

1. A brute-force path enumerator for the path-sensitive checks (C2, C4,
   C5, C6). It replays every execution path and records the violations it
   meets, then must agree exactly with the worklist engine.

2. A structural micro-oracle for C1 and C3, reimplemented from the grammar
   rules, compared against check_c1/check_c3. (This is what would have
   caught the C1 dead-guard false negative: it walks the live prefix
   independently.)

Independence scope: the oracle shares the AST node classes and the term
accessors (var_names/bare_var_names) with the package, and its per-action
transfer rules are derived from the same documented semantics as the
engine's domains. It is independent in (a) exploration strategy - recursive
path enumeration versus a deduplicated worklist to fixpoint - and (b)
intra-state flow-end logic, which it reimplements below rather than
importing model.live_actions. It does NOT independently re-derive the
transfer-rule definitions.

Enumeration is exact for the example corpus, which is acyclic. Caps on
depth and visit count fail the test loudly if the corpus ever stops being
trivially enumerable, rather than silently truncating.
"""
from pathlib import Path

import pytest

from dsl_seccheck import parse
from dsl_seccheck import engine as eng
from dsl_seccheck.checks import (
    AuthDomain,
    TaintDomain,
    VerifiedDomain,
    check_all,
    check_c1,
    check_c3,
)
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
    var_names,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "differential"
# Differential coverage runs over the example corpus PLUS timeout-fact-bearing
# fixtures whose timeout targets actually use the carried variables (the
# examples all time out into an empty Abort, so the timeout fact is invisible
# there - this is the blind spot 0.3.1 closes).
ALL_SPECS = sorted(EXAMPLES.glob("*.dsl")) + sorted(FIXTURES.glob("*.dsl"))
VISIT_CAP = 10_000
DEPTH_CAP = 60


# --- intra-state control flow, reimplemented from the grammar ------------------
# Independent of model.live_actions/edge_targets. A state's linear flow ends
# at an unconditional goto, or at a verify/authenticate whose success jumps
# (has an ok target); actions past that point can never run.

def _flow_ends(a) -> bool:
    return isinstance(a, Goto) or (
        isinstance(a, (Verify, Authenticate)) and a.ok_target is not None
    )


def _live(actions):
    live = []
    for a in actions:
        live.append(a)
        if _flow_ends(a):
            break
    return live


def _edges(st) -> list[str]:
    targets: list[str] = []
    for a in _live(st.actions):
        if isinstance(a, (Timeout, Goto)):
            targets.append(a.target)
        elif isinstance(a, (Verify, Authenticate)):
            targets += [t for t in (a.ok_target, a.fail_target) if t]
    return targets


# --- path-sensitive oracle (C2, C4, C5, C6) ------------------------------------

def oracle_findings(spec) -> set[tuple[str, str, int]]:
    found: set[tuple[str, str, int]] = set()
    visits = 0

    def walk(state_name, taint, unverified, authed, secrets, depth) -> None:
        nonlocal visits
        assert depth < DEPTH_CAP, "oracle depth cap hit; corpus not enumerable"
        visits += 1
        assert visits < VISIT_CAP, "oracle visit cap hit; corpus not enumerable"

        st = spec.states[state_name]
        if st.trusted and not authed:
            found.add(("C5", st.name, st.line))

        taint = set(taint)
        unverified = set(unverified)
        secrets = set(secrets)
        # fact as of the nearest preceding receive blocking; None until one
        # is seen. A timeout carries this, matching the engine's exact
        # timeout-edge semantics.
        pre_receive = None
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

        for a in _live(st.actions):
            if isinstance(a, Receive):
                pre_receive = snapshot(authed)
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
                branches.append((a.target,
                                 pre_receive if pre_receive is not None
                                 else snapshot(authed)))
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


@pytest.mark.parametrize("path", ALL_SPECS, ids=lambda p: p.name)
def test_engine_matches_brute_force_oracle(path: Path) -> None:
    spec = parse(path.read_text(encoding="utf-8"))
    assert engine_findings(spec) == oracle_findings(spec)


# --- structural micro-oracle (C1, C3) ------------------------------------------

def micro_c1(spec) -> set[tuple[str, str, int]]:
    out: set[tuple[str, str, int]] = set()
    for st in spec.states.values():
        pending = None
        for a in _live(st.actions):        # live prefix only, like the check
            if isinstance(a, Receive):
                if pending is not None:
                    out.add(("C1", st.name, pending.line))
                pending = a
            elif isinstance(a, Timeout):
                pending = None
        if pending is not None:
            out.add(("C1", st.name, pending.line))
    return out


def micro_c3(spec) -> set[tuple[str, str, int]]:
    out: set[tuple[str, str, int]] = set()
    for st in spec.states.values():
        for a in st.actions:
            if not isinstance(a, Verify):
                continue
            ft = a.fail_target
            if ft is None:
                out.add(("C3", st.name, a.line))
                continue
            tgt = spec.states[ft]
            terminal = ("deny" in tgt.flags) or ("abort" in tgt.flags)
            if not terminal or _edges(tgt):
                out.add(("C3", st.name, a.line))
    return out


def _real(findings) -> set[tuple[str, str, int]]:
    return {(f.check, f.state, f.line) for f in findings}


@pytest.mark.parametrize("path", ALL_SPECS, ids=lambda p: p.name)
def test_structural_checks_match_micro_oracle(path: Path) -> None:
    spec = parse(path.read_text(encoding="utf-8"))
    assert _real(check_c1(spec)) == micro_c1(spec)
    assert _real(check_c3(spec)) == micro_c3(spec)


# Expected findings pin the timeout-fact semantics directly (not just oracle
# agreement). Each fixture's timeout target uses the carried variables.
EXPECTED_FIXTURE_FINDINGS = {
    # (a) token still secret on the timeout edge -> C4 at the send
    "timeout_a_single_receive_clears_secret.dsl": [("C4", "Leak")],
    # (b) first receive's p present (C6), second receive's q absent (clean):
    #     exactly one finding
    "timeout_b_multi_receive_first_present_second_absent.dsl": [("C6", "Both")],
    # (c) authed survives onto the edge -> trusted entry is fine, no findings
    "timeout_c_auth_survives_onto_edge.dsl": [],
}


@pytest.mark.parametrize("name,expected", sorted(EXPECTED_FIXTURE_FINDINGS.items()))
def test_timeout_fixtures_pin_semantics(name: str, expected) -> None:
    spec = parse((FIXTURES / name).read_text(encoding="utf-8"))
    got = sorted((f.check, f.state) for f in check_all(spec))
    assert got == expected


# Adversarial structural specs the example corpus does not cover: the C1
# dead-guard shape (a timeout past the flow end) and the C3 escaping-deny
# shape. On these, the pre-fix check_c1 (walking st.actions) and pre-fix
# check_c3 (flag-only) would disagree with the micro-oracle - which is how
# the micro-oracle would have caught those findings.
STRUCTURAL_SPECS = [
    # dead timeout after a goto must not clear C1
    "state Init:\n    receive m(x)\n    -> Done\n    timeout -> Abort\n"
    "state Done: terminal\nstate Abort: abort\n",
    # deny fail target that escapes via a goto is not terminal (C3)
    "state Init:\n    receive m(x)\n    timeout -> Abort\n"
    "    verify x ok -> Done fail -> Leaky\n"
    "state Leaky: deny\n    -> Done\n"
    "state Done: terminal\nstate Abort: abort\n",
    # clean multi-receive / guarded / truly-terminal case: no C1, no C3
    "state Init:\n    receive a(x)\n    timeout -> Abort\n"
    "    receive b(y)\n    timeout -> Abort\n"
    "    verify x ok -> Done fail -> Deny\n"
    "state Done: terminal\nstate Deny: deny\nstate Abort: abort\n",
]


@pytest.mark.parametrize("text", STRUCTURAL_SPECS)
def test_structural_micro_oracle_on_adversarial_specs(text: str) -> None:
    spec = parse(text)
    assert _real(check_c1(spec)) == micro_c1(spec)
    assert _real(check_c3(spec)) == micro_c3(spec)
