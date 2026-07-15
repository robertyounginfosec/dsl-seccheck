"""The six checks.

C1 and C3 are structural: they hold or fail by the text of the spec alone.
C2, C4, C5, and C6 are path-sensitive and share the worklist engine, each
supplying its own fact domain:

- C4/C5 (AuthDomain): fact = (authenticated?, secret-carrying variables)
- C2   (VerifiedDomain): fact = received fields not yet verified
- C6   (TaintDomain): fact = tainted variables
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import engine
from .engine import DEFAULT_BUDGET, Finding
from .model import (
    Assign,
    Authenticate,
    Expr,
    Receive,
    Send,
    Sink,
    Spec,
    State,
    Timeout,
    Verify,
    bare_var_names,
    edge_targets,
    live_actions,
    var_names,
)

SINK_LABEL = {
    "query": "SQL injection",
    "exec": "OS command injection",
    "render": "cross-site scripting",
}


def check_all(spec: Spec, budget: int = DEFAULT_BUDGET) -> list[Finding]:
    findings: list[Finding] = []
    findings += check_c1(spec)
    findings += check_c3(spec)
    findings += engine.run(spec, AuthDomain(spec), budget)      # C4 + C5
    findings += engine.run(spec, VerifiedDomain(spec), budget)  # C2
    findings += engine.run(spec, TaintDomain(spec), budget)     # C6
    return sorted(set(findings), key=lambda f: (f.line, f.check, f.message))


def warn_all(spec: Spec) -> list[Finding]:
    """Structural warnings (W*): suspect spec shape, not security findings.

    Kept separate from check_all so "passes the checker" keeps meaning the
    six security properties; the CLI treats these as warnings unless
    --strict is passed.
    """
    warnings = (warn_w1(spec) + warn_w2(spec) + warn_w3(spec)
                + warn_w4(spec) + warn_w5(spec))
    return sorted(set(warnings), key=lambda f: (f.line, f.check, f.message))


# --- W1: actions after the linear flow has ended -------------------------------

def warn_w1(spec: Spec) -> list[Finding]:
    out: list[Finding] = []
    for st in spec.states.values():
        live = live_actions(st)
        if len(live) < len(st.actions):
            out.append(Finding(
                "W1", st.name, st.actions[len(live)].line,
                f"action can never execute: the linear flow ends at "
                f"line {live[-1].line}",
            ))
    return out


# --- W3 / W5: terminality shape -------------------------------------------------
# The two are converses and are kept as separate IDs for a precise message:
# W3 is a state that stops but is not marked terminal; W5 is a state marked
# terminal that does not stop. `deny`/`abort` imply `terminal` (parser), so
# the terminal test is membership of the `terminal` flag.

def warn_w3(spec: Spec) -> list[Finding]:
    """A state with no live outgoing edges halts there; if it is not marked
    terminal/deny/abort that is almost certainly an unintended dead-end."""
    return [
        Finding("W3", st.name, st.line,
                f"state '{st.name}' has no outgoing transition but is not "
                "marked terminal/deny/abort")
        for st in spec.states.values()
        if not edge_targets(st) and "terminal" not in st.flags
    ]


def warn_w5(spec: Spec) -> list[Finding]:
    """A terminal state that still has a live outgoing transition contradicts
    its own flag."""
    return [
        Finding("W5", st.name, st.line,
                f"state '{st.name}' is marked terminal but has an outgoing "
                "transition")
        for st in spec.states.values()
        if edge_targets(st) and "terminal" in st.flags
    ]


# --- W4: timeout that guards no receive ----------------------------------------

def warn_w4(spec: Spec) -> list[Finding]:
    """A timeout with no preceding receive in the live body guards nothing;
    its edge degenerates to the position fact. Almost always a spec
    mistake (a stray timeout, or a receive that was removed)."""
    out: list[Finding] = []
    for st in spec.states.values():
        seen_receive = False
        for a in live_actions(st):
            if isinstance(a, Receive):
                seen_receive = True
            elif isinstance(a, Timeout) and not seen_receive:
                out.append(Finding(
                    "W4", st.name, a.line,
                    f"timeout in state '{st.name}' guards no receive "
                    "(no preceding receive in the state body)",
                ))
    return out


# --- W2: states unreachable from the initial state ------------------------------

def warn_w2(spec: Spec) -> list[Finding]:
    reachable = {spec.initial}
    stack = [spec.initial]
    while stack:
        for target in edge_targets(spec.states[stack.pop()]):
            if target not in reachable:
                reachable.add(target)
                stack.append(target)
    return [
        Finding("W2", st.name, st.line,
                f"state '{st.name}' is unreachable from initial state "
                f"'{spec.initial}'")
        for st in spec.states.values() if st.name not in reachable
    ]


# --- C1: timeout-completeness (structural) -----------------------------------

def check_c1(spec: Spec) -> list[Finding]:
    """Each receive is its own blocking point, so each must be guarded by
    a timeout transition appearing after it and before the next receive;
    a single state-level timeout cannot escape an earlier block it is
    never reached from."""
    out: list[Finding] = []
    for st in spec.states.values():
        unguarded: Receive | None = None
        # walk live_actions, not st.actions: a timeout sitting past the
        # flow end can never execute, so it guards nothing
        for a in live_actions(st):
            if isinstance(a, Receive):
                if unguarded is not None:
                    out.append(_c1_finding(st, unguarded))
                unguarded = a
            elif isinstance(a, Timeout):
                unguarded = None
        if unguarded is not None:
            out.append(_c1_finding(st, unguarded))
    return out


def _c1_finding(st: State, a: Receive) -> Finding:
    return Finding(
        "C1", st.name, a.line,
        f"state '{st.name}' blocks on receive '{a.msg}' with no timeout "
        "transition guarding it",
    )


# --- C3: fail-closed verification (structural) --------------------------------

def check_c3(spec: Spec) -> list[Finding]:
    out: list[Finding] = []
    for st in spec.states.values():
        for a in st.actions:
            if not isinstance(a, Verify):
                continue
            if a.fail_target is None:
                out.append(Finding(
                    "C3", st.name, a.line,
                    f"verify '{a.var}' has no failure transition: failure "
                    "would halt in place, not fail closed",
                ))
            elif not spec.states[a.fail_target].fail_closed:
                out.append(Finding(
                    "C3", st.name, a.line,
                    f"verify '{a.var}' failure transition leads to "
                    f"'{a.fail_target}', which is not a terminal deny/abort "
                    "state",
                ))
            elif edge_targets(spec.states[a.fail_target]):
                # flagged deny/abort but has live outgoing edges, so control
                # escapes it: not actually terminal
                out.append(Finding(
                    "C3", st.name, a.line,
                    f"verify '{a.var}' failure transition leads to "
                    f"'{a.fail_target}', a deny/abort state that is not "
                    "terminal (it has outgoing transitions)",
                ))
    return out


# --- C4 + C5: authentication facts --------------------------------------------

@dataclass
class AuthDomain:
    """Fact: (authenticated, frozenset of secret-carrying variable names).

    Secrecy propagates through assignment and concatenation, and is NOT
    cleared by param()/sanitize(): those make a value injection-safe, not
    disclosure-safe.
    """
    spec: Spec

    def initial_fact(self):
        return (False, frozenset(self.spec.secrets))

    def enter_state(self, st: State, fact, out: list[Finding]) -> None:
        authed, _ = fact
        if st.trusted and not authed:
            out.append(Finding(
                "C5", st.name, st.line,
                f"trusted state '{st.name}' is reachable on a path with no "
                "successful authenticate step",
            ))

    def on_receive(self, a: Receive, fact, st: State, out) -> tuple:
        # A received field that shadows a secret-named variable keeps the
        # secret label: the over-report (a completed receive would clear
        # it) is the safe direction for a disclosure check, and it matches
        # the oracle, which likewise never clears secrets on receive.
        # (Timeout soundness no longer depends on this: timeout edges now
        # carry the fact from before the receive.)
        return fact

    def on_send(self, a: Send, fact, st: State, out: list[Finding]) -> tuple:
        authed, secrets = fact
        if not authed:
            for name in var_names(a.expr):
                if name in secrets:
                    out.append(Finding(
                        "C4", st.name, a.line,
                        f"secret '{name}' is sent on a path with no prior "
                        "successful authenticate step",
                    ))
        return fact

    def on_assign(self, a: Assign, fact, st: State, out) -> tuple:
        authed, secrets = fact
        if any(n in secrets for n in var_names(a.expr)):
            return (authed, secrets | {a.target})
        return (authed, secrets - {a.target})

    def on_sink(self, a: Sink, fact, st: State, out: list[Finding]) -> tuple:
        # writing a secret into a query/exec/render sink discloses it just
        # as a send does, so C4 covers sinks with the same auth gate
        authed, secrets = fact
        if not authed:
            for name in var_names(a.expr):
                if name in secrets:
                    out.append(Finding(
                        "C4", st.name, a.line,
                        f"secret '{name}' reaches {a.kind} sink on a path "
                        "with no prior successful authenticate step",
                    ))
        return fact

    def on_verify_ok(self, a: Verify, fact):
        return fact

    def on_verify_fail(self, a: Verify, fact):
        return fact

    def on_auth_ok(self, a: Authenticate, fact):
        authed, secrets = fact
        return (True, secrets)

    def on_auth_fail(self, a: Authenticate, fact):
        return fact


# --- C2: verify-exhaustiveness -------------------------------------------------

@dataclass
class VerifiedDomain:
    """Fact: frozenset of received fields not yet passed through verify.

    Any use of such a field (in a send, a sink, or the right-hand side of
    an assignment, whether bare or wrapped in param/sanitize) is an error:
    wrapping addresses injection, not semantic validity.
    """
    spec: Spec

    def initial_fact(self):
        return frozenset()

    def enter_state(self, st: State, fact, out) -> None:
        return None

    def _check_uses(self, expr: Expr, fact, st: State, line: int,
                    out: list[Finding]) -> None:
        for name in var_names(expr):
            if name in fact:
                out.append(Finding(
                    "C2", st.name, line,
                    f"received field '{name}' is used before passing a "
                    "verify step",
                ))

    def on_receive(self, a: Receive, fact, st: State, out):
        return fact | set(a.fields)

    def on_send(self, a: Send, fact, st: State, out):
        self._check_uses(a.expr, fact, st, a.line, out)
        return fact

    def on_assign(self, a: Assign, fact, st: State, out):
        self._check_uses(a.expr, fact, st, a.line, out)
        return fact - {a.target}  # assignment overwrites the target

    def on_sink(self, a: Sink, fact, st: State, out):
        self._check_uses(a.expr, fact, st, a.line, out)
        return fact

    def on_verify_ok(self, a: Verify, fact):
        return fact - {a.var}

    def on_verify_fail(self, a: Verify, fact):
        return fact

    def on_auth_ok(self, a: Authenticate, fact):
        return fact

    def on_auth_fail(self, a: Authenticate, fact):
        return fact


# --- C6: injection taint-tracking ----------------------------------------------

@dataclass
class TaintDomain:
    """Fact: frozenset of tainted variable names.

    Variables bound by ``receive`` are tainted. Taint propagates through
    assignment and concatenation. ``param(x)`` and ``sanitize(x)`` terms
    are clean at the point of use, so an assignment whose right side is
    only wrapped/literal terms produces a clean variable.
    """
    spec: Spec

    def initial_fact(self):
        return frozenset()

    def enter_state(self, st: State, fact, out) -> None:
        return None

    def on_receive(self, a: Receive, fact, st: State, out):
        return fact | set(a.fields)

    def on_send(self, a: Send, fact, st: State, out):
        return fact  # send is covered by C4, not by taint sinks

    def on_assign(self, a: Assign, fact, st: State, out):
        if any(n in fact for n in bare_var_names(a.expr)):
            return fact | {a.target}
        return fact - {a.target}

    def on_sink(self, a: Sink, fact, st: State, out: list[Finding]):
        for name in bare_var_names(a.expr):
            if name in fact:
                out.append(Finding(
                    "C6", st.name, a.line,
                    f"tainted value '{name}' reaches {a.kind} sink "
                    f"({SINK_LABEL[a.kind]}): pass it via param() or clear "
                    "it via sanitize()",
                ))
        return fact

    def on_verify_ok(self, a: Verify, fact):
        return fact  # verify is semantic validation, not sanitization

    def on_verify_fail(self, a: Verify, fact):
        return fact

    def on_auth_ok(self, a: Authenticate, fact):
        return fact

    def on_auth_fail(self, a: Authenticate, fact):
        return fact
