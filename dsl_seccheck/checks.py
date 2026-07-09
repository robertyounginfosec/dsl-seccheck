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
from .engine import Finding
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
    var_names,
)

SINK_LABEL = {
    "query": "SQL injection",
    "exec": "OS command injection",
    "render": "cross-site scripting",
}


def check_all(spec: Spec) -> list[Finding]:
    findings: list[Finding] = []
    findings += check_c1(spec)
    findings += check_c3(spec)
    findings += engine.run(spec, AuthDomain(spec))      # C4 + C5
    findings += engine.run(spec, VerifiedDomain(spec))  # C2
    findings += engine.run(spec, TaintDomain(spec))     # C6
    return sorted(set(findings), key=lambda f: (f.line, f.check, f.message))


# --- C1: timeout-completeness (structural) -----------------------------------

def check_c1(spec: Spec) -> list[Finding]:
    out: list[Finding] = []
    for st in spec.states.values():
        receives = [a for a in st.actions if isinstance(a, Receive)]
        has_timeout = any(isinstance(a, Timeout) for a in st.actions)
        if receives and not has_timeout:
            a = receives[0]
            out.append(Finding(
                "C1", st.name, a.line,
                f"state '{st.name}' blocks on receive '{a.msg}' but declares "
                "no timeout transition",
            ))
    return out


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
                    "would silently continue",
                ))
            elif not spec.states[a.fail_target].fail_closed:
                out.append(Finding(
                    "C3", st.name, a.line,
                    f"verify '{a.var}' failure transition leads to "
                    f"'{a.fail_target}', which is not a terminal deny/abort "
                    "state",
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
        authed, secrets = fact
        # a received field overwrites any same-named secret-carrying var
        return (authed, secrets - set(a.fields))

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

    def on_sink(self, a: Sink, fact, st: State, out) -> tuple:
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
