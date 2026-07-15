"""Worklist-based reachability engine over the state graph.

One engine serves every path-sensitive check. It explores (state, fact)
pairs from the initial state, where *fact* is a small hashable value owned
by the check's domain: a boolean ("has an authenticate step succeeded on
this path?") or a frozenset of variable names (tainted set, unverified
set). Exploration is exhaustive over the finite (state, fact) space, so a
property verified here holds on every reachable path.

Control-flow semantics inside a state body:

- Actions run in declaration order.
- ``timeout`` edges carry the fact at the timeout's own position: every
  action textually before it has already been applied. Receive bindings
  are included even though a firing timeout means the receive never
  completed; domains only ever *add* facts on receive (taint, unverified
  fields), so the edge over-approximates and never hides a violation.
- ``verify``/``authenticate`` with an explicit ok target end the linear
  flow (both outcomes jump); with no ok target the success branch falls
  through to the next action.
- ``->`` (goto) ends the body.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable, Protocol

from .model import (
    Assign,
    Authenticate,
    Goto,
    Receive,
    Send,
    Sink,
    Spec,
    State,
    Timeout,
    Verify,
)


DEFAULT_BUDGET = 100_000


class AnalysisBudgetExceeded(Exception):
    """The (state, fact) exploration outgrew its budget.

    The fact space is exponential in the worst case. Rather than silently
    approximating (which would break the every-reachable-path guarantee),
    the engine fails loudly and lets the caller report it.
    """


@dataclass(frozen=True)
class Finding:
    check: str
    state: str
    line: int
    message: str


class Domain(Protocol):
    """Fact lattice + transfer functions for one path-sensitive check."""

    def initial_fact(self) -> Hashable: ...
    def enter_state(self, st: State, fact: Hashable, out: list[Finding]) -> None: ...
    def on_receive(self, a: Receive, fact: Hashable, st: State, out: list[Finding]) -> Hashable: ...
    def on_send(self, a: Send, fact: Hashable, st: State, out: list[Finding]) -> Hashable: ...
    def on_assign(self, a: Assign, fact: Hashable, st: State, out: list[Finding]) -> Hashable: ...
    def on_sink(self, a: Sink, fact: Hashable, st: State, out: list[Finding]) -> Hashable: ...
    def on_verify_ok(self, a: Verify, fact: Hashable) -> Hashable: ...
    def on_verify_fail(self, a: Verify, fact: Hashable) -> Hashable: ...
    def on_auth_ok(self, a: Authenticate, fact: Hashable) -> Hashable: ...
    def on_auth_fail(self, a: Authenticate, fact: Hashable) -> Hashable: ...


def run(spec: Spec, domain: Domain, budget: int = DEFAULT_BUDGET) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, Hashable]] = set()
    work: list[tuple[str, Hashable]] = [(spec.initial, domain.initial_fact())]

    def edge(target: str, fact: Hashable) -> None:
        if (target, fact) not in seen:
            work.append((target, fact))

    while work:
        name, entry = work.pop()
        if (name, entry) in seen:
            continue
        seen.add((name, entry))
        if len(seen) > budget:
            raise AnalysisBudgetExceeded(
                f"analysis exceeded {budget} explored (state, fact) pairs; "
                "the spec's fact space is too large for exhaustive checking "
                "(raise --budget, or simplify the spec)"
            )
        st = spec.states[name]
        domain.enter_state(st, entry, findings)

        fact = entry
        for a in st.actions:
            if isinstance(a, Receive):
                fact = domain.on_receive(a, fact, st, findings)
            elif isinstance(a, Send):
                fact = domain.on_send(a, fact, st, findings)
            elif isinstance(a, Assign):
                fact = domain.on_assign(a, fact, st, findings)
            elif isinstance(a, Sink):
                fact = domain.on_sink(a, fact, st, findings)
            elif isinstance(a, Timeout):
                edge(a.target, fact)
            elif isinstance(a, Verify):
                if a.fail_target:
                    edge(a.fail_target, domain.on_verify_fail(a, fact))
                ok_fact = domain.on_verify_ok(a, fact)
                if a.ok_target:
                    edge(a.ok_target, ok_fact)
                    break  # both outcomes jump; rest of body unreachable
                fact = ok_fact
            elif isinstance(a, Authenticate):
                if a.fail_target:
                    edge(a.fail_target, domain.on_auth_fail(a, fact))
                ok_fact = domain.on_auth_ok(a, fact)
                if a.ok_target:
                    edge(a.ok_target, ok_fact)
                    break
                fact = ok_fact
            elif isinstance(a, Goto):
                edge(a.target, fact)
                break

    # the same violation can be met under many facts; report it once
    return sorted(set(findings), key=lambda f: (f.line, f.check, f.message))
