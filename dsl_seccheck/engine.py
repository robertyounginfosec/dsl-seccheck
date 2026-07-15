"""Worklist-based reachability engine over the state graph.

One engine serves every path-sensitive check. It explores (state, fact)
pairs from the initial state, where *fact* is a small hashable value owned
by the check's domain: a boolean ("has an authenticate step succeeded on
this path?") or a frozenset of variable names (tainted set, unverified
set). Exploration is exhaustive over the finite (state, fact) space, so a
property verified here holds on every reachable path.

Control-flow semantics inside a state body:

- Actions run in declaration order.
- ``timeout`` edges associate with the nearest preceding ``receive`` in
  the body and carry the exact fact as of that receive blocking: entry
  facts plus every action before that receive, with the receive's own
  bindings and everything after it excluded (a fired timeout means the
  receive never completed, so neither its binding nor any later action
  ran). Earlier receives on the path did complete, so their bindings and
  subsequent assigns are included. A ``timeout`` with no preceding
  receive carries the fact at its own position (degenerate; no bindings
  are involved) and is separately flagged W4.
- ``verify``/``authenticate`` with an explicit ok target end the linear
  flow (success jumps to the ok target; failure jumps to the fail target
  or, absent one, halts in place). With no ok target the success branch
  falls through to the next action.
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
    live_actions,
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

        # live_actions (model.py) is the single definition of intra-state
        # control flow: it stops at the flow-ending action, so no break
        # logic is duplicated here.
        fact = entry
        # fact as it stood just before the nearest preceding receive
        # blocked; None until the first receive is seen. A timeout carries
        # this, not the position fact, because a fired timeout means that
        # receive (and everything after it) never ran.
        fact_before_receive = None
        for a in live_actions(st):
            if isinstance(a, Receive):
                fact_before_receive = fact
                fact = domain.on_receive(a, fact, st, findings)
            elif isinstance(a, Send):
                fact = domain.on_send(a, fact, st, findings)
            elif isinstance(a, Assign):
                fact = domain.on_assign(a, fact, st, findings)
            elif isinstance(a, Sink):
                fact = domain.on_sink(a, fact, st, findings)
            elif isinstance(a, Timeout):
                # degenerate case (no preceding receive) uses the position
                # fact and is reported by warn_w4
                edge(a.target,
                     fact if fact_before_receive is None else fact_before_receive)
            elif isinstance(a, Verify):
                if a.fail_target:
                    edge(a.fail_target, domain.on_verify_fail(a, fact))
                # A verify with no fail target emits no failure edge: the
                # failure path is unmodeled, and downstream analysis
                # proceeds under the success assumption. That is sound
                # ONLY because C3 unconditionally reports every verify
                # lacking a fail transition; C3 is load-bearing for the
                # path-sensitive checks here.
                ok_fact = domain.on_verify_ok(a, fact)
                if a.ok_target:
                    edge(a.ok_target, ok_fact)
                else:
                    fact = ok_fact
            elif isinstance(a, Authenticate):
                if a.fail_target:
                    edge(a.fail_target, domain.on_auth_fail(a, fact))
                ok_fact = domain.on_auth_ok(a, fact)
                if a.ok_target:
                    edge(a.ok_target, ok_fact)
                else:
                    fact = ok_fact
            elif isinstance(a, Goto):
                edge(a.target, fact)

    # the same violation can be met under many facts; report it once
    return sorted(set(findings), key=lambda f: (f.line, f.check, f.message))
