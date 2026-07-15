"""Data model for the protocol/handshake DSL.

A spec is a set of named states. Each state carries an ordered list of
actions. Expressions are flat concatenations of terms: variables, string
literals, and the ``param(...)`` / ``sanitize(...)`` wrappers. That is all
the checks need, because taint and secrecy are properties of the variable
terms, not of expression structure.
"""
from __future__ import annotations

from dataclasses import dataclass


# --- expression terms -------------------------------------------------------

@dataclass(frozen=True)
class Var:
    """A bare variable reference."""
    name: str


@dataclass(frozen=True)
class Lit:
    """A double-quoted string literal."""
    text: str


@dataclass(frozen=True)
class Param:
    """``param(x)``: the value is passed parameterized (safe for sinks)."""
    name: str


@dataclass(frozen=True)
class Sanitize:
    """``sanitize(x)``: the value is sanitized (safe for sinks)."""
    name: str


Term = Var | Lit | Param | Sanitize
Expr = tuple[Term, ...]


def var_names(expr: Expr) -> tuple[str, ...]:
    """Names referenced by any term of *expr* (including param/sanitize)."""
    return tuple(
        t.name for t in expr if isinstance(t, (Var, Param, Sanitize))
    )


def bare_var_names(expr: Expr) -> tuple[str, ...]:
    """Names referenced by bare ``Var`` terms only (param/sanitize excluded)."""
    return tuple(t.name for t in expr if isinstance(t, Var))


# --- actions -----------------------------------------------------------------

@dataclass(frozen=True)
class Receive:
    """Block until message *msg* arrives; bind its fields as variables."""
    msg: str
    fields: tuple[str, ...]
    line: int


@dataclass(frozen=True)
class Send:
    expr: Expr
    line: int


@dataclass(frozen=True)
class Assign:
    target: str
    expr: Expr
    line: int


@dataclass(frozen=True)
class Verify:
    """Validate *var*. ``ok_target`` None means fall through on success;
    ``fail_target`` None means the spec silently continues on failure
    (which check C3 reports)."""
    var: str
    ok_target: str | None
    fail_target: str | None
    line: int


@dataclass(frozen=True)
class Authenticate:
    """Perform authentication. Targets as for Verify; a missing fail
    target means authentication failure halts the machine in place."""
    ok_target: str | None
    fail_target: str | None
    line: int


@dataclass(frozen=True)
class Timeout:
    target: str
    line: int


@dataclass(frozen=True)
class Sink:
    """A typed sink: kind is ``query`` (SQL), ``exec`` (OS command), or
    ``render`` (markup output)."""
    kind: str
    expr: Expr
    line: int


@dataclass(frozen=True)
class Goto:
    target: str
    line: int


Action = Receive | Send | Assign | Verify | Authenticate | Timeout | Sink | Goto

SINK_KINDS = ("query", "exec", "render")


# --- states and spec ---------------------------------------------------------

VALID_FLAGS = frozenset({"initial", "trusted", "terminal", "deny", "abort"})


@dataclass
class State:
    name: str
    line: int
    flags: frozenset[str]
    actions: list[Action]

    @property
    def trusted(self) -> bool:
        return "trusted" in self.flags

    @property
    def fail_closed(self) -> bool:
        """True for the states a verify failure is allowed to land in."""
        return "deny" in self.flags or "abort" in self.flags


@dataclass
class Spec:
    states: dict[str, State]
    secrets: dict[str, int]  # name -> declaration line
    initial: str


# --- intra-state control flow --------------------------------------------------

def flow_ends_at(a: Action) -> bool:
    """True if *a* ends a state's linear flow: an unconditional goto, or a
    verify/authenticate whose both outcomes jump."""
    if isinstance(a, Goto):
        return True
    return isinstance(a, (Verify, Authenticate)) and a.ok_target is not None


def live_actions(st: State) -> list[Action]:
    """The actions of *st* that can actually execute, in order, stopping
    at (and including) the flow-ending action.

    This is the single definition of intra-state control flow. The
    engine's action loop and the structural warnings (W1 dead actions,
    W2 reachability) both consume it, so they cannot diverge on what is
    live; a new flow-ending construct changes exactly one place.
    """
    out: list[Action] = []
    for a in st.actions:
        out.append(a)
        if flow_ends_at(a):
            break
    return out


def edge_targets(st: State) -> list[str]:
    """Transition targets that can actually be taken from *st*, in
    declaration order (edges declared after the flow end can never fire)."""
    targets: list[str] = []
    for a in live_actions(st):
        if isinstance(a, (Timeout, Goto)):
            targets.append(a.target)
        elif isinstance(a, (Verify, Authenticate)):
            targets.extend(t for t in (a.ok_target, a.fail_target) if t)
    return targets
