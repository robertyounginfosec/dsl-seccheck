"""Line-oriented parser for the protocol DSL.

Grammar (one construct per line; ``#`` starts a comment):

    spec        := (secret_decl | state_block)*
    secret_decl := "secret" NAME                        (column 0)
    state_block := "state" NAME ":" flag*               (column 0)
                   action*                              (indented)
    flag        := "initial" | "trusted" | "terminal" | "deny" | "abort"
    action      := "receive" NAME "(" NAME ("," NAME)* ")"
                 | "send" expr
                 | NAME "=" expr
                 | "verify" NAME ["ok" "->" NAME] ["fail" "->" NAME]
                 | "authenticate" ["ok" "->" NAME] ["fail" "->" NAME]
                 | "timeout" "->" NAME
                 | ("query" | "exec" | "render") expr
                 | "->" NAME
    expr        := term ("+" term)*
    term        := NAME | STRING | "param(" NAME ")" | "sanitize(" NAME ")"

``deny`` and ``abort`` imply ``terminal``. The initial state is the one
flagged ``initial``, or the first declared state if none is flagged.

A ``#`` starts a comment except inside a double-quoted string literal, so
``render "a#b"`` keeps the ``#`` in the literal.
"""
from __future__ import annotations

import re

from .model import (
    Action,
    Assign,
    Authenticate,
    Expr,
    Goto,
    Lit,
    Param,
    Receive,
    Sanitize,
    Send,
    Sink,
    Spec,
    State,
    Term,
    Timeout,
    Var,
    Verify,
    VALID_FLAGS,
    SINK_KINDS,
)


class ParseError(Exception):
    def __init__(self, msg: str, line: int) -> None:
        super().__init__(f"line {line}: {msg}")
        self.msg = msg
        self.line = line


_NAME = r"[A-Za-z_]\w*"
_STATE_RE = re.compile(rf"^state\s+({_NAME})\s*:\s*(.*)$")
_SECRET_RE = re.compile(rf"^secret\s+({_NAME})$")
_RECEIVE_RE = re.compile(rf"^receive\s+({_NAME})\s*\(\s*([^)]*?)\s*\)$")
_TIMEOUT_RE = re.compile(rf"^timeout\s*->\s*({_NAME})$")
_GOTO_RE = re.compile(rf"^->\s*({_NAME})$")
_VERIFY_RE = re.compile(
    rf"^verify\s+({_NAME})(?:\s+ok\s*->\s*({_NAME}))?(?:\s+fail\s*->\s*({_NAME}))?$"
)
_AUTH_RE = re.compile(
    rf"^authenticate(?:\s+ok\s*->\s*({_NAME}))?(?:\s+fail\s*->\s*({_NAME}))?$"
)
_SINK_RE = re.compile(r"^(query|exec|render)\s+(.+)$")
_SEND_RE = re.compile(r"^send\s+(.+)$")
_ASSIGN_RE = re.compile(rf"^({_NAME})\s*=\s*(.+)$")
_WRAP_RE = re.compile(rf"(param|sanitize)\(\s*({_NAME})\s*\)")
_IDENT_RE = re.compile(_NAME)

# Statement keywords may not be used as an assignment target. Without this,
# `exec=cmd` (no space) parses as an assignment to a variable named `exec`
# and the exec sink is silently dropped.
_RESERVED_LHS = frozenset({
    "receive", "send", "verify", "authenticate", "timeout",
    "query", "exec", "render",
})


def _strip_comment(raw: str) -> str:
    """Remove a trailing ``#`` comment, string-aware: a ``#`` inside a
    double-quoted literal is preserved. (A naive split on ``#`` would cut
    ``send "a#b"`` mid-literal and mis-report an unterminated string.)"""
    in_str = False
    for i, ch in enumerate(raw):
        if ch == '"':
            in_str = not in_str
        elif ch == "#" and not in_str:
            return raw[:i].rstrip()
    return raw.rstrip()


def parse_expr(text: str, line: int) -> Expr:
    """Parse a flat concatenation of terms joined by ``+``."""
    terms: list[Term] = []
    i = 0
    n = len(text)
    while True:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            raise ParseError("expected a term in expression", line)
        ch = text[i]
        if ch == '"':
            end = text.find('"', i + 1)
            if end < 0:
                raise ParseError("unterminated string literal", line)
            terms.append(Lit(text[i + 1:end]))
            i = end + 1
        else:
            m = _WRAP_RE.match(text, i)
            if m:
                kind, name = m.group(1), m.group(2)
                terms.append(Param(name) if kind == "param" else Sanitize(name))
                i = m.end()
            else:
                m = _IDENT_RE.match(text, i)
                if not m:
                    raise ParseError(f"cannot parse expression at {text[i:]!r}", line)
                terms.append(Var(m.group(0)))
                i = m.end()
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            return tuple(terms)
        if text[i] != "+":
            raise ParseError(f"expected '+' or end of expression at {text[i:]!r}", line)
        i += 1


def _parse_action(body: str, line: int) -> Action:
    if m := _RECEIVE_RE.match(body):
        raw = m.group(2)
        fields = tuple(f.strip() for f in raw.split(",")) if raw.strip() else ()
        for f in fields:
            if not re.fullmatch(_NAME, f):
                raise ParseError(f"bad receive field name {f!r}", line)
        return Receive(m.group(1), fields, line)
    if m := _TIMEOUT_RE.match(body):
        return Timeout(m.group(1), line)
    if m := _GOTO_RE.match(body):
        return Goto(m.group(1), line)
    if m := _VERIFY_RE.match(body):
        return Verify(m.group(1), m.group(2), m.group(3), line)
    if m := _AUTH_RE.match(body):
        return Authenticate(m.group(1), m.group(2), line)
    if m := _SINK_RE.match(body):
        return Sink(m.group(1), parse_expr(m.group(2), line), line)
    if m := _SEND_RE.match(body):
        return Send(parse_expr(m.group(1), line), line)
    if m := _ASSIGN_RE.match(body):
        target = m.group(1)
        if target in _RESERVED_LHS:
            raise ParseError(
                f"cannot assign to reserved word {target!r}; if you meant the "
                f"'{target}' statement, put a space after it (e.g. "
                f"'{target} ...')",
                line,
            )
        return Assign(target, parse_expr(m.group(2), line), line)
    raise ParseError(f"unrecognized action: {body!r}", line)


def parse(text: str) -> Spec:
    states: dict[str, State] = {}
    secrets: dict[str, int] = {}
    current: State | None = None
    initial_flagged: list[str] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indented = line[0].isspace()
        body = line.strip()

        if not indented:
            if m := _STATE_RE.match(body):
                name, flag_text = m.group(1), m.group(2).strip()
                if name in states:
                    raise ParseError(f"duplicate state {name!r}", lineno)
                flags = set(flag_text.split()) if flag_text else set()
                bad = flags - VALID_FLAGS
                if bad:
                    raise ParseError(f"unknown state flag(s): {sorted(bad)}", lineno)
                if "deny" in flags or "abort" in flags:
                    flags.add("terminal")
                if "initial" in flags:
                    initial_flagged.append(name)
                current = State(name, lineno, frozenset(flags), [])
                states[name] = current
                continue
            if m := _SECRET_RE.match(body):
                name = m.group(1)
                if name in secrets:
                    raise ParseError(f"duplicate secret declaration {name!r}", lineno)
                secrets[name] = lineno
                continue
            raise ParseError(
                f"expected 'state NAME:' or 'secret NAME' at top level, got {body!r}",
                lineno,
            )

        if current is None:
            raise ParseError("action outside of any state", lineno)
        current.actions.append(_parse_action(body, lineno))

    if not states:
        raise ParseError("spec declares no states", 1)
    if len(initial_flagged) > 1:
        raise ParseError(
            f"multiple states flagged initial: {initial_flagged}",
            states[initial_flagged[1]].line,
        )
    initial = initial_flagged[0] if initial_flagged else next(iter(states))

    # every transition target must name a declared state
    for st in states.values():
        for a in st.actions:
            for target in _targets_of(a):
                if target not in states:
                    raise ParseError(
                        f"transition to undefined state {target!r}", a.line
                    )

    return Spec(states=states, secrets=secrets, initial=initial)


def _targets_of(a: Action) -> tuple[str, ...]:
    if isinstance(a, (Timeout, Goto)):
        return (a.target,)
    if isinstance(a, (Verify, Authenticate)):
        return tuple(t for t in (a.ok_target, a.fail_target) if t)
    return ()
