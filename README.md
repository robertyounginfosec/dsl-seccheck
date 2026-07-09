# dsl-seccheck

A deterministic static security checker for a small protocol/handshake DSL.
You describe a protocol as states, transitions, and actions (send, receive,
verify, timeout, authenticate, and the typed sinks `query`, `exec`,
`render`); the checker parses the spec and enforces six security properties
structurally, so that "passes the checker" means the property holds on every
reachable path, not just the paths someone thought to test.

## Design thesis

Make security violations structurally inexpressible or statically
detectable. The interesting failure modes of handshake and session
protocols, sending secrets before authentication, trusting unverified
input, verification that fails open, user input concatenated into a query,
are all *path* properties: they depend on what has or has not happened
earlier on an execution path. This tool checks them with an exhaustive
worklist reachability analysis over the protocol's finite state graph, so
the result is deterministic and complete over the spec: no sampling, no
heuristics, no model calls.

That determinism is the point. In an AI-assisted development workflow,
generated code and specs need a trust boundary that does not share the
generator's failure modes. A checker like this one is that boundary for the
properties it covers: the spec either proves the property or names the
line where it fails.

## The six checks

| ID | Name | Property |
|----|------|----------|
| C1 | timeout-completeness | every state that can block on a `receive` declares a `timeout` transition |
| C2 | verify-exhaustiveness | every received field passes a `verify` step before it is used |
| C3 | fail-closed verification | every `verify` has an explicit failure transition, and it lands in a terminal `deny`/`abort` state |
| C4 | no-secret-before-auth | fields declared `secret` are never sent on a path without a successful `authenticate` |
| C5 | auth-before-trusted-state | states marked `trusted` are unreachable on any path lacking a successful `authenticate` |
| C6 | injection taint-tracking | values originating from `receive` never reach `query` (SQLi), `exec` (command injection), or `render` (XSS) sinks, unless passed via `param(...)` or cleared via `sanitize(...)`; taint propagates through assignment and concatenation |

C1 and C3 are structural. C2, C4, C5, and C6 are path-sensitive and share
one worklist engine, each carrying its own fact: a boolean for
authentication, a set of variable names for taint and verification.

### Example: catching an injection (C6)

```
state Init:
    receive request(q)
    timeout -> Abort
    verify q fail -> Deny
    sql = "SELECT name FROM users WHERE id = " + q
    query sql
    -> Done
```

```
$ dsl-seccheck examples/c6_fail.dsl
examples/c6_fail.dsl:7: C6 [state Init]: tainted value 'sql' reaches query sink (SQL injection): pass it via param() or clear it via sanitize()
```

Replace the concatenation with `query param(q)` and the finding disappears,
because the property now holds on every path, not because a pattern
stopped matching.

### Example: a trusted state reachable without authentication (C5)

```
state Init:
    -> Session          # forgot the authenticate step

state Session: trusted
```

```
$ dsl-seccheck examples/c5_fail.dsl
examples/c5_fail.dsl:5: C5 [state Session]: trusted state 'Session' is reachable on a path with no successful authenticate step
```

## Install and run

Python 3.11+, no runtime dependencies (stdlib only).

```
pip install -e .
dsl-seccheck path/to/spec.dsl        # or: python -m dsl_seccheck spec.dsl
```

Exit codes: `0` clean, `1` findings, `2` parse error. Findings report the
check ID, the state and line, and a one-line explanation.

The `examples/` directory contains a passing and a failing spec for each of
the six checks; they double as the acceptance suite.

## Tests

```
pip install -e .[test]
pytest
```

The test suite asserts that every example produces exactly its expected
result, plus targeted semantics tests (taint through aliasing, timeout
edges carrying pre-receive facts, unreachable states staying quiet).

## DSL reference

```
secret NAME                          # declare a secret variable
state NAME: [initial] [trusted] [terminal] [deny] [abort]
    receive msg(field1, field2)     # bind fields; taints them (C6), marks unverified (C2)
    verify VAR [ok -> STATE] [fail -> STATE]
    authenticate [ok -> STATE] [fail -> STATE]
    timeout -> STATE                # may fire while blocked on receive
    send EXPR
    VAR = EXPR                      # taint/secrecy propagate through + concatenation
    query EXPR | exec EXPR | render EXPR
    -> STATE                        # unconditional transition
EXPR := term (+ term)*   where term := VAR | "literal" | param(VAR) | sanitize(VAR)
```

`deny` and `abort` imply `terminal`. The initial state is the one flagged
`initial`, or the first declared. A `verify`/`authenticate` without an `ok`
target falls through on success.

## Scope, honestly

This covers the structurally-preventable slice of protocol security:
injection reaching typed sinks, authentication ordering, fail-closed
verification, timeout coverage. It is not a full OWASP Top 10 tool, it
does not analyze implementations (only specs), and it cannot see
properties outside the DSL's vocabulary (crypto correctness, replay,
timing). It is positioned as design-time prevention that sits alongside,
not instead of, SCA/DAST and code review.

The project originated in an AI-assisted design process working from a
human-directed specification.

## License

MIT
