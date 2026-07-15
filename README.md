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
| C1 | timeout-completeness | every blocking `receive` is guarded by a `timeout` transition following it (each receive is its own blocking point) |
| C2 | verify-exhaustiveness | every received field passes a `verify` step before it is used |
| C3 | fail-closed verification | every `verify` has an explicit failure transition, and it lands in a terminal `deny`/`abort` state |
| C4 | no-secret-before-auth | fields declared `secret` are never sent, and never reach a sink, on a path without a successful `authenticate`; `param()`/`sanitize()` do not clear secrecy (they address injection, not disclosure) |
| C5 | auth-before-trusted-state | states marked `trusted` are unreachable on any path lacking a successful `authenticate` |
| C6 | injection taint-tracking | values originating from `receive` never reach `query` (SQLi), `exec` (command injection), or `render` (XSS) sinks unless neutralized by a wrapper that is the **whole** sink argument **and** matches the sink kind (`param()` for `query`/`exec`, `sanitize()` for `render`); taint propagates through assignment and concatenation, and a wrapper used inside a larger expression, assigned to a variable, or at a sink of the wrong kind does **not** clear it |

C1 and C3 are structural. C2, C4, C5, and C6 are path-sensitive and share
one worklist engine, each carrying its own fact: a boolean for
authentication, a set of variable names for taint and verification.

One coupling is worth knowing: a `verify` with no failure transition
leaves its failure path unmodeled by the engine, and downstream analysis
proceeds under the success assumption. That is sound only because C3
unconditionally reports every such verify first, so the checker never
silently analyzes around a failure path it cannot see.

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

Replace the whole argument with `query param(q)` and the finding
disappears, because `param()` as the entire argument of a `query` sink is a
genuine parameter binding. The wrapper only neutralizes in that exact form:
`query param(q) + "x"` (wrapper inside a concatenation), `y = param(q)`
followed by `query y` (wrapper assigned to a variable), and `render
param(q)` (wrapper at a sink of the wrong kind) are all still flagged.

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

Exit codes: `0` clean, `1` findings, `2` parse, read, or analysis-budget
error. A bad file does not stop the remaining files; the highest code
wins. Findings report the check ID, the state and line, and a one-line
explanation.

The `examples/` directory contains a passing and a failing spec for each of
the six checks; they double as the acceptance suite.

## Warnings and the analysis budget

Beyond the six checks, structural warnings flag suspect spec shape: `W1`,
an action that can never execute (the linear flow already ended at a goto,
or at a verify/authenticate whose success jumps away); `W2`, a state
unreachable from the initial state; `W3`, a state with no outgoing
transition that is not marked terminal; `W4`, a timeout that guards no
receive; and `W5`, a terminal state that still has an outgoing transition.
Warnings print like findings but do not affect the exit code unless
`--strict` is passed: "passes the checker" keeps meaning the six security
properties.

A `verify` or `authenticate` with no failure transition halts in place on
failure; it does not continue. C3 still reports a missing failure
transition, because fail-closed design requires an explicit deny/abort
edge.

The path-sensitive checks explore the finite (state, fact) space
exhaustively, which is exponential in the worst case. Rather than silently
approximating, the engine carries a budget (default 100000 explored pairs,
tunable with `--budget N`): exceeding it aborts that file with exit code 2
and a clear error. The checker either proves a property or tells you that
it could not; it never quietly downgrades the guarantee.

## Tests

```
pip install -e .[test]
pytest
```

The test suite asserts that every example produces exactly its expected
result, plus targeted semantics tests (taint through aliasing, timeout
exactness in both directions, dead code invisible to engine and warnings
alike, unreachable states staying quiet) and two differential checks: a
brute-force path enumerator must agree with the engine on every example
spec, and a structural micro-oracle must agree with C1/C3. The oracles are
independent in exploration strategy and in the intra-state flow-end logic
they reimplement; the per-action transfer-rule definitions are shared with
the engine by derivation, so the differential check validates the engine's
exploration, not the transfer rules themselves.

## DSL reference

```
secret NAME                          # declare a secret variable
state NAME: [initial] [trusted] [terminal] [deny] [abort]
    receive msg(field1, field2)     # bind fields; taints them (C6), marks unverified (C2)
    verify VAR [ok -> STATE] [fail -> STATE]
    authenticate [ok -> STATE] [fail -> STATE]
    timeout -> STATE                # guards the nearest preceding receive; its
                                    # edge carries facts as of that receive
                                    # blocking (that receive's bindings excluded)
    send EXPR
    VAR = EXPR                      # taint/secrecy propagate through + concatenation
    query EXPR | exec EXPR | render EXPR
    -> STATE                        # unconditional transition
EXPR := term (+ term)*   where term := VAR | "literal" | param(VAR) | sanitize(VAR)
```

`deny` and `abort` imply `terminal`. The initial state is the one flagged
`initial`, or the first declared. A `verify`/`authenticate` without an `ok`
target falls through on success.

A `param()`/`sanitize()` wrapper is a property of the **sink call site**,
not a durable property of a value. Under C6 it neutralizes taint only when
it is the entire sink argument and its kind matches the sink:

| wrapper | neutralizes at sink kind | rationale |
|---|---|---|
| `param(x)` | `query`, `exec` | parameter binding defuses SQL and OS-command injection |
| `sanitize(x)` | `render` | context escaping defuses markup injection |

Anywhere else the wrapped variable is exposed exactly as if it were bare:
inside a concatenation (`query "..." + param(x)`), as an assignment
right-hand side (`y = param(x)` does **not** make `y` clean), or at a sink
of a non-matching kind (`render param(x)`, `query sanitize(x)`). Secrecy
(C4) is never laundered at all: `param()`/`sanitize()` never clear a secret,
since parameterizing or escaping a secret still discloses it.

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

## Versioning

Pre-1.0: changes that can alter a spec's findings bump the minor version;
changes that cannot bump the patch version. See CHANGELOG.md.

## License

MIT
