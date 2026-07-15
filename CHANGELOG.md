# Changelog

## Versioning policy (pre-1.0)

Any change that can alter the set of findings a given spec produces (new
or removed checks, stricter or broader check semantics, new warning IDs)
bumps the MINOR version. Changes that cannot alter any spec's findings
(reporting fixes, performance, docs, CLI ergonomics) bump the PATCH
version. Anyone gating CI on this tool's exit codes should pin to a minor
version.

## 0.3.0 - 2026-07-14

Unpublished soundness-closure release. Resolves the 0.2.0 known limitation
and the findings from the independent-review round.

### Changed: finding-set changes

- Timeout edges are now exact: a timeout associates with the nearest
  preceding receive and carries the fact as of that receive blocking
  (that receive's bindings and every later action excluded; earlier
  completed receives included). This both removes the 0.2.0 over-report
  (a guarded receive's bindings no longer appear on its timeout path) and
  adds the finding the 0.2.0 semantics missed (a post-receive fact-removal
  that a fired timeout never ran is no longer reflected). Net: some C2/C4/
  C6 findings on timeout paths disappear and some appear.
- C1 walks the live action prefix, so a timeout sitting past a state's
  flow end no longer counts as a guard (previously a false negative: such
  a state could pass C1 with an unguarded receive).
- C3 enforces terminality: a verify's failure transition must lead to a
  deny/abort state that also has no live outgoing edges. A deny/abort
  state that escapes via a transition now fails C3.

### Added

- W3 (a state with no outgoing transition that is not marked terminal),
  W4 (a timeout that guards no receive), and W5 (a terminal state that
  still has an outgoing transition). Warnings, like W1/W2, do not affect
  the exit code unless `--strict`.
- A structural micro-oracle (independent reimplementation of C1 and C3)
  compared against the checks on every example and on adversarial specs
  covering the dead-guard and escaping-deny shapes.

### Fixed

- Parser strips `#` comments string-aware, so a `#` inside a double-quoted
  literal is preserved.
- The differential oracle no longer imports `model.live_actions`; it
  reimplements the flow-end logic, restoring its independence on that
  dimension. Its visit counter is renamed from `paths` (it counts visits).

### Documentation

- A verify/authenticate with no failure transition is documented as
  halt-in-place (matching authenticate), not continue-on-failure, with the
  C3-load-bearing coupling noted at the model site and in the README.
- README gains the taint-vs-secrecy laundering note (wrapped/literal
  assignment yields a C6-clean variable; `param()`/`sanitize()` never clear
  C4 secrecy).

## 0.2.0 - 2026-07-14

Unpublished development version; consolidates two review rounds on the
initial build.

### Changed: finding-set changes (recorded retroactively for commit 9f76036)

- Timeout edges carry facts as of the timeout's position instead of the
  state-entry fact, closing a false-negative window for taint acquired
  earlier in the same state body. The edge over-approximates by including
  receive bindings; a characterization test marks the resulting
  over-reporting as intended.
- C4 also reports secrets reaching `query`/`exec`/`render` sinks on
  unauthenticated paths, wrapped in `param()`/`sanitize()` or not, and
  secrecy is no longer cleared by a same-named receive field.
- C1 is per-receive: each receive must be guarded by a timeout transition
  after it and before the next receive; a single state-level timeout no
  longer covers earlier blocking points.

### Added

- W1 (dead actions) and W2 (unreachable states) structural warnings,
  printed by the CLI without affecting the exit code unless `--strict`.
- Analysis budget: `--budget N` caps explored (state, fact) pairs per
  domain run and aborts loudly with exit code 2 instead of silently
  approximating.
- Shared intra-state control-flow definition (`model.live_actions`,
  `model.edge_targets`) consumed by both the engine and the structural
  warnings, with a divergence-guard test.
- Differential oracle test: an independent brute-force path enumerator
  must agree exactly with the engine on every example spec for every
  path-sensitive check.

### Fixed

- CLI: a parse or read error in one file no longer stops the remaining
  files; the highest exit code wins.
- `--budget` help text states the budget is per domain run (three domain
  runs per file).

### Known limitation (RESOLVED in 0.3.0)

- A fact-removing action between a receive and its timeout (for example,
  an assignment clearing a variable's taint) is reflected on the timeout
  edge although a fired timeout means it never ran. The exact semantics
  would carry the fact as of the blocking receive itself. Fixing this is
  a finding-set change and is deferred to a future minor version.
  (Resolved in 0.3.0 by the exact timeout-edge semantics.)

## 0.1.0 - 2026-07-09

- Initial version: DSL parser, worklist reachability engine, checks
  C1-C6, per-check pass/fail examples doubling as the acceptance suite,
  pytest suite, CLI with exit-code contract.
