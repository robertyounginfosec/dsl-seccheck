"""Command-line interface.

Exit codes: 0 = all specs clean, 1 = findings reported (or warnings, with
--strict), 2 = parse, read, or analysis-budget error. A bad file does not
stop the remaining files; the highest code wins.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .checks import check_all, warn_all
from .engine import DEFAULT_BUDGET, AnalysisBudgetExceeded
from .parser import ParseError, parse


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dsl-seccheck",
        description="Deterministic static security checker for protocol DSL "
                    "specs (checks C1-C6, warnings W1-W2).",
    )
    ap.add_argument("specs", nargs="+", metavar="SPEC.dsl",
                    help="one or more .dsl spec files")
    ap.add_argument("--strict", action="store_true",
                    help="warnings (W*) also cause a nonzero exit")
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET, metavar="N",
                    help="max explored (state, fact) pairs per check "
                         "(default %(default)s); exceeding it is an error, "
                         "never a silent approximation")
    ns = ap.parse_args(argv)

    exit_code = 0
    for path_str in ns.specs:
        path = Path(path_str)
        try:
            spec = parse(path.read_text(encoding="utf-8"))
        except OSError as e:
            print(f"{path}: cannot read: {e}", file=sys.stderr)
            exit_code = 2
            continue
        except ParseError as e:
            print(f"{path}:{e.line}: parse error: {e.msg}", file=sys.stderr)
            exit_code = 2
            continue

        try:
            findings = check_all(spec, budget=ns.budget)
        except AnalysisBudgetExceeded as e:
            print(f"{path}: {e}", file=sys.stderr)
            exit_code = 2
            continue
        warnings = warn_all(spec)

        for f in findings + warnings:
            print(f"{path}:{f.line}: {f.check} [state {f.state}]: {f.message}")
        if findings:
            exit_code = max(exit_code, 1)
        elif warnings:
            if ns.strict:
                exit_code = max(exit_code, 1)
        else:
            print(f"{path}: OK ({len(spec.states)} states, no findings)")
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
