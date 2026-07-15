"""Command-line interface.

Exit codes: 0 = all specs clean, 1 = findings reported, 2 = parse or read
error. A bad file does not stop the remaining files; the highest code wins.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .checks import check_all
from .parser import ParseError, parse


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="dsl-seccheck",
        description="Deterministic static security checker for protocol DSL "
                    "specs (checks C1-C6).",
    )
    ap.add_argument("specs", nargs="+", metavar="SPEC.dsl",
                    help="one or more .dsl spec files")
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

        findings = check_all(spec)
        for f in findings:
            print(f"{path}:{f.line}: {f.check} [state {f.state}]: {f.message}")
        if findings:
            exit_code = max(exit_code, 1)
        else:
            print(f"{path}: OK ({len(spec.states)} states, no findings)")
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
