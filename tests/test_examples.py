"""The examples directory is the acceptance suite: every pass example must
produce zero findings, and every fail example must produce findings for
exactly its own check."""
from pathlib import Path

import pytest

from dsl_seccheck import check_all, parse

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

EXPECTED: dict[str, set[str]] = {
    "c1_pass.dsl": set(),
    "c1_fail.dsl": {"C1"},
    "c2_pass.dsl": set(),
    "c2_fail.dsl": {"C2"},
    "c3_pass.dsl": set(),
    "c3_fail.dsl": {"C3"},
    "c4_pass.dsl": set(),
    "c4_fail.dsl": {"C4"},
    "c5_pass.dsl": set(),
    "c5_fail.dsl": {"C5"},
    "c6_pass.dsl": set(),
    "c6_fail.dsl": {"C6"},
}


def test_every_example_is_covered() -> None:
    on_disk = {p.name for p in EXAMPLES.glob("*.dsl")}
    assert on_disk == set(EXPECTED)


@pytest.mark.parametrize("name,expected", sorted(EXPECTED.items()))
def test_example(name: str, expected: set[str]) -> None:
    spec = parse((EXAMPLES / name).read_text(encoding="utf-8"))
    got = {f.check for f in check_all(spec)}
    assert got == expected, f"{name}: expected {expected or 'no findings'}, got {got}"


def test_cli_exit_codes(capsys) -> None:
    from dsl_seccheck.cli import main

    assert main([str(EXAMPLES / "c1_pass.dsl")]) == 0
    assert main([str(EXAMPLES / "c1_fail.dsl")]) == 1
    out = capsys.readouterr().out
    assert "C1" in out and "timeout" in out


def test_cli_parse_error(tmp_path, capsys) -> None:
    from dsl_seccheck.cli import main

    bad = tmp_path / "bad.dsl"
    bad.write_text("state A:\n    fly -> Moon\n", encoding="utf-8")
    assert main([str(bad)]) == 2
    assert "parse error" in capsys.readouterr().err
