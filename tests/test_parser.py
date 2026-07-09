import pytest

from dsl_seccheck.model import Lit, Param, Sanitize, Var
from dsl_seccheck.parser import ParseError, parse, parse_expr


def test_expr_terms() -> None:
    expr = parse_expr('"SELECT " + a + param(b) + sanitize(c)', 1)
    assert expr == (Lit("SELECT "), Var("a"), Param("b"), Sanitize("c"))


def test_expr_errors() -> None:
    with pytest.raises(ParseError):
        parse_expr('"unterminated', 1)
    with pytest.raises(ParseError):
        parse_expr("a b", 1)  # missing '+'


def test_state_flags_and_initial() -> None:
    spec = parse(
        "state A:\n"
        "    -> B\n"
        "state B: trusted\n"
        "state C: deny\n"
        "state D: initial terminal\n"
    )
    assert spec.initial == "D"  # explicit flag wins over declaration order
    assert spec.states["B"].trusted
    assert spec.states["C"].fail_closed and "terminal" in spec.states["C"].flags


def test_initial_defaults_to_first_state() -> None:
    spec = parse("state First:\nstate Second:\n")
    assert spec.initial == "First"


@pytest.mark.parametrize("text,fragment", [
    ("    send x\n", "outside of any state"),
    ("state A:\n    -> Nowhere\n", "undefined state"),
    ("state A:\nstate A:\n", "duplicate state"),
    ("state A: shiny\n", "unknown state flag"),
    ("secret k\nsecret k\nstate A:\n", "duplicate secret"),
    ("", "no states"),
    ("state A: initial\nstate B: initial\n", "multiple states flagged initial"),
])
def test_parse_errors(text: str, fragment: str) -> None:
    with pytest.raises(ParseError, match=fragment):
        parse(text)
