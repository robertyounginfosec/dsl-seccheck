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


@pytest.mark.parametrize("body", ["exec=cmd", "exec= cmd", "query=x", "timeout=T"])
def test_reserved_word_assignment_target_is_a_loud_error(body: str) -> None:
    # E3: `exec=cmd` (no space) must not silently parse as an assignment to a
    # variable named `exec` and drop the sink; it is a loud parse error.
    with pytest.raises(ParseError, match="reserved word"):
        parse(f"state Init:\n    {body}\n")


def test_sink_statement_with_space_still_parses() -> None:
    # The reservation must not break the real statement form.
    spec = parse(
        "state Init:\n"
        "    receive m(q)\n"
        "    timeout -> Abort\n"
        "    verify q fail -> Deny\n"
        "    exec param(q)\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Deny: deny\n"
        "state Abort: abort\n"
    )
    assert spec.states["Init"].actions[3].__class__.__name__ == "Sink"


def test_hash_inside_string_is_not_a_comment() -> None:
    spec = parse(
        'state Init:\n'
        '    render "a#b"   # real trailing comment\n'
        '    -> Done\n'
        'state Done: terminal\n'
    )
    sink = spec.states["Init"].actions[0]
    assert sink.expr == (Lit("a#b"),)


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
