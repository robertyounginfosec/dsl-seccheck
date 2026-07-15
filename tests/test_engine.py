"""Targeted semantics tests for the path-sensitive checks."""
import pytest

from dsl_seccheck import AnalysisBudgetExceeded, check_all, parse, warn_all


def checks_of(text: str) -> set[str]:
    return {f.check for f in check_all(parse(text))}


def test_taint_propagates_through_chained_assignment() -> None:
    text = (
        "state Init:\n"
        "    receive m(q)\n"
        "    timeout -> Abort\n"
        "    verify q fail -> Deny\n"
        "    a = q\n"
        '    b = a + "-suffix"\n'
        "    exec b\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Deny: deny\n"
        "state Abort: abort\n"
    )
    assert checks_of(text) == {"C6"}


def test_sanitizing_assignment_clears_taint() -> None:
    text = (
        "state Init:\n"
        "    receive m(q)\n"
        "    timeout -> Abort\n"
        "    verify q fail -> Deny\n"
        "    b = sanitize(q)\n"
        "    exec b\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Deny: deny\n"
        "state Abort: abort\n"
    )
    assert checks_of(text) == set()


def test_c5_fires_when_any_path_is_unauthenticated() -> None:
    # Two routes into Session: one authenticated, one not. The property is
    # per-path, so the unauthenticated route must still be reported.
    text = (
        "state Init:\n"
        "    receive m(choice)\n"
        "    timeout -> Direct\n"
        "    authenticate ok -> Session fail -> Deny\n"
        "state Direct:\n"
        "    -> Session\n"
        "state Session: trusted\n"
        "state Deny: deny\n"
    )
    assert "C5" in checks_of(text)


def test_timeout_edge_carries_fact_at_its_position() -> None:
    # The timeout fires while Init is still blocked on its receive, before
    # the authenticate below it runs, so Session is reachable
    # unauthenticated even though the linear body authenticates before
    # the goto.
    text = (
        "state Init:\n"
        "    receive m(x)\n"
        "    timeout -> Session\n"
        "    authenticate fail -> Deny\n"
        "    -> Session\n"
        "state Session: trusted\n"
        "state Deny: deny\n"
    )
    assert "C5" in checks_of(text)


def test_timeout_path_keeps_taint_acquired_earlier_in_the_body() -> None:
    # x is tainted before the second blocking point; the timeout edge to
    # Leak must carry that taint (entry-fact semantics would drop it and
    # miss the exec violation).
    text = (
        "state Init:\n"
        "    receive first(p)\n"
        "    timeout -> Abort\n"
        "    verify p fail -> Deny\n"
        "    x = p\n"
        "    receive second(y)\n"
        "    timeout -> Leak\n"
        "    -> Done\n"
        "state Leak:\n"
        "    exec x\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Deny: deny\n"
        "state Abort: abort\n"
    )
    assert checks_of(text) == {"C6"}


def test_each_receive_needs_its_own_timeout_guard() -> None:
    # One timeout guards the first receive; the second blocking point has
    # no escape and must be reported by C1.
    text = (
        "state Init:\n"
        "    receive a(x)\n"
        "    timeout -> Abort\n"
        "    receive b(y)\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Abort: abort\n"
    )
    assert checks_of(text) == {"C1"}


def test_secret_reaching_sink_pre_auth_is_flagged() -> None:
    # Disclosure via a sink is as bad as a send; param() makes a value
    # injection-safe, not disclosure-safe.
    text = (
        "secret token\n"
        "state Init:\n"
        "    query param(token)\n"
        "    -> Done\n"
        "state Done: terminal\n"
    )
    assert checks_of(text) == {"C4"}


def test_secret_aliasing_is_tracked() -> None:
    text = (
        "secret token\n"
        "state Init:\n"
        "    leaked = token\n"
        "    send leaked\n"
        "    -> Done\n"
        "state Done: terminal\n"
    )
    assert checks_of(text) == {"C4"}


def test_unreachable_violations_are_not_reported() -> None:
    # The offending state exists but no path reaches it; path-sensitive
    # checks stay quiet (structural C1/C3 would still fire if violated).
    text = (
        "secret token\n"
        "state Init:\n"
        "    -> Done\n"
        "state Ghost:\n"
        "    send token\n"
        "    -> Done\n"
        "state Done: terminal\n"
    )
    assert checks_of(text) == set()


def test_dead_actions_and_orphan_states_warn_but_do_not_fail() -> None:
    # The goto after a both-target verify can never execute (W1), so the
    # state it names is unreachable (W2). Neither is a security finding.
    text = (
        "state Init:\n"
        "    verify x ok -> Done fail -> Deny\n"
        "    -> Orphan\n"
        "state Orphan:\n"
        "state Done: terminal\n"
        "state Deny: deny\n"
    )
    spec = parse(text)
    assert {f.check for f in check_all(spec)} == set()
    warns = warn_all(spec)
    assert {(f.check, f.state) for f in warns} == {("W1", "Init"), ("W2", "Orphan")}


def test_analysis_budget_fails_loudly_instead_of_approximating() -> None:
    spec = parse("state A:\n    -> B\nstate B: terminal\n")
    with pytest.raises(AnalysisBudgetExceeded):
        check_all(spec, budget=1)


def test_re_receive_re_taints_and_unverifies() -> None:
    text = (
        "state Init:\n"
        "    receive m(q)\n"
        "    timeout -> Abort\n"
        "    verify q fail -> Deny\n"
        "    -> Again\n"
        "state Again:\n"
        "    receive m(q)\n"
        "    timeout -> Abort\n"
        "    query param(q)\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Deny: deny\n"
        "state Abort: abort\n"
    )
    # the second receive re-binds q unverified; param() covers C6 but not C2
    assert checks_of(text) == {"C2"}
