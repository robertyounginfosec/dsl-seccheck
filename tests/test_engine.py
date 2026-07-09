"""Targeted semantics tests for the path-sensitive checks."""
from dsl_seccheck import check_all, parse


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


def test_timeout_edge_carries_state_entry_fact() -> None:
    # The timeout can fire while Init is still blocked on its receive,
    # before authenticate runs, so Session is reachable unauthenticated
    # even though the linear body authenticates before the goto.
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
