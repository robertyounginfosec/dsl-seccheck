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


def test_timeout_before_authenticate_reaches_state_unauthenticated() -> None:
    # The timeout guards receive m; when it fires, the authenticate below
    # never ran, so Session is reached unauthenticated. Under the exact
    # semantics the timeout carries the fact from before m (authed=False),
    # so C5 fires.
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


def test_dead_code_is_invisible_to_both_engine_and_warnings() -> None:
    # Divergence guard for the shared control-flow definition
    # (model.live_actions). The dead `exec q` would be a C6 finding and
    # the dead `-> Ghost` would make a trusted state reachable (C5) if
    # the engine ever executed past the flow end; the dead goto would
    # also hide the W2 if the warnings' edge collection ever included
    # dead edges. If either consumer stops honoring the shared flow-end
    # rule, one of these assertions trips.
    text = (
        "state Init:\n"
        "    receive m(q)\n"
        "    timeout -> Abort\n"
        "    verify q ok -> Done fail -> Deny\n"
        "    exec q\n"
        "    -> Ghost\n"
        "state Ghost: trusted\n"
        "state Done: terminal\n"
        "state Deny: deny\n"
        "state Abort: abort\n"
    )
    spec = parse(text)
    assert {f.check for f in check_all(spec)} == set()
    warns = {(f.check, f.state) for f in warn_all(spec)}
    # Ghost is also a bodyless non-terminal dead-end (W3).
    assert warns == {("W1", "Init"), ("W2", "Ghost"), ("W3", "Ghost")}


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
    warns = {(f.check, f.state) for f in warn_all(spec)}
    # Orphan is unreachable (W2) and also a bodyless dead-end (W3).
    assert warns == {("W1", "Init"), ("W2", "Orphan"), ("W3", "Orphan")}


def test_timeout_excludes_the_bindings_of_the_receive_it_guards() -> None:
    # Exactness, direction (a). The ONLY path into UseQ is Init's timeout,
    # which guards receive m. When it fires, m never bound q, so q is not
    # tainted on that edge: `query q` in UseQ is clean, no C6. (Position-
    # fact semantics wrongly reported this as the over-approximation FP.)
    text = (
        "state Init:\n"
        "    receive m(q)\n"
        "    timeout -> UseQ\n"
        "    -> Done\n"
        "state UseQ:\n"
        "    query q\n"
        "    -> Done\n"
        "state Done: terminal\n"
    )
    assert checks_of(text) == set()


def test_timeout_reports_taint_a_later_clear_never_reached() -> None:
    # Exactness, direction (b) - the FN the exact semantics closes. x is
    # tainted before the second receive, then cleared AFTER it. A fired
    # timeout on the second receive means that clear never ran, so the
    # timeout edge to Leak must still carry x tainted -> C6 reported.
    # (Position-fact semantics reflected the clear and missed this.)
    text = (
        "state Init:\n"
        "    receive first(p)\n"
        "    timeout -> Abort\n"
        "    verify p fail -> Deny\n"
        "    x = p\n"
        "    receive second(y)\n"
        "    x = sanitize(x)\n"
        "    timeout -> Leak\n"
        "    -> Done\n"
        "state Leak:\n"
        "    query x\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Deny: deny\n"
        "state Abort: abort\n"
    )
    assert checks_of(text) == {"C6"}


def test_timeout_guarding_a_receive_is_not_w4() -> None:
    text = (
        "state Init:\n"
        "    receive m(x)\n"
        "    timeout -> Abort\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Abort: abort\n"
    )
    assert warn_all(parse(text)) == []


def test_timeout_without_preceding_receive_is_w4() -> None:
    text = (
        "state Init:\n"
        "    timeout -> Abort\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Abort: abort\n"
    )
    warns = {(f.check, f.state) for f in warn_all(parse(text))}
    assert warns == {("W4", "Init")}


def test_dead_timeout_after_flow_end_does_not_guard_receive() -> None:
    # Suppression direction for the C1 live-actions fix. The receive is
    # followed by a goto (flow ends), then a dead `timeout -> Abort`.
    # That dead timeout must NOT clear C1 for the receive before it;
    # walking st.actions instead of live_actions would hide the finding.
    text = (
        "state Init:\n"
        "    receive m(x)\n"
        "    -> Done\n"
        "    timeout -> Abort\n"
        "state Done: terminal\n"
        "state Abort: abort\n"
    )
    assert "C1" in checks_of(text)


def test_c3_rejects_fail_target_with_live_outgoing_edges() -> None:
    # The fail target is flagged deny but escapes via a goto, so it is not
    # actually terminal: C3 must reject it.
    text = (
        "state Init:\n"
        "    receive m(x)\n"
        "    timeout -> Abort\n"
        "    verify x ok -> Done fail -> Leaky\n"
        "state Leaky: deny\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "state Abort: abort\n"
    )
    assert "C3" in checks_of(text)


def test_c3_accepts_truly_terminal_deny_target() -> None:
    text = (
        "state Init:\n"
        "    receive m(x)\n"
        "    timeout -> Abort\n"
        "    verify x ok -> Done fail -> Deny\n"
        "state Deny: deny\n"
        "state Done: terminal\n"
        "state Abort: abort\n"
    )
    assert "C3" not in checks_of(text)


def test_w3_flags_non_terminal_dead_end() -> None:
    text = (
        "state Init:\n"
        "    send x\n"
        "state Done: terminal\n"
    )
    warns = {(f.check, f.state) for f in warn_all(parse(text))}
    assert ("W3", "Init") in warns


def test_w3_absent_when_dead_end_is_flagged_terminal() -> None:
    text = (
        "state Init:\n"
        "    -> Stop\n"
        "state Stop: terminal\n"
        "    send x\n"
    )
    # Stop has a body but no outgoing edge and IS terminal -> no W3.
    warns = {(f.check, f.state) for f in warn_all(parse(text))}
    assert not any(c == "W3" for c, _ in warns)


def test_w5_flags_terminal_state_with_outgoing_edge() -> None:
    text = (
        "state Init:\n"
        "    -> Done\n"
        "state Done: terminal\n"
        "    -> Init\n"
    )
    warns = {(f.check, f.state) for f in warn_all(parse(text))}
    assert ("W5", "Done") in warns


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
