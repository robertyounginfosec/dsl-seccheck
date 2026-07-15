# FN-2 (assignment): wrapping a value in an assignment RHS must NOT create a
# durable clean variable. safe takes q's taint, so the later query safe is a
# C6. Pre-0.4.0 the assignment laundered q and safe was treated as clean.
state Init:
    receive req(q)
    timeout -> Abort
    verify q fail -> Deny
    safe = param(q)
    query safe
    -> Done
state Done: terminal
state Deny: deny
state Abort: abort
