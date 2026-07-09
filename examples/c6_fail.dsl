# C6 fail: taint propagates through concatenation into a query sink.
state Init:
    receive request(q)
    timeout -> Abort
    verify q fail -> Deny
    sql = "SELECT name FROM users WHERE id = " + q
    query sql
    -> Done

state Done: terminal
state Deny: deny
state Abort: abort
