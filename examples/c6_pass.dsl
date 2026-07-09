# C6 pass: tainted input reaches sinks only via param()/sanitize().
state Init:
    receive request(q)
    timeout -> Abort
    verify q fail -> Deny
    query param(q)
    render sanitize(q)
    -> Done

state Done: terminal
state Deny: deny
state Abort: abort
