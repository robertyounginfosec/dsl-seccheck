# FN-1 (mismatched wrapper): sanitize() escapes for a render context, not for
# a query sink. As the whole argument of a query it does NOT neutralize q, so
# C6 must fire. Pre-0.4.0 any wrapper cleared any sink regardless of kind.
state Init:
    receive req(q)
    timeout -> Abort
    verify q fail -> Deny
    query sanitize(q)
    -> Done
state Done: terminal
state Deny: deny
state Abort: abort
