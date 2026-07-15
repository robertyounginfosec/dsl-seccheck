# FN-1 (matching affinity guard): param() binds parameters for BOTH query and
# exec sinks, so param(q) as the whole argument of exec is correctly
# neutralized and must stay clean (no findings). Pins the affinity table's
# param -> {query, exec} entry so a future narrowing does not regress it.
state Init:
    receive cmd(q)
    timeout -> Abort
    verify q fail -> Deny
    exec param(q)
    -> Done
state Done: terminal
state Deny: deny
state Abort: abort
