# (a) Single receive with a fact-clearing assign between the receive and its
# timeout. The assign removes token's secret label, but a fired timeout means
# that assign never ran: the timeout edge carries token still-secret from
# before the receive, so "send token" in Leak is a C4 disclosure. This is the
# resolved 0.2.0 false negative - the position-fact semantics carried the
# cleared value and missed it. The target sinks the variable, so the fact is
# observable to the differential oracle.
secret token
state Init:
    receive m(x)
    token = "cleared"
    timeout -> Leak
    -> Done
state Leak:
    send token
    -> Done
state Done: terminal
