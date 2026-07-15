# (b) Two blocking receives. The timeout on the SECOND receive carries the
# fact as of that receive blocking: the first receive completed (p is bound
# and tainted, and it is verified so it is not a C2), while the second did
# not (q is absent). In Both, "query p" is a C6 and "query q" is clean, so
# exactly one finding is expected. This pins that earlier completed receives
# are present on the edge and the guarded receive's own binding is absent.
state Init:
    receive first(p)
    timeout -> Abort
    verify p fail -> Deny
    receive second(q)
    timeout -> Both
    -> Done
state Both:
    query p
    query q
    -> Done
state Done: terminal
state Deny: deny
state Abort: abort
