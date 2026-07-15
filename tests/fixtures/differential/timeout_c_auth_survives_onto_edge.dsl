# (c) Authenticate (fall-through, no ok target) runs BEFORE the receive, so it
# has completed by the time the receive blocks. The timeout carries the fact as
# of the receive blocking, which includes authed=True, so the trusted target is
# entered authenticated: no C5. A pure entry-fact semantics would carry
# authed=False and wrongly fire C5, so this pins that pre-receive actions
# survive onto the timeout edge.
state Init:
    authenticate fail -> Deny
    receive m(x)
    timeout -> Trusted
    -> Done
state Trusted: trusted
    -> Done
state Done: terminal
state Deny: deny
