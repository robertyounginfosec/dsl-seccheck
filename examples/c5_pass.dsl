# C5 pass: the trusted state is only reachable through authenticate.
state Init:
    authenticate ok -> Session fail -> Deny

state Session: trusted
    -> Done

state Done: terminal
state Deny: deny
