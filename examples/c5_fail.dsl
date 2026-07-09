# C5 fail: a trusted state is reachable with no authenticate step on the path.
state Init:
    -> Session

state Session: trusted
    -> Done

state Done: terminal
