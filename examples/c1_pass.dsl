# C1 pass: the blocking receive has a timeout escape.
state Init:
    receive ping(seq)
    timeout -> Abort
    -> Done

state Done: terminal
state Abort: abort
