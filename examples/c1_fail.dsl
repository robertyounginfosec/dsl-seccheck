# C1 fail: Init blocks on receive with no timeout transition declared.
state Init:
    receive ping(seq)
    -> Done

state Done: terminal
