# C2 pass: the received field passes verify before it is used.
state Init:
    receive login(user)
    timeout -> Abort
    verify user fail -> Deny
    send user
    -> Done

state Done: terminal
state Deny: deny
state Abort: abort
