# C2 fail: the received field is sent before any verify step.
state Init:
    receive login(user)
    timeout -> Abort
    send user
    verify user fail -> Deny
    -> Done

state Done: terminal
state Deny: deny
state Abort: abort
