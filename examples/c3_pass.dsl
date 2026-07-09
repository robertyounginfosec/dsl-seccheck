# C3 pass: verify failure transitions to a terminal deny state.
state Init:
    receive hello(nonce)
    timeout -> Abort
    verify nonce ok -> Done fail -> Deny

state Done: terminal
state Deny: deny
state Abort: abort
