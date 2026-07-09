# C3 fail: verify failure lands in a plain terminal state, not deny/abort,
# so a failed verification does not fail closed.
state Init:
    receive hello(nonce)
    timeout -> Abort
    verify nonce ok -> Done fail -> Done

state Done: terminal
state Abort: abort
