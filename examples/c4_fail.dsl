# C4 fail: the secret is sent on a path that never authenticates.
secret token

state Init:
    send token
    -> Done

state Done: terminal
