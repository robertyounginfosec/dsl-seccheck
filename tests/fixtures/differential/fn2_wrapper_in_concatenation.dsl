# FN-2 (concatenation): a param() wrapper is only neutralizing as the WHOLE
# sink argument. Here it is one term of a concatenation, so the tainted q is
# exposed and the exec sink must report C6. Pre-0.4.0 this was silently clean
# (the wrapper laundered q regardless of position).
state Init:
    receive cmd(q)
    timeout -> Abort
    verify q fail -> Deny
    exec "run " + param(q)
    -> Done
state Done: terminal
state Deny: deny
state Abort: abort
