# C4 pass: the secret is only sent after a successful authenticate.
secret token

state Init:
    authenticate ok -> Session fail -> Deny

state Session:
    send token
    -> Done

state Done: terminal
state Deny: deny
