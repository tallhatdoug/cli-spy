#!/usr/bin/env python3
"""Generate a cli-spy operator keypair. pk = public key; sk = secret key. cli-spy.sk should never go to a target."""
from nacl.public import PrivateKey

sk = PrivateKey.generate()
with open("cli-spy.sk", "w") as f:
    f.write(bytes(sk).hex() + "\n")
with open("cli-spy.pk", "w") as f:
    f.write(bytes(sk.public_key).hex() + "\n")
print("wrote cli-spy.pk (ship to target) / cli-spy.sk (keep it safe, keep it secret)")
