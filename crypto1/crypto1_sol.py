#!/usr/bin/env python

from Crypto.Cipher import XOR

out = "ed139bafa3833c178afd29f21dc16f94a869c49b90d06373b99e5b8b6db530b5".decode("hex")

encryptedIV = out[:16]
cipher = out[16:]

t = XOR.new(encryptedIV)
print t.decrypt(cipher)
