import hashlib
from cryptcrro.secp256k1 import *
import base64
import os

p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1


# first using modular



message_to_sign = "Hello World"

private_key = int.from_bytes(os.urandom(32))


public_key = pow(3, -private_key , p) #before with -private_key

k = int.from_bytes(os.urandom(32))

r = pow(3,k, p)

e = int.from_bytes(hashlib.sha256((str(r) + message_to_sign).encode()).digest())

s = (k + private_key * e) % (p-1)

signature = s, e

print("signature",signature)

# let check

s_v, e_v = signature

print("here")

r_v = (pow(3, s_v, p) * pow(public_key, e_v, p) ) % p

print("r",r, "r_v", r_v)

e_v2 = int.from_bytes(hashlib.sha256((str(r) + message_to_sign).encode()).digest()) % p


if e_v == e_v2:
    print("The signature is True")

else:
    print("signature False")

print(r_v)
