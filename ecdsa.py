import secrets
import os

import base64

import random
import hashlib

from cryptcrro.secp256k1 import point_multiply , n ,gx ,gy ,point_addition


def hashing_message_int(message):
    return int(hashlib.sha256(message).hexdigest(), 16)

def verification_signature(public_key,signature,message):

    x_signature, y_signature = signature
    hash_int = hashing_message_int(message.encode())
    y_signature = int(y_signature)

    s_inv = pow(y_signature, -1, n)
    u1 = (hash_int * s_inv) % n
    u2 = (x_signature * s_inv) % n

    X1, Y1 = point_multiply(u1, (gx, gy))
    X2, Y2 = point_multiply(u2, public_key)
    X, Y = point_addition(X1, Y1, X2, Y2)
    X = X % n

    return X , x_signature


def ecdsa_signature(private_key,message):

    hash_int = hashing_message_int(message)
    random_int = int.from_bytes(os.urandom(32))
    #random_int = secrets.randbelow(n - 1) + 1

    random_point = point_multiply(random_int, (gx, gy))
    x_random, y_random = random_point
    x_signature = x_random % n
    y_signature = ((hash_int + private_key * x_signature) * pow(random_int, -1, n)) % n

    signature = x_signature, y_signature

    return signature
