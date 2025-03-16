import secrets
import os

import base64

import random
import hashlib

from cryptcrro.secp256k1 import point_multiply , n ,gx ,gy ,point_addition
from cryptcrro import _rust


def hashing_message_int(message):
    return int(hashlib.sha256(message).hexdigest(), 16)

def sign(private_key:int, message:bytes):
    hash_message = hashing_message_int(message)
    return _rust.create_ecdsa_sig(private_key, hash_message)

def check_signature(public_key:[int, int], signature:[int, int], message:bytes):
    hash_message_int = hashing_message_int(message)
    i = _rust.check_sig(public_key, signature, hash_message_int)

    x = signature[0]
    
    if i == x:
        signature_True = True
    else:
        signature_True = False

    return signature_True

