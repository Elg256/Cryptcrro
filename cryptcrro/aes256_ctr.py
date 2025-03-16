import hashlib
import os
import base64
from cryptcrro.hmac import hmac_sha256
from cryptcrro import _rust
import time


def generate_key():
    return os.urandom(32)


def encrypt(key: bytes, message: bytes) -> bytes:
    ciphertext = bytes.fromhex(_rust.aes256_ctr_encrypt(key.hex(), message.hex()))
    hmac = hmac_sha256(key, ciphertext)
    return base64.urlsafe_b64encode((hmac + ciphertext))


def decrypt(key: bytes, message: bytes) -> bytes:
    message = base64.urlsafe_b64decode(message)
    hmac = message[:32]
    ciphertext = message[32:]
    calc_hmac = hmac_sha256(key, ciphertext)

    if hmac != calc_hmac:
        raise ValueError("Invalid HMAC: verification failed")

    plaintext = bytes.fromhex(rust_cryptcrro.aes256_ctr_decrypt(key.hex(), ciphertext.hex()))

    return plaintext
