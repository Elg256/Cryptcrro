import hashlib
import os
import base64
from cryptcrro.hmac import hmac_sha256



def generate_key():
    return base64.urlsafe_b64encode(os.urandom(32))


def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def padding(message):
    lenght_message_mod = len(message) % 32
    
    if lenght_message_mod == 0:
        return message

    padding_len = 32 - lenght_message_mod
    padding = bytes([padding_len] * padding_len)
    return message + padding


def unpadding(message):
    padding_len = message[-1]
    unpadded_message, padding = message[:-padding_len], message[-padding_len:]
    return unpadded_message


def split_message(message):

    block_size = 32  # 256 bits
    message_blocks = []
    for i in range(0, len(message), block_size):
        message_blocks.append(message[i:i+block_size])

    return message_blocks


def encrypt(key: bytes, message: bytes) -> bytes:

    padded_message = padding(message)
    padded_message_block = split_message(padded_message)

    ciphertext = []

    iv = os.urandom(16)

    for i in range(0, len(padded_message_block)):
        iv_with_count = iv + i.to_bytes(32, byteorder="big")
        key_and_iv = key + iv_with_count
        sha256 = hashlib.sha256(key_and_iv).digest()
        ciphertext_block = xor_bytes(sha256, padded_message_block[i])
        ciphertext_block = ciphertext_block
        ciphertext.append(ciphertext_block)

    hmac = hmac_sha256(key, iv + b"".join(ciphertext))
    return base64.urlsafe_b64encode((hmac + iv + b"".join(ciphertext)))


def decrypt(key: bytes, message: bytes) -> bytes:
    hmac = message[:32]
    iv = message[32:48]
    ciphertext = message[48:]

    calc_hmac = hmac_sha256(key, iv + ciphertext)

    if hmac != calc_hmac:
        raise ValueError("Invalid HMAC: verification failed")

    message_blocks = split_message(ciphertext)
    ciphertext = []

    for i in range(0, len(message_blocks)):
        iv_with_count = iv + i.to_bytes(32, byteorder="big")  # by using sha256 instead of aes we can use a bigger counter than 16 bytes
        key_and_iv = key + iv_with_count
        sha256 = hashlib.sha256(key_and_iv).digest()
        ciphertext_block = xor_bytes(sha256, message_blocks[i])
        ciphertext_block = ciphertext_block
        ciphertext.append(ciphertext_block)

    last_block = ciphertext.pop()
    last_block = unpadding(last_block)
    ciphertext.append(last_block)

    return b''.join(ciphertext)
