import hashlib
import os
import base64

def generate_key():
    return base64.urlsafe_b64encode(os.urandom(32))

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def padding(message):

    padding_len = 32 - len(message) % 32

    if padding_len == 0:
        padding_len = 32

    padding = bytes([padding_len] * padding_len)

    return message + padding

def unpadding(message):
    padding_len = message[-1]
    unpadded_message, padding = message[:-padding_len], message[-padding_len:]
    return unpadded_message


def pad(plaintext):
    """"
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """

    padding_len = 32 - (len(plaintext) % 32)
    padding = bytes([padding_len] * padding_len)

    return plaintext + padding


def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """

    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message


def split_bytes_into_blocks(message_bytes, block_size=32):
    message_blocks = []
    for i in range(0, len(message_bytes), block_size):
        message_blocks.append(message_bytes[i:i + block_size])
    return message_blocks


def split_message_simple(message):

    block_size = 32  # 256 bits (32 octets)
    message_blocks = []
    for i in range(0, len(message), block_size):
        message_blocks.append(message[i:i+block_size])

    return message_blocks


def encrypt(key, message:bytes):

    padded_message = padding(message)
    padded_message_block = split_message_simple(padded_message)

    ciphertext = []

    iv = os.urandom(16)

    iv_int = int.from_bytes(iv)

    for i in range(0,len(padded_message_block)):

        iv_with_count = iv_int + (i+1) # by using sha256 instead of aes we don't need a counter that is x bits longs
        iv_with_count = hex(int(iv_with_count))[2:]

        key_and_iv = bytes.fromhex(iv_with_count) + key
        sha256 = hashlib.sha256(key_and_iv).digest()

        ciphertext_block = xor_bytes(sha256, padded_message_block[i])
        ciphertext_block = ciphertext_block
        ciphertext.append(ciphertext_block)

    return base64.urlsafe_b64encode((iv + b"---" + b"".join(ciphertext)))


def encrypt_without_padding(key, message:bytes):

    padded_message_block = split_bytes_into_blocks(message)

    ciphertext = []

    iv = os.urandom(16)

    iv_int = int.from_bytes(iv)

    for i in range(0,len(padded_message_block)):

        iv_with_count = iv_int + (i + 1)  # by using sha256 instead of aes we don't need a counter that is x bits longs
        iv_with_count = hex(int(iv_with_count))[2:]
        key_and_iv = bytes.fromhex(iv_with_count) + key

        sha256 = hashlib.sha256(key_and_iv).digest()
        ciphertext_block = xor_bytes(sha256, padded_message_block[i])
        ciphertext_block = ciphertext_block
        ciphertext.append(ciphertext_block)

    return base64.urlsafe_b64encode((iv + b"---" + b"".join(ciphertext)))

def decrypt(key, message: bytes):

    message = message.split(b"---")

    iv_int = int.from_bytes(bytes(message[0]))

    message = message[1]
    message_blocks = split_message_simple(message)

    ciphertext = []

    for i in range(0, len(message_blocks)):
        iv_with_count = iv_int + (i + 1)  # by using sha256 instead of aes we don't need a counter that is x bits longs

        iv_with_count = hex(int(iv_with_count))[2:]

        key_and_iv = bytes.fromhex(iv_with_count) + key

        sha256 = hashlib.sha256(key_and_iv).digest()

        ciphertext_block = xor_bytes(bytes(sha256), message_blocks[i])

        ciphertext_block = ciphertext_block

        ciphertext.append(ciphertext_block)

    last_block = ciphertext.pop()

    last_block = unpadding(last_block)

    ciphertext.append(last_block)

    return b''.join(ciphertext)


def decrypt_without_padding(key, message:bytes):

    message = message.split(b"---")

    iv_int = int.from_bytes(bytes(message[0]))

    message = message[1]

    message_blocks = split_message_simple(message)

    ciphertext = []

    for i in range(0, len(message_blocks)):
        iv_with_count = iv_int + (i + 1)  # by using sha256 instead of aes we don't need a counter that is x bits longs

        iv_with_count = hex(int(iv_with_count))[2:]

        key_and_iv = bytes.fromhex(iv_with_count) + key

        sha256 = hashlib.sha256(key_and_iv).digest()

        ciphertext_block = xor_bytes(bytes(sha256), message_blocks[i])

        ciphertext_block = ciphertext_block

        ciphertext.append(ciphertext_block)


    return b''.join(ciphertext)
