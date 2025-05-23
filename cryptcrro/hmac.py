import hashlib

BLOCK_SIZE = 64 * 1024

def xor_bytes(a_b: bytes, b_b: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(a_b, b_b))


def hmac_sha256(secret: bytes, message: bytes) -> bytes:
    ipad = b"\x36" * 64
    opad = b"\x5c" * 64

    if len(secret) > 64:
        secret = hashlib.sha256(secret).digest()
        secret = secret.ljust(64, b'\x00')
    elif len(secret) < 64:
        secret = secret.ljust(64, b'\x00')

    final_hash = hashlib.sha256((xor_bytes(secret, opad)) + hashlib.sha256(xor_bytes(secret, ipad) + message).digest())\
        .digest()

    return final_hash

def hmac_sha256_chunk(secret: bytes):
    ipad = b"\x36" * 64
    opad = b"\x5c" * 64

    if len(secret) > 64:
        secret = hashlib.sha256(secret).digest()
    secret = secret.ljust(64, b'\x00')

    si = xor_bytes(secret, ipad)
    so = xor_bytes(secret, opad)

    inner = hashlib.sha256()
    inner.update(si)

    outer = hashlib.sha256()
    outer.update(so)

    return inner, outer
