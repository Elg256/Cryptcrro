import os
import base64
import hashlib
from cryptcrro.utility import insert_newlines_with_tags
from cryptcrro import _rust

generator_point = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def generate_private_key():
    return int.from_bytes(os.urandom(32), byteorder='big')

def generate_public_key(private_key:int):
    return _rust.generate_public_key(int(private_key))


def encrypt_symetric(symetric_key, message):
    return bytes(_rust.chacha20_encrypt(symetric_key, message.hex()))


def decrypt_symetric(symetric_key, encrypted_message):
    return bytes.fromhex(_rust.chacha20_decrypt(symetric_key,
                                                           base64.urlsafe_b64decode(encrypted_message).hex()))

def encrypt_message(public_key, message):

    random_int = int.from_bytes(os.urandom(32))

    random_int_on_curve = _rust.ecies_mul_points(random_int, generator_point)

    shared_secret = _rust.ecies_mul_points(random_int, public_key)

    gx_shared, gy_shared = shared_secret
    gx_shared = str(gx_shared)

    symetric_key = hashlib.sha256(gx_shared.encode('utf-8')).digest()

    encrypted_message = encrypt_symetric(symetric_key ,message)

    return random_int_on_curve, encrypted_message


def decrypt_message(private_key, encrypted_message):

    start_marker = "---BEGIN CRRO MESSAGE---"
    end_marker = "---END CRRO MESSAGE---"
    if start_marker in encrypted_message and end_marker in encrypted_message:
        start_index = encrypted_message.index(start_marker) + len(start_marker)
        end_index = encrypted_message.index(end_marker)
        encrypted_message = encrypted_message[start_index:end_index].strip()

    start_marker = "---BEGIN CURVE INT---"
    end_marker = "---END CURVE INT---"

    if start_marker not in encrypted_message or end_marker not in encrypted_message:
        raise ValueError("An Error occurred, Wrong/Missing private key or Missing CRUVE INT key in ciphertext.")

    start_index = encrypted_message.index(start_marker) + len(start_marker)
    end_index = encrypted_message.index(end_marker)
    cle_hex = encrypted_message[start_index:end_index].strip()
    random_int_on_curve = cle_hex.replace(" ", "").replace("\n", "")

    random_int_on_curve = base64.urlsafe_b64decode(random_int_on_curve)

    x = int.from_bytes(random_int_on_curve[:32])
    y = int.from_bytes(random_int_on_curve[32:])

    random_int_on_curve = x, y

    message_hex = encrypted_message[end_index + len(end_marker):].strip()
    message_hex = message_hex.replace(" ", "").replace("\n", "")

    encrypted_message = encrypted_message[end_index + len(end_marker):].strip()

    encrypted_message.encode('utf-8')

    shared_secret = _rust.ecies_mul_points(private_key, random_int_on_curve)

    gx_shared, gy_shared = shared_secret
    gx_shared = str(gx_shared)

    symetric_key = hashlib.sha256(gx_shared.encode('utf-8')).digest()

    decrypted_message = decrypt_symetric(symetric_key, encrypted_message)

    return decrypted_message
