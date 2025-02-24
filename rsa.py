import os
import base64
import random
import hashlib

from cryptcrro.utility import insert_newlines_with_tags
from cryptcrro.secp256k1 import gx, gy
from cryptcrro.arith import next_prime

import rust_cryptcrro


generator_point = gx , gy

e = 65537


def hashing_message_int(message):
    hash = int(hashlib.sha256(message).hexdigest(), 16)

    return hash

def generate_keys(key_size=2048):

    while True:
        p = next_prime(int.from_bytes(os.urandom(key_size // 2  // 8), byteorder='big'))
        q = next_prime(int.from_bytes(os.urandom(key_size // 2 // 8), byteorder='big'))

        if p != q:
            break

    n = p * q
    phi = (p - 1) * (q - 1)

    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)

    return private_key, public_key


def encrypt_aes256(symetric_key, message):
    return bytes.fromhex(rust_cryptcrro.aes256_ctr_encrypt(symetric_key, message.hex()))

def decrypt_aes256(symetric_key, encrypted_message):
    return bytes.fromhex(rust_cryptcrro.aes256_ctr_decrypt(symetric_key,
                                                           base64.urlsafe_b64decode(encrypted_message).hex()))

def encrypt_message(public_key, message):

    e,n = public_key
    symetric_key = os.urandom(32)

    int_symetric_key = int.from_bytes(symetric_key, byteorder='big')

    encrypted_key = pow(int_symetric_key, e, n)
    encrypted_key = base64.urlsafe_b64encode((encrypted_key.to_bytes((encrypted_key.bit_length() + 7) //8, byteorder='big'))).decode()
 
    encrypted_message = base64.urlsafe_b64encode(encrypt_aes256(symetric_key.hex() ,message))

    return encrypted_key, encrypted_message


def decrypt_message(private_key, encrypted_message):
    
    d, n =  private_key

    start_marker = "---BEGIN CRRO MESSAGE---"
    end_marker = "---END CRRO MESSAGE---"
    if start_marker in encrypted_message and end_marker in encrypted_message:
        start_index = encrypted_message.index(start_marker) + len(start_marker)
        end_index = encrypted_message.index(end_marker)
        encrypted_message = encrypted_message[start_index:end_index].strip()

    start_marker = "---Start AES key---"
    end_marker = "---End AES key---"



    if start_marker not in encrypted_message or end_marker not in encrypted_message:
        raise ValueError("An Error occurred, Wrong/Missing private key or Missing AES key in ciphertext.")
        return

    start_index = encrypted_message.index(start_marker) + len(start_marker)
    end_index = encrypted_message.index(end_marker)
    symetric_key_encrypted = encrypted_message[start_index:end_index].strip()
    symetric_key_encrypted = symetric_key_encrypted.replace(" ", "").replace("\n", "")

    message = encrypted_message[end_index + len(end_marker):].strip()
    message = message.replace(" ", "").replace("\n", "")

    encrypted_message = encrypted_message[end_index + len(end_marker):].strip()

    symetric_key_encrypted_int = base64.urlsafe_b64decode(symetric_key_encrypted)

    symetric_key = pow(int.from_bytes(symetric_key_encrypted_int), d , n)  # need to de a blind decryption

    symetric_key = symetric_key.to_bytes(32, byteorder='big')

    decrypted_message = decrypt_aes256(symetric_key.hex(), encrypted_message)

    return decrypted_message


def sign(private_key:tuple, message:bytes):
    d, n = private_key

    hash_message_int = hashing_message_int(message)

    encrypted_hash = pow(hash_message_int, d, n)  # (int_symetric_key ** e) % n

    encrypted_hash = base64.urlsafe_b64encode(
        (encrypted_hash.to_bytes((encrypted_hash.bit_length() + 7) // 8, byteorder='big'))).decode()

    return encrypted_hash

def check_sig(public_key, signature, message):

    e, n = public_key

    hash_message_int = hashing_message_int(message.encode())

    decrypt_sig = pow(int.from_bytes(base64.urlsafe_b64decode(signature)), e, n)

    if hash_message_int == decrypt_sig:
        return True
    else:
        return False
