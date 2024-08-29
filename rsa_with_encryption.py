
from cryptography.fernet import Fernet

import secrets
import os
import base64
import sympy

import random
import hashlib

from cryptcrro.utility import insert_newlines_with_tags
from cryptcrro.secp256k1 import point_multiply , n ,gx ,gy

generator_point = gx , gy

e = 65537

def generate_keys(key_size=2048):

    while True:
        p = sympy.nextprime(int.from_bytes(os.urandom(key_size // 2  // 8), byteorder='big'))
        q = sympy.nextprime(int.from_bytes(os.urandom(key_size // 2 // 8), byteorder='big'))

        if p != q:
            break

    n = p * q
    phi = (p - 1) * (q - 1)

    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)

    return private_key, public_key


def encrypt_aes256(symetric_key ,message):

    fernet = Fernet(symetric_key)

    encrypted_message = fernet.encrypt(message)

    return encrypted_message


def decrypt_aes256(symetric_key, encrypted_message):

    #fernet_key = base64.urlsafe_b64encode(str(symetric_key).encode())
    fernet_key = symetric_key
    #fernet_key = base64.urlsafe_b64encode(symetric_key.to_bytes(32, byteorder='big'))
    #fernet_key = base64.urlsafe_b64decode(symetric_key)
    fernet = Fernet(fernet_key)

    decrypted_message = fernet.decrypt(encrypted_message)

    return decrypted_message


def encrypt_message(public_key, message):

    e,n = public_key
    #symetric_key = os.urandom(32)
    symetric_key = base64.urlsafe_b64encode(os.urandom(32))

    symetric_key_str = str(base64.urlsafe_b64encode(symetric_key)).encode()

    print("symetric_key", symetric_key)

    int_symetric_key = int.from_bytes(symetric_key, byteorder='big')
    #random_int = secrets.randbelow(n-1) + 1
    print("int symetric_key", int_symetric_key)

    encrypted_key = pow(int_symetric_key, e, n) #(int_symetric_key ** e) % n

    print("encrypted_key", encrypted_key)

    encrypted_key = base64.urlsafe_b64encode((encrypted_key.to_bytes((encrypted_key.bit_length() + 7) //8, byteorder='big'))).decode()
 
    encrypted_message = encrypt_aes256(symetric_key ,message)

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
        print("Error, Missing AES key in ciphertext, or missing private key.")

        return

    start_index = encrypted_message.index(start_marker) + len(start_marker)
    end_index = encrypted_message.index(end_marker)
    symetric_key_encrypted = encrypted_message[start_index:end_index].strip()
    symetric_key_encrypted = symetric_key_encrypted.replace(" ", "").replace("\n", "")

    #symetric_key_encrypted = base64.urlsafe_b64decode(symetric_key_encrypted)

    message = encrypted_message[end_index + len(end_marker):].strip()
    message = message.replace(" ", "").replace("\n", "")

    encrypted_message = encrypted_message[end_index + len(end_marker):].strip()
    # message_hex = base64.b64decode(message_base64).hex()

    #encrypted_message.encode('utf-8')

    print("symetric_key_encrypted", symetric_key_encrypted)

    symetric_key_encrypted_int = base64.urlsafe_b64decode(symetric_key_encrypted)

    print("symetric_key_encrypted_int",symetric_key_encrypted_int)
    symetric_key = pow(int.from_bytes(symetric_key_encrypted_int), d , n)

    print("symetric_key", symetric_key)

    symetric_key = symetric_key.to_bytes(symetric_key.bit_length() + 7 // 8, byteorder='big')

    decrypted_message = decrypt_aes256(symetric_key,encrypted_message)

    return decrypted_message.decode()

