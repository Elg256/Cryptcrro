
from cryptography.fernet import Fernet

import secrets
import os
import base64

import random
import hashlib

from cryptcrro.utility import insert_newlines_with_tags
from cryptcrro.secp256k1 import point_multiply , n ,gx ,gy

generator_point = gx , gy

def generate_private_key():

    private_key = int.from_bytes(os.urandom(32), byteorder='big')
    #private_key = secrets.randbelow(n-1) + 1 # why? you don't want to know :)

    return private_key


def generate_public_key(private_key):
    private_key = int(private_key)
    public_key = point_multiply(private_key,generator_point)

    return public_key

def encrypt_aes256(symetric_key ,message):

    fernet_key  = base64.urlsafe_b64encode(bytes.fromhex(symetric_key))

    fernet = Fernet(fernet_key)

    encrypted_message = fernet.encrypt(message.encode())

    return encrypted_message


def decrypt_aes256(symetric_key, encrypted_message):

    fernet_key = base64.urlsafe_b64encode(bytes.fromhex(symetric_key))

    fernet = Fernet(fernet_key)

    decrypted_message = fernet.decrypt(encrypted_message)

    return decrypted_message


def encrypt_message(public_key, message):

    # private_key = os.urandom(32)
    random_int = secrets.randbelow(n-1) + 1

    random_int_on_curve = point_multiply(random_int, generator_point)

    shared_secret = point_multiply(random_int,public_key)

    gx_shared, gy_shared = shared_secret
    gx_shared = str(gx_shared)


    symetric_key = hashlib.sha256(gx_shared.encode('utf-8')).hexdigest()

    encrypted_message = encrypt_aes256(symetric_key ,message)

    return random_int_on_curve, encrypted_message


def decrypt_message(private_key, encrypted_message):


    start_marker = "---BEGIN CRRO MESSAGE---"
    end_marker = "---END CRRO MESSAGE---"
    if start_marker in encrypted_message and end_marker in encrypted_message:
        start_index = encrypted_message.index(start_marker) + len(start_marker)
        end_index = encrypted_message.index(end_marker)
        encrypted_message = encrypted_message[start_index:end_index].strip()


    # Extraire la clé et le message chiffré
    start_marker = "---BEGIN CURVE INT---"
    end_marker = "---END CURVE INT---"



    if start_marker not in encrypted_message or end_marker not in encrypted_message:
        print("Here Error, Missing CRUVE INT key in ciphertext, or missing private key.")

        return

    start_index = encrypted_message.index(start_marker) + len(start_marker)
    end_index = encrypted_message.index(end_marker)
    cle_hex = encrypted_message[start_index:end_index].strip()
    random_int_on_curve = cle_hex.replace(" ", "").replace("\n", "")

    random_int_on_curve = base64.b64decode(random_int_on_curve).decode()

    random_int_on_curve = random_int_on_curve.replace(" ", "").replace("(", "").replace(")",
                                                                                        "").split(
        ",")

    random_int_on_curve = tuple(
        int(random_int_on_curve) for random_int_on_curve in random_int_on_curve)

    message_hex = encrypted_message[end_index + len(end_marker):].strip()
    message_hex = message_hex.replace(" ", "").replace("\n", "")

    encrypted_message = encrypted_message[end_index + len(end_marker):].strip()
    # message_hex = base64.b64decode(message_base64).hex()


    encrypted_message.encode('utf-8')


    shared_secret = point_multiply(private_key,random_int_on_curve)

    gx_shared, gy_shared = shared_secret
    gx_shared = str(gx_shared)

    symetric_key = hashlib.sha256(gx_shared.encode('utf-8')).hexdigest()

    decrypted_message = decrypt_aes256(symetric_key,encrypted_message)

    return decrypted_message

'''
private_key = generate_private_key()

public_key = generate_public_key(private_key)

message = "Hello world"

encrypt_message = encrypt_message(public_key, message)

print("end" ,encrypt_message)

decrypted_message = decrypt_message(private_key, encrypt_message)

print(decrypted_message)

'''


