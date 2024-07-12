
from cryptography.fernet import Fernet

import secrets
import os
import base64

import random
import hashlib
from cryptcrro.secp256k1 import point_multiply , n ,gx ,gy

generator_point = gx , gy

def generate_private_key():

    #private_key = os.urandom(32)
    private_key = secrets.randbelow(n-1) + 1 # why? you don't want to know :)

    return private_key


def generate_public_key(private_key):
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

    random_int = secrets.randbelow(n-1) + 1

    random_int_on_curve = point_multiply(random_int, generator_point)

    shared_secret = point_multiply(random_int,public_key)

    gx_shared, gy_shared = shared_secret
    gx_shared = str(gx_shared)


    symetric_key = hashlib.sha256(gx_shared.encode('utf-8')).hexdigest()

    encrypted_message = encrypt_aes256(symetric_key ,message)

    return random_int_on_curve,encrypted_message

def decrypt_message(private_key, random_int_on_curve, encrypted_message):

    shared_secret = point_multiply(private_key,random_int_on_curve)

    gx_shared, gy_shared = shared_secret
    gx_shared = str(gx_shared)

    symetric_key = hashlib.sha256(gx_shared.encode('utf-8')).hexdigest()

    decrypted_message = decrypt_aes256(symetric_key,encrypted_message)

    return decrypted_message