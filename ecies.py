
import random
import hashlib
from secp256k1 import point_multiply , n ,gx ,gy

generator_point = gx , gy

def generate_private_key():
    private_key = random.randint(1,n - 1 )


    return private_key

def generate_public_key(private_key):
    public_key = point_multiply(private_key,generator_point)

    return public_key

def encrypt_message(public_key):
    random_int = random.randint(1, n - 1)

    random_int_on_curve = point_multiply(random_int, generator_point)

    shared_secret = point_multiply(random_int,public_key)

    gx_shared, gy_shared = shared_secret
    gx_shared = str(gx_shared)


    symetric_key = hashlib.sha256(gx_shared.encode('utf-8')).hexdigest()

    encrypted_message= symetric_key #temp

    return random_int_on_curve,encrypted_message

def decrypt_message(private_key, random_int_on_curve):

    shared_secret = point_multiply(private_key,random_int_on_curve)

    gx_shared, gy_shared = shared_secret

    symetric_key = hashlib.sha256(gx_shared.encode('utf-8')).hexdigest

    decrypted_message = symetric_key #temp

    return decrypted_message