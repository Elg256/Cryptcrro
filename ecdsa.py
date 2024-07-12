from cryptography.fernet import Fernet

import secrets

import base64

import random
import hashlib

from cryptcrro.secp256k1 import point_multiply , n ,gx ,gy ,point_addition

#private_key = 29614089468857638080889876681931735704923737530063087789996222271441416354293

#public_key = (53703938601645171900027426597892701600373663703363891516176297865259653411090, 65822541145976848934910282135599441621086771871930479247414434128295844136401)

#message = "bonjour a tous"

#hash = hashlib.sha256(message.encode('utf-8')).hexdigest()

#print(hash)

#y_int =  int(hash, 16)

#print(y_int)

def hashing_message_int(message):
    hash = int(hashlib.sha256(message.encode('utf-8')).hexdigest(), 16)

    return hash

def verification_signature(public_key,signature,message):

    x_signature, y_signature = signature

    hash_int = hashing_message_int(message)

    y_signature = int(y_signature)

    s_inv = pow(y_signature, -1, n)
    u1 = (hash_int * s_inv) % n
    u2 = (x_signature * s_inv) % n
    X1, Y1 = point_multiply(u1, (gx, gy))
    X2, Y2 = point_multiply(u2, public_key)
    X, Y = point_addition(X1, Y1, X2, Y2)


    X = X % n

    return X , x_signature


def ecdsa_signature(private_key,message):

    hash_int = hashing_message_int(message)

    #random_int = os.urandom(32)
    random_int = secrets.randbelow(n - 1) + 1

    random_point = point_multiply(random_int, (gx, gy))
    x_random, y_random = random_point
    x_signature = x_random % n
    y_signature = ((hash_int + private_key * x_signature) * pow(random_int, -1, n)) % n

    signature = x_signature, y_signature

    return signature





