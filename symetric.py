from cryptcrro.aes256_ctr import generate_key , encrypt ,decrypt
from cryptcrro.sha256_ctr import encrypt as sha256_ctr_encrypt
from cryptcrro.sha256_ctr import decrypt as sha256_ctr_decrypt
from cryptcrro.sha256_ctr import generate_key as sha256_generate_key
import os

import base64

class crro:

    @staticmethod
    def generate_key() -> bytes:
        return generate_key()

    @staticmethod
    def encrypt(key, message: bytes) -> bytes:
        encrypted_message = encrypt(key, message)
        return encrypted_message

    @staticmethod
    def decrypt(key, encrypted_message) -> bytes:
        encrypted_message = encrypted_message
        decrypted_message = decrypt(key, encrypted_message)
        return decrypted_message

class Sha256_Ctr:

    @staticmethod
    def generate_key() -> bytes:
        return generate_key()

    @staticmethod
    def encrypt(key, message: bytes, padding = True) -> bytes:
        encrypted_message = sha256_ctr_encrypt(key, message)
        return encrypted_message

    @staticmethod
    def decrypt(key, encrypted_message, padding = True) -> bytes:
        encrypted_message = base64.urlsafe_b64decode(encrypted_message)
        decrypted_message = sha256_ctr_decrypt(key, encrypted_message)
        return decrypted_message

class AES256_Ctr:

    @staticmethod
    def generate_key() -> bytes:
        return generate_key()

    @staticmethod
    def encrypt(key, message: bytes, padding = True) -> bytes:
        encrypted_message = encrypt(key, message)
        return encrypted_message

    @staticmethod
    def decrypt(key, encrypted_message, padding = True) -> bytes:
        encrypted_message = base64.urlsafe_b64decode(encrypted_message)
        decrypted_message = decrypt(key, encrypted_message)
        return decrypted_message