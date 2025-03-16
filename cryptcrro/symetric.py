import os
import base64

from cryptcrro.chacha20 import encrypt as chacha20_encrypt
from cryptcrro.chacha20 import decrypt as chacha20_decrypt

from cryptcrro.aes256_ctr import encrypt as aes256_ctr_encrypt
from cryptcrro.aes256_ctr import decrypt as aes256_ctr_decrypt

from cryptcrro.sha256_ctr import generate_key as sha256_generate_key
from cryptcrro.sha256_ctr import encrypt as sha256_ctr_encrypt
from cryptcrro.sha256_ctr import decrypt as sha256_ctr_decrypt


class crro:

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)

    @staticmethod
    def encrypt(key: bytes, message: bytes) -> bytes:
        encrypted_message = chacha20_encrypt(key, message)
        return encrypted_message

    @staticmethod
    def decrypt(key: bytes, encrypted_message) -> bytes:
        decrypted_message = chacha20_decrypt(key, encrypted_message)
        return decrypted_message


class Sha256_Ctr:

    @staticmethod
    def generate_key() -> bytes:
        return sha256_generate_key() # need to be rewrite to be like other symetric encryption

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
        return os.urandom(32)

    @staticmethod
    def encrypt(key, message: bytes, padding = True) -> bytes:
        encrypted_message = aes256_ctr_encrypt(key, message)
        return encrypted_message

    @staticmethod
    def decrypt(key, encrypted_message, padding = True) -> bytes:
        encrypted_message = base64.urlsafe_b64decode(encrypted_message)
        decrypted_message = aes256_ctr_decrypt(key, encrypted_message)
        return decrypted_message

class ChaCha20:

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)

    @staticmethod
    def encrypt(key: bytes, message: bytes, padding = True) -> bytes:
        encrypted_message = chacha20_encrypt(key, message)
        return encrypted_message

    @staticmethod
    def decrypt(key: bytes, encrypted_message: bytes, padding = True) -> bytes:
        decrypted_message = chacha20_decrypt(key, encrypted_message)
        return decrypted_message