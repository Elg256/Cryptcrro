from cryptcrro.sha256_ctr import generate_key , encrypt ,decrypt
import os

import base64

class crro:

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
