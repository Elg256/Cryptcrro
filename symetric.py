from cryptcrro.sha256_ctr import generate_key , encrypt ,decrypt, decrypt_without_padding, encrypt_without_padding
import os

import base64

class crro:

    @staticmethod
    def generate_key() -> bytes:
        key = generate_key()

        return key


    @staticmethod
    def encrypt(key, message: bytes, padding = True) -> bytes:

        if padding == False:
            encrypted_message = encrypt_without_padding(key, message)
            
        else:
            encrypted_message = encrypt(key, message)

        return encrypted_message



    @staticmethod
    def decrypt(key, encrypted_message, padding = True) -> bytes:

        encrypted_message = base64.urlsafe_b64decode(encrypted_message)


        if padding == False:
            decrypted_message = decrypt_without_padding(key, encrypted_message)
        else:

            decrypted_message = decrypt(key, encrypted_message)

        return decrypted_message
