from cryptcrro import ecies_with_encrypt_new
from cryptcrro import rsa_with_encryption
from cryptcrro.ecdsa import ecdsa_signature , verification_signature
from cryptcrro.utility import insert_newlines_with_tags , add_sign_tags , add_encrypt_tags_ecc,add_encrypt_tags_rsa, add_encrypt_and_sign_tags, extract_message_and_signature,extract_signature
import base64

class crro:

    @staticmethod
    def generate_private_key():
        private_key = ecies_with_encrypt_new.generate_private_key()

        return private_key

    @staticmethod
    def generate_public_key(private_key:int):
        public_key = ecies_with_encrypt_new.generate_public_key(private_key)

        return public_key

    @staticmethod
    def encrypt(public_key:tuple, message:bytes):

        random_int_on_curve, encrypted_message = ecies_with_encrypt_new.encrypt_message(public_key, message)

        encrypted_message_with_tags = add_encrypt_tags_ecc(random_int_on_curve, encrypted_message)

        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key:int, message:bytes):

        signature = ecdsa_signature(private_key ,message)

        signed_message = add_sign_tags(signature,message)

        return signed_message

    @staticmethod
    def sign_and_encrypt(private_key:int, public_key:tuple, message:bytes):

        signature = ecdsa_signature(private_key, message)

        signed_message = add_sign_tags(signature, message)

        random_int_on_curve, encrypted_and_sign_message = ecies_with_encrypt_new.encrypt_message(public_key, signed_message.encode())

        encrypted_and_sign_message_with_tags = add_encrypt_tags_ecc(random_int_on_curve, encrypted_and_sign_message).replace("---BEGIN CRRO MESSAGE---", "---BEGIN SIGNED CRRO MESSAGE---")
        return encrypted_and_sign_message_with_tags

    @staticmethod
    def decrypt_and_verify_signature(private_key: int, public_key: tuple, encrypted_message:str):

        decrypted_message = ecies_with_encrypt_new.decrypt_message(private_key, encrypted_message)

        #print("decrypted_message", decrypted_message)

        signature, message = extract_message_and_signature(decrypted_message)

        #print("signature , message", signature, message)

        x, i = verification_signature(public_key, signature, message)

        if x == i:
            return True, message
        else:
            return False, message

    @staticmethod
    def decrypt(private_key:int, encrypted_message:str):

        decrypted_message = ecies_with_encrypt_new.decrypt_message(private_key, encrypted_message)

        return decrypted_message

    @staticmethod
    def verify_signature(public_key:tuple, signed_message:str):

        signature, message = extract_message_and_signature(signed_message)

        #print("signature , message",signature , message)

        x, i = verification_signature(public_key,signature,message)

        if x == i:
            return True , message
        else:
            return False , message



class rsa:

    @staticmethod
    def generate_keys(size=2048):
        private_key, public_key = rsa_with_encryption.generate_keys(size)
        return private_key , public_key

    @staticmethod
    def encrypt(public_key:tuple, message:bytes):

        encrypted_key, encrypted_message = rsa_with_encryption.encrypt_message(public_key, message)

        encrypted_message_with_tags = add_encrypt_tags_rsa(encrypted_key, encrypted_message)

        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key:int, message:bytes):

        signature = ecdsa_signature(private_key ,message)

        signed_message = add_sign_tags(signature,message)

        return signed_message

    @staticmethod
    def sign_and_encrypt(private_key:int, public_key:tuple, message:bytes):

        random_int_on_curve, encrypted_message = encrypt_message(public_key, message)

        signature = ecdsa_signature(private_key, message)

        encrypted_and_sign_message_with_tags = add_encrypt_and_sign_tags(random_int_on_curve,signature, encrypted_message)

        return encrypted_and_sign_message_with_tags


    @staticmethod
    def decrypt(private_key:tuple, encrypted_message:str):

        decrypted_message = rsa_with_encryption.decrypt_message(private_key, encrypted_message)

        return decrypted_message

    @staticmethod
    def verify_signature(public_key:tuple, signed_message:str):

        signature , message = extract_message_and_signature(signed_message)

        x, i = verification_signature(public_key,signature,message)

        if x == i:
            return True , message
        else:
            return False , message

    @staticmethod
    def decrypt_and_verify_signature(private_key:int,public_key:tuple, encrypted_message:str):

        decrypted_message = decrypt_message(private_key, encrypted_message)

        decrypted_message = decrypted_message.decode('utf-8')

        signature = extract_signature(encrypted_message)

        x, i = verification_signature(public_key, signature, decrypted_message)

        if x == i:
            return True , decrypted_message
        else:
            return False , decrypted_message