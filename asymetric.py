from cryptcrro import ecies
from cryptcrro import rsa as crro_rsa
from cryptcrro.utility import insert_newlines_with_tags ,add_encrypt_and_sign_tags_rsa, add_sign_tags , add_encrypt_tags_ecc,add_encrypt_tags_rsa,extract_message_and_signature_rsa, add_encrypt_and_sign_tags, extract_message_and_signature,extract_signature,add_sign_tags_rsa
import base64
import hashlib
import rust_cryptcrro

class crro:

    @staticmethod
    def generate_private_key() -> int:
        return rust_cryptcrro.generate_private_key()

    @staticmethod
    def generate_public_key(private_key:int) ->  tuple[int, int]:
        return rust_cryptcrro.generate_public_key(private_key)

    @staticmethod
    def encrypt(public_key:tuple, message:bytes) -> str:
        random_int_on_curve, encrypted_message = ecies.encrypt_message(public_key, message)
        encrypted_message_with_tags = add_encrypt_tags_ecc(random_int_on_curve, encrypted_message)
        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key:int, message:bytes) -> str:

        int_hash_msg = int(hashlib.sha256(message.strip()).hexdigest(), 16)
        signature = rust_cryptcrro.create_ecdsa_sig(private_key ,int_hash_msg)
        signed_message = add_sign_tags(signature,message)

        return signed_message

    @staticmethod
    def sign_and_encrypt(private_key:int, public_key:tuple, message:bytes) -> str:

        int_hash_msg = int(hashlib.sha256(message.strip()).hexdigest(), 16)
        
        signature = rust_cryptcrro.create_ecdsa_sig(private_key, int_hash_msg)
        
        signed_message = add_sign_tags(signature, message.strip())
        
        random_int_on_curve, encrypted_and_sign_message = ecies.encrypt_message(public_key,
                                                                                                 signed_message.encode())

        encrypted_and_sign_message_with_tags = add_encrypt_tags_ecc(random_int_on_curve,
                                                                    encrypted_and_sign_message).replace(
            "---BEGIN CRRO MESSAGE---", "---BEGIN SIGNED CRRO MESSAGE---")
        return encrypted_and_sign_message_with_tags

    @staticmethod
    def decrypt_and_check_signature(private_key: int, public_key: tuple, encrypted_message:str) -> tuple[bool,str]:

        decrypted_message = ecies.decrypt_message(private_key, encrypted_message)
        signature, message = extract_message_and_signature(decrypted_message.decode())

        int_hash_msg = int(hashlib.sha256(message.encode().strip()).hexdigest(), 16)

        i = rust_cryptcrro.check_sig(public_key, signature, int_hash_msg)

        if signature[0] == i:
            return True, message
        else:
            return False, message

    @staticmethod
    def decrypt(private_key:int, encrypted_message:str) -> bytes:

        decrypted_message = ecies.decrypt_message(private_key, encrypted_message)

        return decrypted_message

    @staticmethod
    def check_signature(public_key:tuple, signed_message:str):

        signature, message = extract_message_and_signature(signed_message)

        int_hash_msg = int(hashlib.sha256(message.encode().strip()).hexdigest(), 16)

        i = rust_cryptcrro.check_sig(public_key, signature, int_hash_msg)

        if signature[0] == i:
            return True , message
        else:
            return False , message

class rsa:

    @staticmethod
    def generate_keys(size=2048) -> tuple[tuple[int,int], tuple[int,int]]:
        private_key, public_key = crro_rsa.generate_keys(size)
        return private_key , public_key

    @staticmethod
    def encrypt(public_key:tuple, message:bytes) -> str:

        encrypted_key, encrypted_message = crro_rsa.encrypt_message(public_key, message)

        encrypted_message_with_tags = add_encrypt_tags_rsa(encrypted_key, encrypted_message)

        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key:int, message:bytes) -> str:

        signature = crro_rsa.sign(private_key ,message.strip())

        signed_message = add_sign_tags_rsa(signature,message)

        return signed_message

    @staticmethod
    def sign_and_encrypt(private_key:int, public_key:tuple, message:bytes) -> str:
        signature = crro_rsa.sign(private_key, message.strip())
        signed_message = add_sign_tags_rsa(signature, message.strip())

        encrypted_key, encrypted_message = crro_rsa.encrypt_message(public_key, signed_message.encode())
        encrypted_and_sign_message_with_tags = add_encrypt_tags_rsa(encrypted_key, encrypted_message)

        return encrypted_and_sign_message_with_tags


    @staticmethod
    def decrypt(private_key:tuple, encrypted_message:str) -> bytes:

        decrypted_message = crro_rsa.decrypt_message(private_key, encrypted_message)

        return decrypted_message

    @staticmethod
    def check_signature(public_key:tuple, signed_message:str) -> tuple[bool,str]:

        signature, message = extract_message_and_signature_rsa(signed_message.strip())

        is_true = crro_rsa.check_sig(public_key,signature,message)

        return is_true, message

    @staticmethod
    def decrypt_and_check_signature(private_key:int,public_key:tuple, encrypted_message:str) -> tuple[bool,str]:

        signed_message = crro_rsa.decrypt_message(private_key, encrypted_message).decode()

        signature, message = extract_message_and_signature_rsa(signed_message)

        is_true = crro_rsa.check_sig(public_key,signature,message)

        return is_true, message