from cryptcrro import ecies_with_encrypt_new
from cryptcrro import rsa_with_encryption
from cryptcrro.ecdsa import ecdsa_signature , verification_signature
from cryptcrro.utility import insert_newlines_with_tags ,add_encrypt_and_sign_tags_rsa, add_sign_tags , add_encrypt_tags_ecc,add_encrypt_tags_rsa,extract_message_and_signature_rsa, add_encrypt_and_sign_tags, extract_message_and_signature,extract_signature,add_sign_tags_rsa
import base64

class crro:

    @staticmethod
    def generate_private_key() -> int:
        private_key = ecies_with_encrypt_new.generate_private_key()

        return private_key

    @staticmethod
    def generate_public_key(private_key:int) ->  tuple[int, int]:
        public_key = ecies_with_encrypt_new.generate_public_key(private_key)

        return public_key

    @staticmethod
    def encrypt(public_key:tuple, message:bytes) -> str:

        random_int_on_curve, encrypted_message = ecies_with_encrypt_new.encrypt_message(public_key, message)

        encrypted_message_with_tags = add_encrypt_tags_ecc(random_int_on_curve, encrypted_message)

        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key:int, message:bytes) -> str:

        signature = ecdsa_signature(private_key ,message.strip())

        signed_message = add_sign_tags(signature,message)

        return signed_message

    @staticmethod
    def sign_and_encrypt(private_key:int, public_key:tuple, message:bytes) -> str:

        signature = ecdsa_signature(private_key, message.strip())

        signed_message = add_sign_tags(signature, message.strip())

        random_int_on_curve, encrypted_and_sign_message = ecies_with_encrypt_new.encrypt_message(public_key,
                                                                                                 signed_message.encode())

        encrypted_and_sign_message_with_tags = add_encrypt_tags_ecc(random_int_on_curve,
                                                                    encrypted_and_sign_message).replace(
            "---BEGIN CRRO MESSAGE---", "---BEGIN SIGNED CRRO MESSAGE---")
        return encrypted_and_sign_message_with_tags

    @staticmethod
    def decrypt_and_verify_signature(private_key: int, public_key: tuple, encrypted_message:str) -> tuple[bool,str]:

        decrypted_message = ecies_with_encrypt_new.decrypt_message(private_key, encrypted_message)
        signature, message = extract_message_and_signature(decrypted_message.decode())

        x, i = verification_signature(public_key, signature, message)

        if x == i:
            return True, message
        else:
            return False, message

    @staticmethod
    def decrypt(private_key:int, encrypted_message:str) -> bytes:

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
    def generate_keys(size=2048) -> tuple[tuple[int,int], tuple[int,int]]:
        private_key, public_key = rsa_with_encryption.generate_keys(size)
        return private_key , public_key

    @staticmethod
    def encrypt(public_key:tuple, message:bytes) -> str:

        encrypted_key, encrypted_message = rsa_with_encryption.encrypt_message(public_key, message)

        encrypted_message_with_tags = add_encrypt_tags_rsa(encrypted_key, encrypted_message)

        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key:int, message:bytes) -> str:

        signature = rsa_with_encryption.sign(private_key ,message.strip())

        signed_message = add_sign_tags_rsa(signature,message)

        return signed_message

    @staticmethod
    def sign_and_encrypt(private_key:int, public_key:tuple, message:bytes) -> str:
        signature = rsa_with_encryption.sign(private_key, message.strip())
        signed_message = add_sign_tags_rsa(signature, message.strip())

        encrypted_key, encrypted_message = rsa_with_encryption.encrypt_message(public_key, signed_message.encode())
        encrypted_and_sign_message_with_tags = add_encrypt_tags_rsa(encrypted_key, encrypted_message)

        return encrypted_and_sign_message_with_tags


    @staticmethod
    def decrypt(private_key:tuple, encrypted_message:str) -> str:

        decrypted_message = rsa_with_encryption.decrypt_message(private_key, encrypted_message)

        return decrypted_message

    @staticmethod
    def verify_signature(public_key:tuple, signed_message:str) -> tuple[bool,str]:

        signature, message = extract_message_and_signature_rsa(signed_message.strip())

        is_true = rsa_with_encryption.check_sig(public_key,signature,message)

        return is_true, message

    @staticmethod
    def decrypt_and_verify_signature(private_key:int,public_key:tuple, encrypted_message:str) -> tuple[bool,str]:

        signed_message = rsa_with_encryption.decrypt_message(private_key, encrypted_message).decode()

        signature, message = extract_message_and_signature_rsa(signed_message)

        is_true = rsa_with_encryption.check_sig(public_key,signature,message)

        return is_true, message