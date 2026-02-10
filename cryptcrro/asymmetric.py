from cryptcrro import ecies
from cryptcrro import rsa as crro_rsa
from cryptcrro.utility import insert_newlines_with_tags ,add_encrypt_and_sign_tags_rsa, add_sign_tags , add_encrypt_tags_ecc,add_encrypt_tags_rsa,extract_message_and_signature_rsa, add_encrypt_and_sign_tags, extract_message_and_signature,extract_signature,add_sign_tags_rsa
import base64
import hashlib
from cryptcrro import _rust

class crro:

    @staticmethod
    def generate_private_key() -> int:
        return _rust.generate_private_key()

    @staticmethod
    def generate_public_key(private_key:int) ->  tuple[int, int]:
        return _rust.generate_public_key(private_key)

    @staticmethod
    def encrypt(public_key:tuple, message:bytes) -> str:
        if isinstance(message, str):
            message = message.encode()
        assert isinstance(public_key, tuple), f"CRRO public key need to be tuple[int, int] not {type(public_key).__name__}"
        assert isinstance(message, bytes), f"Plaintext need to be bytes or str not {type(message).__name__}"

        random_int_on_curve, encrypted_message = ecies.encrypt_message(public_key, message)
        encrypted_message_with_tags = add_encrypt_tags_ecc(random_int_on_curve, encrypted_message)
        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key:int, message:bytes) -> str:
        if isinstance(message, str):
            message = message.encode()
        assert isinstance(message, bytes), f"Message need to be bytes or str not {type(message).__name__}"
        assert isinstance(private_key, int), f"Private key  need to be int not {type(private_key).__name__}"
        
        int_hash_msg = int(hashlib.sha256(message.strip()).hexdigest(), 16)
        signature = _rust.create_ecdsa_sig(private_key ,int_hash_msg)
        signed_message = add_sign_tags(signature,message)

        return signed_message

    @staticmethod
    def sign_and_encrypt(private_key:int, public_key:tuple, message:bytes) -> str:
        if isinstance(message, str):
            message = message.encode()
        assert isinstance(public_key, tuple), f"CRRO public key need to be tuple[int, int] not {type(public_key).__name__}"
        assert isinstance(message, bytes), f"Plaintext need to be bytes or str not {type(message).__name__}"
        assert isinstance(private_key, int), f"Private key  need to be int not {type(private_key).__name__}"

        int_hash_msg = int(hashlib.sha256(message.strip()).hexdigest(), 16)
        
        signature = _rust.create_ecdsa_sig(private_key, int_hash_msg)
        
        signed_message = add_sign_tags(signature, message.strip())
        
        random_int_on_curve, encrypted_and_sign_message = ecies.encrypt_message(public_key,
                                                                                                 signed_message.encode())

        encrypted_and_sign_message_with_tags = add_encrypt_tags_ecc(random_int_on_curve,
                                                                    encrypted_and_sign_message).replace(
            "---BEGIN CRRO MESSAGE---", "---BEGIN SIGNED CRRO MESSAGE---")
        return encrypted_and_sign_message_with_tags

    @staticmethod
    def decrypt_and_check_signature(private_key: int, public_key: tuple, encrypted_message:str) -> tuple[bool,str]:
        if isinstance(encrypted_message, bytes):
            encrypted_message = encrypted_message.decode()
        assert isinstance(public_key, tuple), f"CRRO public key need to be tuple[int, int] not {type(public_key).__name__}"
        assert isinstance(encrypted_message, str), f"Ciphertext need to be bytes or str not {type(encrypted_message).__name__}"
        assert isinstance(private_key, int), f"Private key  need to be int not {type(private_key).__name__}"

        decrypted_message = ecies.decrypt_message(private_key, encrypted_message)
        signature, message = extract_message_and_signature(decrypted_message.decode())

        int_hash_msg = int(hashlib.sha256(message.encode().strip()).hexdigest(), 16)

        i = _rust.check_sig(public_key, signature, int_hash_msg)

        if signature[0] == i:
            return True, message
        else:
            return False, message

    @staticmethod
    def decrypt(private_key:int, encrypted_message:str) -> bytes:
        if isinstance(encrypted_message, bytes):
            encrypted_message = encrypted_message.decode()
        assert isinstance(encrypted_message, str), f"Ciphertext need to be bytes or str not {type(encrypted_message).__name__}"
        assert isinstance(private_key, int), f"Private key  need to be int not {type(private_keyy).__name__}"

        decrypted_message = ecies.decrypt_message(private_key, encrypted_message)

        return decrypted_message

    @staticmethod
    def check_signature(public_key:tuple, signed_message:str):
        if isinstance(signed_message, bytes):
            signed_message = signed_message.decode()
        assert isinstance(public_key, tuple), f"CRRO public key need to be tuple[int, int] not {type(public_key).__name__}"
        assert isinstance(signed_message, str), f"Signed_message need to be bytes or str not {type(signed_message).__name__}"

        signature, message = extract_message_and_signature(signed_message)

        int_hash_msg = int(hashlib.sha256(message.encode().strip()).hexdigest(), 16)

        i = _rust.check_sig(public_key, signature, int_hash_msg)

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
        if isinstance(message, str):
            message = message.encode()
        assert isinstance(public_key,
                          tuple), f"CRRO public key need to be tuple[int, int] not {type(public_key).__name__}"
        assert isinstance(message, bytes), f"Plaintext need to be bytes or str not {type(message).__name__}"

        encrypted_key, encrypted_message = crro_rsa.encrypt_message(public_key, message)

        encrypted_message_with_tags = add_encrypt_tags_rsa(encrypted_key, encrypted_message)

        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key:tuple, message:bytes) -> str:
        if isinstance(message, str):
            message = message.encode()
        assert isinstance(message, bytes), f"Message need to be bytes or str not {type(message).__name__}"
        assert isinstance(private_key, tuple), f"Rsa Private key need to be tuple[int, int] not {type(private_key).__name__}"

        signature = crro_rsa.sign(private_key ,message.strip())

        signed_message = add_sign_tags_rsa(signature,message)

        return signed_message

    @staticmethod
    def sign_and_encrypt(private_key:tuple, public_key:tuple, message:bytes) -> str:
        if isinstance(message, str):
            message = message.encode()
        assert isinstance(public_key,
                          tuple), f"CRRO public key need to be tuple[int, int] not {type(public_key).__name__}"
        assert isinstance(message, bytes), f"Plaintext need to be bytes or str not {type(message).__name__}"
        assert isinstance(private_key, tuple), f"Private key  need to be tuple[int, int] not {type(private_key).__name__}"

        signature = crro_rsa.sign(private_key, message.strip())
        signed_message = add_sign_tags_rsa(signature, message.strip())

        encrypted_key, encrypted_message = crro_rsa.encrypt_message(public_key, signed_message.encode())
        encrypted_and_sign_message_with_tags = add_encrypt_tags_rsa(encrypted_key, encrypted_message)

        return encrypted_and_sign_message_with_tags


    @staticmethod
    def decrypt(private_key:tuple, encrypted_message:str) -> bytes:
        if isinstance(encrypted_message, bytes):
            encrypted_message = encrypted_message.decode()
        assert isinstance(encrypted_message, str), f"Ciphertext need to be bytes or str not {type(encrypted_message).__name__}"
        assert isinstance(private_key, tuple), f"Private key  need to be tuple[int, int] not {type(private_keyy).__name__}"

        decrypted_message = crro_rsa.decrypt_message(private_key, encrypted_message)

        return decrypted_message

    @staticmethod
    def check_signature(public_key:tuple, signed_message:str) -> tuple[bool,str]:
        if isinstance(signed_message, bytes):
            signed_message = signed_message.decode()
        assert isinstance(public_key, tuple), f"CRRO public key need to be tuple[int, int] not {type(public_key).__name__}"
        assert isinstance(signed_message, str), f"Signed_message need to be bytes or str not {type(signed_message).__name__}"

        signature, message = extract_message_and_signature_rsa(signed_message.strip())

        is_true = crro_rsa.check_sig(public_key,signature,message)

        return is_true, message

    @staticmethod
    def decrypt_and_check_signature(private_key:int,public_key:tuple, encrypted_message:str) -> tuple[bool,str]:
        if isinstance(encrypted_message, bytes):
            encrypted_message = encrypted_message.decode()
        assert isinstance(public_key, tuple), f"CRRO public key need to be tuple[int, int] not {type(public_key).__name__}"
        assert isinstance(encrypted_message, str), f"Ciphertext need to be bytes or str not {type(encrypted_message).__name__}"
        assert isinstance(private_key, tuple), f"Private key  need to be tuple[int, int] not {type(private_key).__name__}"

        signed_message = crro_rsa.decrypt_message(private_key, encrypted_message).decode()

        signature, message = extract_message_and_signature_rsa(signed_message)

        is_true = crro_rsa.check_sig(public_key,signature,message)

        return is_true, message
