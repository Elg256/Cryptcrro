from cryptcrro.ecies_with_encrypt_new import encrypt_message, decrypt_message , generate_private_key , generate_public_key
from cryptcrro.ecdsa import ecdsa_signature , verification_signature
from cryptcrro.utility import insert_newlines_with_tags , add_sign_tags , add_encrypt_tags, add_encrypt_and_sign_tags, extract_message_and_signature,extract_signature
import base64

class crro:

    @staticmethod
    def generate_private_key():
        private_key = generate_private_key()

        return private_key

    @staticmethod
    def generate_public_key(private_key):
        public_key = generate_public_key(private_key)

        return public_key

    @staticmethod
    def encrypt(public_key, message):


        random_int_on_curve, encrypted_message = encrypt_message(public_key, message)

        encrypted_message_with_tags = add_encrypt_tags(random_int_on_curve, encrypted_message)


        return encrypted_message_with_tags

    @staticmethod
    def sign(private_key, message):


        signature = ecdsa_signature(private_key ,message)

        signed_message = add_sign_tags(signature,message)

        return signed_message

    @staticmethod
    def encrypt_and_sign(private_key, public_key, message):


        random_int_on_curve, encrypted_message = encrypt_message(public_key, message)

        signature = ecdsa_signature(private_key, message)

        encrypted_and_sign_message_with_tags = add_encrypt_and_sign_tags(random_int_on_curve,signature, encrypted_message)

        return encrypted_and_sign_message_with_tags


    @staticmethod
    def decrypt(private_key:int, encrypted_message:str):


        decrypted_message = decrypt_message(private_key, encrypted_message)

        return decrypted_message

    @staticmethod
    def verify_signature(public_key, signed_message):


        signature , message = extract_message_and_signature(signed_message)

        x, i = verification_signature(public_key,signature,message)



        if x == i:
            return True , message
        else:
            return False , message



    @staticmethod
    def decrypt_and_verify_signature(private_key,public_key, encrypted_message):


        decrypted_message = decrypt_message(private_key, encrypted_message)

        decrypted_message = decrypted_message.decode('utf-8')


        signature = extract_signature(encrypted_message)


        x, i = verification_signature(public_key, signature, decrypted_message)

        if x == i:
            return True , decrypted_message
        else:
            return False , decrypted_message
