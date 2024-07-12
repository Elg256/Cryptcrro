# Cryptcrro
A cryptography librairie 

This librairie provide ecdsa signature, ecies encryption (using AES from the cryptography librairie for symetric encryption) using Secp256k1 curve. The librairie also provide a symmetric encryption that I call sha256_CTR it is basically a CTR encyprtion mode but using Sha256 instead of AES. (I know it seems weird, but if you are perplexed about encryption with a hashing function pls check the code)
It is the librairie used both in CrroChat and in CrroCoin and will be use in the Crro software at the end.





For using It here a little example:

#import
from cryptcrro.asymetric import crro

#generate keys
private_key = crro.generate_private_key()
public_key = crro.generate_public_key(private_key)

#message
message = "Chancellor on brink of second bailout for banks"

#encryption
encrypted_message = crro.encrypt(public_key, message)
print(encrypted_message)

#decryption
decrypt_message = crro.decrypt(private_key, encrypted_message)
print(decrypt_message.decode())
