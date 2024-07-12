import hashlib
import os
import base64

def generate_key():
    return base64.urlsafe_b64encode(os.urandom(32))

def xor_bytes(a, b):
    return bytes(i^j for i, j in zip(a, b))

def padding(message):

    padding_len = 32 - len(message) % 32

    if padding_len == 0:
        padding_len = 32

    padding = bytes([padding_len] * padding_len)

    #print("padding_len",padding_len)

    #print("message + padding",message + padding)

    return message + padding

def unpadding(message):

    #print("len(message)",len(message))

    # Lire le dernier octet pour obtenir la longueur du padding
    padding_len = message[-1]

    #print("unpadding_len",padding_len)

    unpadded_message, padding = message[:-padding_len], message[-padding_len:]

    # Supprimer le padding du message
    #unpadded_message = message[:-padding_len]

    #print("unpadded_message",unpadded_message)

    return unpadded_message


def pad(plaintext):
    """"
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """

    padding_len = 32 - (len(plaintext) % 32)
    padding = bytes([padding_len] * padding_len)

    #print("plaintext",plaintext)

    #print("padding",padding)

    return plaintext + padding



def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """

    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message


def split_bytes_into_blocks(message_bytes, block_size=32):
    """
    Divise une chaîne d'octets en blocs de la taille spécifiée.

    Args:
        message_bytes (bytes): La chaîne d'octets à diviser en blocs.
        block_size (int): La taille de chaque bloc en octets. Par défaut, 32 octets.

    Returns:
        list: Une liste de blocs de bytes.
    """
    message_blocks = []
    for i in range(0, len(message_bytes), block_size):
        message_blocks.append(message_bytes[i:i + block_size])
        #print("split_bytes_into_blocks",message_blocks)
    return message_blocks


def split_message_simple(message):

    block_size = 32  # 256 bits (32 octets)
    message_blocks = []
    for i in range(0, len(message), block_size):
        message_blocks.append(message[i:i+block_size])
        #print(i)

    #print("message_blocks",message_blocks)

    return message_blocks


def encrypt(key, message:bytes):

    padded_message = padding(message)

    #print("padded_message",padded_message)

    padded_message_block = split_message_simple(padded_message)

    #print("padded_message_block",padded_message_block)

    ciphertext = []

    iv = os.urandom(16)

    iv_int = int.from_bytes(iv)

    #print("iv:",iv)

    #print("padded_message_block",len(padded_message_block))

    for i in range(0,len(padded_message_block)):

        iv_with_count = iv_int + (i+1) # by using sha256 instead of aes we don't need a counter that is x bits longs

        print("iv_with_count", iv_with_count)

        iv_with_count = hex(int(iv_with_count))[2:]

        print("iv_with_count",iv_with_count )

        #print("iv_with_count", i , iv_with_count)

        #print("iv  142:",iv)

        key_and_iv = bytes.fromhex(iv_with_count) + key

        #print("key_and_iv:",key_and_iv,"\n")

        sha256 = hashlib.sha256(key_and_iv).digest()

        #print("sha256  1:", sha256,"\n")

        #print("block cipher:",sha256)

        #ciphertext_block = message_blocks[i] ^ block_cipher

        #padded_message_block = message_blocks[i] + b'\0' * (32 - len(message_blocks[i]))

        #print("padded_message_block",padded_message_block)

        ciphertext_block = xor_bytes(sha256, padded_message_block[i])

        ciphertext_block = ciphertext_block

        ciphertext.append(ciphertext_block)

        #print("ciphertext_block: ",ciphertext_block)

        #print("iv + b"".join(ciphertext)",iv + b"".join(ciphertext))

        #print(base64.urlsafe_b64encode((iv + b"---" + b"".join(ciphertext))))

    return base64.urlsafe_b64encode((iv + b"---" + b"".join(ciphertext)))

def encrypt_without_padding(key, message:bytes):

    padded_message_block = split_bytes_into_blocks(message)

    #print("padded_message_block",padded_message_block)

    ciphertext = []

    iv = os.urandom(16)

    iv_int = int.from_bytes(iv)

    for i in range(0,len(padded_message_block)):

        iv_with_count = iv_int + (i + 1)  # by using sha256 instead of aes we don't need a counter that is x bits longs
        iv_with_count = hex(int(iv_with_count))[2:]
        key_and_iv = bytes.fromhex(iv_with_count) + key

        sha256 = hashlib.sha256(key_and_iv).digest()
        ciphertext_block = xor_bytes(sha256, padded_message_block[i])
        ciphertext_block = ciphertext_block
        ciphertext.append(ciphertext_block)

    return base64.urlsafe_b64encode((iv + b"---" + b"".join(ciphertext)))

def decrypt(key, message: bytes):


    #print("message in bytes",message)

    message = message.split(b"---")

    #print("message:",message,"\n")

    #print("message divise: ",message)

    iv_int = int.from_bytes(bytes(message[0]))

    #print("iv  142:", iv)

    message = message[1]

    #print("lenght message",len(message))

    #print("iv3:" ,iv)

    message_blocks = split_message_simple(message)

    #print("message_blocks",message_blocks)

    ciphertext = []

    #print("message_blocks",len(message_blocks))

    for i in range(0, len(message_blocks)):
        iv_with_count = iv_int + (i + 1)  # by using sha256 instead of aes we don't need a counter that is x bits longs

        print("iv_with_count", iv_with_count)

        iv_with_count = hex(int(iv_with_count))[2:]

        print("iv_with_count", iv_with_count)

        # print("iv_with_count", i , iv_with_count)

        # print("iv  142:",iv)

        key_and_iv = bytes.fromhex(iv_with_count) + key

        #print("key_and_iv:", key_and_iv,"\n")

        sha256 = hashlib.sha256(key_and_iv).digest()

        #print("block cipher:", sha256)

        # ciphertext_block = message_blocks[i] ^ block_cipher

        # padded_message_block = message_blocks[i] + b'\0' * (32 - len(message_blocks[i]))

        #padded_message_block = pad(message_blocks[i])

        #print("padded_message_block", padded_message_block)

        ciphertext_block = xor_bytes(bytes(sha256), message_blocks[i])

        #print("ciphertext_block",i,ciphertext_block)

        #print("sha256  2:",sha256,"\n")

        ciphertext_block = ciphertext_block

        ciphertext.append(ciphertext_block)

        #print("ciphertext_block",ciphertext_block)

        #ciphertext = unpad(b''.join(ciphertext))

    #print("ciphertext", ciphertext)

    last_block = ciphertext.pop()

    #print("last_block pop",last_block)

    last_block = unpadding(last_block)

    #print("last_block",last_block)


    ciphertext.append(last_block)

    #print("ciphertext",ciphertext)


    return b''.join(ciphertext)


def decrypt_without_padding(key, message:bytes):

    #print("message in bytes", message)

    message = message.split(b"---")

    #print("message:",message,"\n")

    # print("message divise: ",message)

    iv_int = int.from_bytes(bytes(message[0]))

    # print("iv  142:", iv)

    message = message[1]

    #print("lenght message", len(message))

    # print("iv3:" ,iv)

    message_blocks = split_message_simple(message)

    #print("message_blocks", message_blocks)

    ciphertext = []

    # print(len(message_blocks))

    for i in range(0, len(message_blocks)):
        iv_with_count = iv_int + (i + 1)  # by using sha256 instead of aes we don't need a counter that is x bits longs

        print("iv_with_count", iv_with_count)

        iv_with_count = hex(int(iv_with_count))[2:]

        print("iv_with_count", iv_with_count)

        key_and_iv = bytes.fromhex(iv_with_count) + key

        # print("key_and_iv:", key_and_iv,"\n")

        sha256 = hashlib.sha256(key_and_iv).digest()

        # print("block cipher:", sha256)

        # ciphertext_block = message_blocks[i] ^ block_cipher

        # padded_message_block = message_blocks[i] + b'\0' * (32 - len(message_blocks[i]))

        # padded_message_block = pad(message_blocks[i])

        # print("padded_message_block", padded_message_block)

        ciphertext_block = xor_bytes(bytes(sha256), message_blocks[i])

        #print("ciphertext_block", i, ciphertext_block)

        # print("sha256  2:",sha256,"\n")

        ciphertext_block = ciphertext_block

        ciphertext.append(ciphertext_block)

        # print("ciphertext_block",ciphertext_block)

        # ciphertext = unpad(b''.join(ciphertext))

    #print("ciphertext", ciphertext)


    #print("ciphertext", ciphertext)

    return b''.join(ciphertext)


'''
#message = "hello world!".encode()

message = "hello world                   jkqhntuisretv vstuieryntver vteruyvnu !".encode()

print(message)

key = "58641736236".encode()

iv = b'SnGoGQlofqh9tjQD06FnGr2OUjJjSoEUGekKVQCIYqo='

iv = base64.urlsafe_b64decode(iv)

print("iv: ",iv )

cipher = encrypt(message , key)

print("ciphertext:",cipher)

print("decrypted message: ", decrypt(cipher , key , iv))

print("decrypted message utf: ", decrypt(cipher , key , iv))

print(cipher)

print(b'e5613036b9d6b98d0ad4ca6128c83314'.decode())

'''








