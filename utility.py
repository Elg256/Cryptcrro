import base64


def insert_newlines_with_tags(s, every):
    parts = s.split('\n') 
    new_parts = []

    for part in parts:
        if part.startswith('---') and part.endswith('---'):
            new_parts.append(part)  
        else:
            new_parts.extend([part[i:i + every] for i in range(0, len(part), every)])

    return '\n'.join(new_parts)

def add_sign_tags_old(signature,message):

    signature = ''.join(str(signature)).encode("utf-8")

    signature_base64 = base64.urlsafe_b64encode(signature).decode("utf-8")

    signature = f"---Start Signature---\n{signature_base64}\n---End Signature---"

    signature_with_tags = insert_newlines_with_tags(signature, 64)

    signed_message = f"---BEGIN SIGNED CRRO MESSAGE---\n{message}\n{signature_with_tags}\n---END SIGNED CRRO MESSAGE---"

    return signed_message

def add_sign_tags(signature, message):
    r, s = signature

    r_bytes = r.to_bytes(32, byteorder='big')
    s_bytes = s.to_bytes(32, byteorder='big')
    signature_bytes = r_bytes + s_bytes

    signature_base64 = base64.urlsafe_b64encode(signature_bytes).decode('utf-8')
    signature = f"---Start Signature---\n{signature_base64}\n---End Signature---"
    signature_with_tags = insert_newlines_with_tags(signature, 64)
    signed_message = f"---BEGIN SIGNED CRRO MESSAGE---\n{message.decode()}\n{signature_with_tags}\n---END SIGNED CRRO MESSAGE---"
    return signed_message

def add_sign_tags_rsa(signature:str, message:bytes):

    signature = f"---Start Signature---\n{signature}\n---End Signature---"
    signature_with_tags = insert_newlines_with_tags(signature, 64)
    signed_message = f"---BEGIN SIGNED CRRO MESSAGE---\n{message.decode()}\n{signature_with_tags}\n---END SIGNED CRRO MESSAGE---"
    return signed_message

def add_encrypt_tags_old(random_int_on_curve, encrypted_message):

    random_int_on_curve = ''.join(str(random_int_on_curve)).encode('utf-8')

    random_int_on_curve = base64.urlsafe_b64encode(random_int_on_curve).decode('utf-8')

    encrypted_message = encrypted_message.decode('utf-8')

    encrypted_message = f"---BEGIN CURVE INT---\n{random_int_on_curve}\n---END CURVE INT---\n{encrypted_message}"

    encrypted_message = insert_newlines_with_tags(encrypted_message,
                                                  64)
    encrypted_message_with_tags = f"---BEGIN CRRO MESSAGE---\n{encrypted_message}\n---END CRRO MESSAGE---"

    return encrypted_message_with_tags

def add_encrypt_tags_ecc(random_int_on_curve, encrypted_message):

    x, y = random_int_on_curve

    x_bytes = x.to_bytes(32, byteorder='big')
    y_bytes = y.to_bytes(32, byteorder='big')
    signature_bytes = x_bytes + y_bytes

    random_int_on_curve = base64.urlsafe_b64encode(signature_bytes).decode('utf-8')

    encrypted_message = base64.urlsafe_b64encode(encrypted_message).decode()

    encrypted_message = f"---BEGIN CURVE INT---\n{random_int_on_curve}\n---END CURVE INT---\n{encrypted_message}"

    encrypted_message = insert_newlines_with_tags(encrypted_message,
                                                  64)
    encrypted_message_with_tags = f"---BEGIN CRRO MESSAGE---\n{encrypted_message}\n---END CRRO MESSAGE---"

    return encrypted_message_with_tags

def add_encrypt_tags_rsa(encrypted_symetric_key:int, encrypted_message):
    encrypted_message = encrypted_message.decode('utf-8')

    encrypted_message = f"---Start AES key---\n{encrypted_symetric_key}\n---End AES key---\n{encrypted_message}"

    encrypted_message = insert_newlines_with_tags(encrypted_message,
                                                  64)
    encrypted_message_with_tags = f"---BEGIN CRRO MESSAGE---\n{encrypted_message}\n---END CRRO MESSAGE---"

    return encrypted_message_with_tags


def add_encrypt_and_sign_tags(random_int_on_curve,signature, encrypted_message):

    random_int_on_curve = ''.join(str(random_int_on_curve)).encode('utf-8')

    random_int_on_curve = base64.urlsafe_b64encode(random_int_on_curve).decode('utf-8')

    encrypted_message = encrypted_message.decode('utf-8')

    signature = ''.join(str(signature)).encode("utf-8")

    signature_base64 = base64.urlsafe_b64encode(signature).decode("utf-8")


    encrypted_message_with_tags = f"---Start Signature---\n{signature_base64}\n---End Signature---\n" \
                     f"---BEGIN CURVE INT---\n{random_int_on_curve}\n---END CURVE INT---\n{encrypted_message}"

    encrypted_message_with_tags = f"---BEGIN CRRO MESSAGE---\n{encrypted_message_with_tags}\n---END CRRO MESSAGE---"

    encrypted_message_with_tags = insert_newlines_with_tags(encrypted_message_with_tags, 64)

    return encrypted_message_with_tags

def add_encrypt_and_sign_tags_rsa(encrypted_key, signature, encrypted_message):
    encrypted_message = encrypted_message.decode('utf-8')

    encrypted_message_with_tags = f"---Start Signature---\n{signature}\n---End Signature---\n" \
                     f"---Start AES key---\n{encrypted_key}\n---End AES key---\n{encrypted_message}"

    encrypted_message_with_tags = f"---BEGIN CRRO MESSAGE---\n{encrypted_message_with_tags}\n---END CRRO MESSAGE---"

    encrypted_message_with_tags = insert_newlines_with_tags(encrypted_message_with_tags, 64)

    return encrypted_message_with_tags


def extract_signature(message):

    start_marker = "---Start Signature---"
    end_marker = "---End Signature---"
    if start_marker in message and end_marker in message:
        start_index = message.index(start_marker) + len(start_marker)
        end_index = message.index(end_marker)
        cle_sign = message[start_index:end_index].strip()

    signature = base64.urlsafe_b64decode(cle_sign)

    signature_x = int.from_bytes(signature[:32])

    signature_y = int.from_bytes(signature[32:])

    signature = signature_x, signature_y

    return signature

def extract_message_and_signature(signed_message):

    start_marker = "---BEGIN SIGNED CRRO MESSAGE---"
    end_marker = "---Start Signature---"
    if start_marker in signed_message and end_marker in signed_message:
        start_index = signed_message.index(start_marker) + len(start_marker)
        end_index = signed_message.index(end_marker)
        message = signed_message[start_index:end_index].strip()

    start_marker = "---Start Signature---"
    end_marker = "---End Signature---"

    start_index = signed_message.index(start_marker) + len(start_marker)
    end_index = signed_message.index(end_marker)
    cle_sign = signed_message[start_index:end_index].strip()
    cle_sign = cle_sign.replace(" ", "").replace("\n", "")

    signature = base64.urlsafe_b64decode(cle_sign)

    signature_x = int.from_bytes(signature[:32])

    signature_y = int.from_bytes(signature[32:])

    signature = signature_x, signature_y

    return signature, message

def extract_message_and_signature_rsa(signed_message):

    start_marker = "---BEGIN SIGNED CRRO MESSAGE---"
    end_marker = "---Start Signature---"
    if start_marker in signed_message and end_marker in signed_message:
        start_index = signed_message.index(start_marker) + len(start_marker)
        end_index = signed_message.index(end_marker)
        message = signed_message[start_index:end_index].strip()

    start_marker = "---Start Signature---"
    end_marker = "---End Signature---"

    start_index = signed_message.index(start_marker) + len(start_marker)
    end_index = signed_message.index(end_marker)
    cle_sign = signed_message[start_index:end_index].strip()
    signature = cle_sign.replace(" ", "").replace("\n", "")

    return signature, message

def extract_message_and_signature_old(signed_message):

    start_marker = "---BEGIN SIGNED CRRO MESSAGE---"
    end_marker = "---Start Signature---"
    if start_marker in signed_message and end_marker in signed_message:
        start_index = signed_message.index(start_marker) + len(start_marker)
        end_index = signed_message.index(end_marker)
        message = signed_message[start_index:end_index].strip()

    start_marker = "---Start Signature---"
    end_marker = "---End Signature---"

    start_index = signed_message.index(start_marker) + len(start_marker)
    end_index = signed_message.index(end_marker)
    cle_sign = signed_message[start_index:end_index].strip()
    cle_sign = cle_sign.replace(" ", "").replace("\n", "")

    signature = base64.urlsafe_b64decode(cle_sign).decode('utf-8').replace(" ", "")

    signature = signature.replace(" ", "").replace("(", "").replace(")", "").split(",")

    signature = tuple(int(signature) for signature in signature)

    return signature, message


def int_to_base32(num):
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    if num == 0:
        return alphabet[0]
    base32 = []
    while num:
        num, rem = divmod(num, 32)
        base32.append(alphabet[rem])
    base32.reverse()
    return ''.join(base32)

def int_to_base58(num):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if num == 0:
        return alphabet[0]
    base58 = []
    while num:
        num, rem = divmod(num, 58)
        base58.append(alphabet[rem])
    base58.reverse()
    return ''.join(base58)


def base58_to_int(base58_str):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base58_map = {char: index for index, char in enumerate(alphabet)}
    num = 0
    for char in base58_str:
        num = num * 58 + base58_map[char]
    return num

def base32_to_int(base32_str):
    alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    base32_map = {char: index for index, char in enumerate(alphabet)}
    num = 0
    for char in base32_str:
        num = num * 32 + base32_map[char]
    return num

def make_base58_addr(pubkey):
    x, y = pubkey

    addr58 = int_to_base58(x)

    if y % 2 == 0:
        addr58 = "tc2" + addr58

    else:
        addr58 = "tc3" + addr58

    return addr58

def make_base32_addr(pubkey:tuple):
    x, y = pubkey

    addr32 = int_to_base32(x)

    if y % 2 == 0:
        addr32 = "tc2" + addr32

    else:
        addr32 = "tc3" + addr32

    return addr32


def uncompress_base58_public_key(compressed_key):
    from cryptcrro.secp256k1 import p
    if compressed_key.startswith("tc2"):

        compressed_key_without_prefix = compressed_key[3:]

        compressed_key_without_prefix = base58_to_int(compressed_key_without_prefix)

        y_square = (pow(compressed_key_without_prefix, 3, p) + 7) % p

        y = pow(y_square, (p + 1) // 4, p)

        y = p - y

    if compressed_key.startswith("tc3"):

        compressed_key_without_prefix = compressed_key[3:]

        y_square = (pow(compressed_key_without_prefix, 3, p) + 7) % p

        y = pow(y_square, (p + 1) // 4, p)

    x = compressed_key_without_prefix

    public_key = f"{x},{y}"

    return public_key

def uncompress_base32_public_key(compressed_key):
    from cryptcrro.secp256k1 import p
    if compressed_key.startswith("tc2"):

        compressed_key_without_prefix = compressed_key[3:]

        compressed_key_without_prefix = base32_to_int(compressed_key_without_prefix)

        y_square = (pow(compressed_key_without_prefix, 3, p) + 7) % p

        y = pow(y_square, (p + 1) // 4, p)

        y = p - y

    if compressed_key.startswith("tc3"):

        compressed_key_without_prefix = compressed_key[3:]

        compressed_key_without_prefix = base32_to_int(compressed_key_without_prefix)

        y_square = (pow(compressed_key_without_prefix, 3, p) + 7) % p

        y = pow(y_square, (p + 1) // 4, p)

    x = compressed_key_without_prefix

    public_key = f"{x},{y}"

    return public_key
