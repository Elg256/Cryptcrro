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


def parse_crro_private_block(block: bytes):
    block = block.split(b"\n")
    block = base64.urlsafe_b64decode(b"".join(block[1:-1]))
    if block.startswith(b"ECC"):
        block = block.replace(b"ECC 256 bits\n", b"")
        x = int.from_bytes(block[:32])
        y = int.from_bytes(block[32:64])
        private_key = int.from_bytes(block[64:])
        public_key = x, y
        key_type = "ECC 256 bits"
        return private_key, public_key, key_type

    elif block.startswith(b"RSA"):
        # Format: [RSA size] [size_n] [size_d] [e] [n] [d]

        key_type = block[:13].decode("utf-8")

        size_n = int.from_bytes(block[13:15], byteorder="big")
        size_d = int.from_bytes(block[15:17], byteorder="big")

        e = int.from_bytes(block[17:20], byteorder="big")
        n = int.from_bytes(block[20:20 + size_n], byteorder="big")
        d = int.from_bytes(block[20 + size_n:20 + size_n + size_d], byteorder="big")

        public_key = (e, n)
        private_key = (d, n)

        return private_key, public_key, key_type
    else:
        raise ValueError("Key Format isn't repected")


def parse_crro_public_block(block: bytes):
    block = block.split(b"\n")
    block = base64.urlsafe_b64decode(b"".join(block[1:-1]))
    if block.startswith(b"ECC"):
        block = block.replace(b"ECC 256 bits\n", b"")
        x = int.from_bytes(block[:32], byteorder="big")
        y = int.from_bytes(block[32:], byteorder="big")
        public_key = x, y
        key_type = "ECC 256 bits"
        return public_key, key_type


    elif block.startswith(b"RSA"):
        # Format: [RSA size] [size_n] [e] [n]

        key_type = str(block[:13])
        size_n = int.from_bytes(block[13:15], byteorder="big")

        e = int.from_bytes(block[15:18], byteorder="big")
        n = int.from_bytes(block[18:20 + size_n], byteorder="big")

        public_key = (e, n)

        return public_key, key_type
    else:
        raise ValueError("Key Format isn't repected")


def create_crro_block(public_key: tuple, private_key=None):
    if int(public_key[0]) == 65537: # mean a rsa public key
        if private_key:
            e, n = public_key
            e_int, n_int = int(e), int(n)
            e_bytes = int(public_key[0]).to_bytes(3, byteorder="big")
            size_n = (n_int.bit_length() + 7) // 8
            n_bytes = int(public_key[1]).to_bytes((size_n), byteorder="big")

            d, _ = private_key
            size_d = (int(d).bit_length() + 7) // 8
            d_bytes = int(private_key[0]).to_bytes(size_d, byteorder="big")

            rsa_sizes = [1024, 2048, 3072, 4096]
            rsa_bits = min(rsa_sizes, key=lambda x: abs(x - n_int.bit_length()))

            # Format: [RSA size] [size_n] [size_d] [e] [n] [d]

            header = b"RSA " + str(rsa_bits).encode() + b" bits"
            metadata = size_n.to_bytes(2, byteorder="big") + size_d.to_bytes(2, byteorder="big")

            b64_key_pair = base64.urlsafe_b64encode(header + metadata + e_bytes + n_bytes + d_bytes)

            block = b"-----BEGIN CRRO PRIVATE KEY BLOCK-----\n" + b64_key_pair + \
                    b"\n-----END CRRO PRIVATE KEY BLOCK-----"

            return insert_newlines_with_tags(block.decode(), 64).encode()

        else:
            e, n = public_key
            e_int, n_int = int(e), int(n)
            e = int(public_key[0]).to_bytes(3, byteorder="big")
            real_size_n = (n_int.bit_length() + 7) // 8
            n = int(public_key[1]).to_bytes(real_size_n, byteorder="big")

            rsa_sizes = [1024, 2048, 3072, 4096]
            rsa_bits = min(rsa_sizes, key=lambda x: abs(x - n_int.bit_length()))

            b64_key_pair = base64.urlsafe_b64encode(b"RSA " + str(rsa_bits).encode() + b" bits\nn=" +
                                                    str(real_size_n).encode() + b"bits\n" + e + n)

            block = b"-----BEGIN CRRO PUBLIC KEY BLOCK-----\n" + b64_key_pair + \
                    b"\n-----END CRRO PUBLIC KEY BLOCK-----"

            return insert_newlines_with_tags(block.decode(), 64).encode()

    else:
        if private_key:
            x, y = int(public_key[0]).to_bytes(32, byteorder="big"), int(public_key[1]).to_bytes(32, byteorder="big")
            k = int(private_key).to_bytes(32, byteorder="big")
            print(x, y)
            print(k)
            b64_key_pair = base64.urlsafe_b64encode(b"ECC 256 bits\n" + x + y + k)
            block = b"-----BEGIN CRRO PRIVATE KEY BLOCK-----\n" + b64_key_pair + \
                    b"\n-----END CRRO PRIVATE KEY BLOCK-----"

            return insert_newlines_with_tags(block.decode(), 64).encode()
        else:
            x, y = int(public_key[0]).to_bytes(32, byteorder="big"), int(public_key[1]).to_bytes(32, byteorder="big")
            b64_public_key = base64.urlsafe_b64encode(b"ECC 256 bits\n" + x + y)
            block = b"-----BEGIN CRRO PUBLIC KEY BLOCK-----\n" + b64_public_key + \
                    b"\n-----END CRRO PUBLIC KEY BLOCK-----"

            return insert_newlines_with_tags(block.decode(), 64).encode()




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
