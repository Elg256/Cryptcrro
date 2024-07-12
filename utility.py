import base64

def insert_newlines_with_tags(s, every):
    parts = s.split('\n')  # Divise le texte en lignes existantes
    new_parts = []

    for part in parts:
        if part.startswith('---') and part.endswith('---'):
            new_parts.append(part)  # Les balises sont traitées comme une ligne entière
        else:
            new_parts.extend([part[i:i + every] for i in range(0, len(part), every)])

    return '\n'.join(new_parts)

def add_sign_tags(signature,message):

    signature = ''.join(str(signature)).encode("utf-8")

    signature_base64 = base64.b64encode(signature).decode("utf-8")

    signature = f"---Start Signature---\n{signature_base64}\n---End Signature---"

    signature_with_tags = insert_newlines_with_tags(signature, 64)

    signed_message = f"---BEGIN SIGNED CRRO MESSAGE---\n{message}\n{signature_with_tags}\n---END SIGNED CRRO MESSAGE---"

    return signed_message

def add_encrypt_tags(random_int_on_curve, encrypted_message):

    random_int_on_curve = ''.join(str(random_int_on_curve)).encode('utf-8')

    random_int_on_curve = base64.b64encode(random_int_on_curve).decode('utf-8')

    encrypted_message = encrypted_message.decode('utf-8')

    encrypted_message = f"---BEGIN CURVE INT---\n{random_int_on_curve}\n---END CURVE INT---\n{encrypted_message}"

    encrypted_message = insert_newlines_with_tags(encrypted_message,
                                                  64)
    encrypted_message_with_tags = f"---BEGIN CRRO MESSAGE---\n{encrypted_message}\n---END CRRO MESSAGE---"

    return encrypted_message_with_tags


def add_encrypt_and_sign_tags(random_int_on_curve,signature, encrypted_message):

    random_int_on_curve = ''.join(str(random_int_on_curve)).encode('utf-8')

    random_int_on_curve = base64.b64encode(random_int_on_curve).decode('utf-8')

    encrypted_message = encrypted_message.decode('utf-8')

    signature = ''.join(str(signature)).encode("utf-8")

    signature_base64 = base64.b64encode(signature).decode("utf-8")


    encrypted_message_with_tags = f"---Start Signature---\n{signature_base64}\n---End Signature---\n" \
                     f"---BEGIN CURVE INT---\n{random_int_on_curve}\n---END CURVE INT---\n{encrypted_message}"

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

    cle_sign = cle_sign.replace(" ", "").replace("\n", "")

    signature = base64.b64decode(cle_sign).decode('utf-8').replace(" ", "")

    signature = signature.replace(" ", "").replace("(", "").replace(")", "").split(",")

    signature = tuple(int(signature) for signature in signature)

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

    signature = base64.b64decode(cle_sign).decode('utf-8').replace(" ", "")

    signature = signature.replace(" ", "").replace("(", "").replace(")", "").split(",")

    signature = tuple(int(signature) for signature in signature)

    return signature, message


