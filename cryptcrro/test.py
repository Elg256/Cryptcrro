import os

from cryptcrro.asymetric import crro
from cryptcrro.asymetric import rsa
from cryptcrro.symetric import crro as scrro
import time

from cryptcrro.symetric import Sha256_Ctr

message = b"""Information can leak from a system through measurement of the time it takes to respond to certain queries. How much this information can help an attacker depends on many variables: cryptographic system design, the CPU running the system, the algorithms used, assorted implementation details, timing attack countermeasures, the accuracy of the timing measurements, etc. Timing attacks can be applied to any algorithm that has data-dependent timing variation. Removing timing-dependencies is difficult in some algorithms that use low-level operations that frequently exhibit varied execution time."""

# lets test crro ECC first
private_key = crro.generate_private_key()
pk = crro.generate_public_key(private_key)

start_time = time.time()
ciphertext = crro.encrypt(pk, message)
text = crro.decrypt(private_key, ciphertext)

if text == message:
    print(f"crro.encrypt/decrypt             Ok  {time.time() - start_time}")
else:
    print("crro.encrypt/decrypt              Failed")


start_time = time.time()
ciphertext = crro.sign(private_key, message)
t_f_sign, text = crro.check_signature(pk, ciphertext)

if text == message.decode().strip() and t_f_sign == True:
    print(f"crro.sign/verif                  Ok  {time.time() - start_time}")
elif t_f_sign != True:
    print("crro.sign/verif                   Failed signature False")

elif text != message.decode().strip():
    print("crro.sign/verif                   Failed text != message")

start_time = time.time()
ciphertext = crro.sign_and_encrypt(private_key, pk, message)
t_f_sign, text = crro.decrypt_and_check_signature(private_key,pk, ciphertext)


if text == message.decode().strip() and t_f_sign == True:
    print(f"crro.sign_encrypt/decrypt_verify Ok  {time.time() - start_time}")
elif t_f_sign == False:
    print(f"crro.sign_encrypt/decrypt_verify Failed signature False")
elif text != message.decode().strip():
    print(f"crro.sign_encrypt/decrypt_verify Failed text != message")




# lets test crro RSA
private_key, pk = rsa.generate_keys()

start_time = time.time()
ciphertext = rsa.encrypt(pk, message)
text = rsa.decrypt(private_key, ciphertext)


if text == message:
    print(f"rsa.encrypt/decrypt              Ok  {time.time() - start_time}")
else:
    print(f"rsa.encrypt/decrypt              Failed")

start_time = time.time()
ciphertext = rsa.sign(private_key, message)
t_f_sign, text = rsa.check_signature(pk, ciphertext)

if text == message.decode().strip() and t_f_sign == True:
    print(f"rsa.sign/verif                   Ok  {time.time() - start_time}")
else:
    print(f"rsa.sign/verif                   Failed")

start_time = time.time()
ciphertext = rsa.sign_and_encrypt(private_key, pk, message)
t_f_sign, text = rsa.decrypt_and_check_signature(private_key,pk, ciphertext)

if text == message.decode().strip() and t_f_sign == True:
    print(f"rsa.sign_encrypt/decrypt_verify  Ok  {time.time() - start_time}")
else:
    print(f"rsa.sign_encrypt/decrypt_verify  Failed")


key = scrro.generate_key()
start_time = time.time()
ciphertext = scrro.encrypt(key, message)

text = scrro.decrypt(key, ciphertext)

if text == message:
    print(f"scrro.encrypt/decrypt            Ok  {time.time() - start_time}")
else:
    print(f"scrro.encrypt/decrypt            Failed")


key = Sha256_Ctr.generate_key()
start_time = time.time()
ciphertext = Sha256_Ctr.encrypt(key, message)

text = Sha256_Ctr.decrypt(key, ciphertext)

if text == message:
    print(f"Sha256_Ctr.encrypt/decrypt       Ok  {time.time() - start_time}")
else:
    print(f"Sha256_Ctr.encrypt/decrypt       Failed")
