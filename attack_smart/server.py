from sage.all import *
from hashlib import sha3_512
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
# Define elliptic curve parameters
p = 0xa15c4fb663a578d8b2496d3151a946119ee42695e18e13e90600192b1d0abdbb6f787f90c8d102ff88e284dd4526f5f6b6c980bf88f1d0490714b67e8a2a2b77
a = 0x5e009506fcc7eff573bc960d88638fe25e76a9b6c7caeea072a27dcd1fa46abb15b7b6210cf90caba982893ee2779669bac06e267013486b22ff3e24abae2d42
b = 0x2ce7d1ca4493b0977f088f6d30d9241f8048fdea112cc385b793bce953998caae680864a7d3aa437ea3ffd1441ca3fb352b0b710bb3f053e980e503be9a7fece
E = EllipticCurve(GF(p), [a, b])

def get_plain_text(file_path):
    try:
        with open(file_path, "rb") as f:
            plaintext = f.read()
        return plaintext
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    except Exception as e:
        print(f"Error reading file '{file_path}': {str(e)}")
        return None

def encrypt(key, plain):
    try:
        # Create a SHA-256 hash of the key and use the first 16 bytes as the AES key
        aes_key = sha3_512(str(key).encode()).digest()[:16]
        iv = random.randbytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(plain,16))
        return iv + encrypted_data
    except Exception as e:
        print(f"Encryption error: {str(e)}")
        return None

def generate_private_key(P):
    try:
        return random.randint(1, P.order() - 1)
    except Exception as e:
        print(f"Error generating private key: {str(e)}")
        return None

def generate_public_key(P, n):
    try:
        return P * n
    except Exception as e:
        print(f"Error generating public key: {str(e)}")
        return None
assert is_prime(E.order())
P = E.gen(0)
file_path = "test.txt"
plaintext = get_plain_text(file_path)
n = generate_private_key(P)
Q = generate_public_key(P, n)
print(f'{a = }')
print(f'{b = }')
print(f'{p = }')
print('P =', P.xy())
print('Q =', Q.xy())
encrypted = encrypt(n, plaintext)
#print(f"encrypted :{encrypted}")
with open("/output/cipher.enc", "wb") as cipher_file:
    if encrypted is not None:
        cipher_file.write(encrypted)
    else:
        cipher_file.write(b'None')
