from sage.all import *
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import json

io = remote("localhost", 6002)
io.sendlineafter(b"> ", b"1")

# Obtaining the values from the server
a = int(io.recvlineS().split('=')[1].strip())
b = int(io.recvlineS().split('=')[1].strip())
p = int(io.recvlineS().split('=')[1].strip())
Gx = int(io.recvlineS().split('=')[1].strip())
Gy = int(io.recvlineS().split('=')[1].strip())
aGx = int(io.recvlineS().split('=')[1].strip())
aGy = int(io.recvlineS().split('=')[1].strip())
bGx = int(io.recvlineS().split('=')[1].strip())
bGy = int(io.recvlineS().split('=')[1].strip())

E = EllipticCurve(GF(p), [a, b])
G = E(Gx, Gy)
A = E(aGx, aGy)
B = E(bGx, bGy)

info (f"Base Point: {(Gx,Gy)}")
info(f"Alice : {(aGx, aGy)}")
info(f"Bob   : {(bGx, bGy)}")


# Actually solving
def movAttack(G, Q, p, a, b):
    # finding the embdedding degree
    k = 1
    while (p**k - 1) % E.order():
        k += 1

    E2 = EllipticCurve(GF(p**k), [a,b])
    T = E2.random_point()
    M = T.order()
    N = G.order()
    T1 = (M//gcd(M, N)) * T
    _G = E2(G).weil_pairing(T1, N)
    _Q = E2(Q).weil_pairing(T1, N)
    nQ = _Q.log(_G)
    return nQ

# see `source.py`
def decrypt(secret: int, ciphertext: bytes):
    hash = sha256(str(secret).encode()).digest()
    iv, key = hash[:16], hash[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted


with open("output/cipher.enc", "rb") as cipher_file:
    enc = cipher_file.read()
alice_secret = movAttack(G, A, p, a, b)
shared_secret = B * alice_secret
info(f"shared: {shared_secret[0]} {shared_secret[1]}")
flag = unpad(decrypt(shared_secret[0], enc), 16)
with open("recovered.txt", "wb") as recover_file:
    if flag is not None:
        recover_file.write(flag)
        print("Write to recovered.txt successfully!!!")
    else:
        print("Write to recovered.txt failed!!!")
