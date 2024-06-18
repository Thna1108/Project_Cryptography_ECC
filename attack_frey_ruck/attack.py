from sage.all import *
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import json

io = remote("localhost", 6004)
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

def get_embedding_degree(q, n, max_k):
    for k in range(1, max_k + 1):
        if q ** k % n == 1:
            return k
    return None

def attack(P, Q, E, max_k=100, max_tries=100):
    q = E.base_ring().order()
    n = P.order()
    assert gcd(n, q) == 1, "GCD of base point order and curve base ring order should be 1."

    logging.info("Calculating embedding degree...")
    k = get_embedding_degree(q, n, max_k)
    if k is None:
        return None

    logging.info(f"Found embedding degree {k}")
    Ek = E.base_extend(GF(q ** k))
    Pk = Ek(P)
    Qk = Ek(Q)
    for _ in range(max_tries):
        S = Ek.random_point()
        T = Ek.random_point()
        if (gamma := Pk.tate_pairing(S, n, k) / Pk.tate_pairing(T, n, k)) == 1:
            continue

        delta = Qk.tate_pairing(S, n, k) / Qk.tate_pairing(T, n, k)
        logging.info(f"Computing {delta}.log({gamma})...")
        l = delta.log(gamma)
        return int(l)
    return None

def decrypt(secret: int, ciphertext: bytes):
    hash = sha256(str(secret).encode()).digest()
    iv, key = hash[:16], hash[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted


with open("output/cipher.enc", "rb") as cipher_file:
    enc = cipher_file.read()
alice_secret = attack(G, A, E)
shared_secret = B * alice_secret
print(f"shared: {shared_secret[0]} {shared_secret[1]}")
flag = unpad(decrypt(shared_secret[0], enc), 16)
with open("recovered.txt", "wb") as recover_file:
    if flag is not None:
        recover_file.write(flag)
        print("Write to recovered.txt successfully!!!")
    else:
        print("Write to recovered.txt failed!!!")