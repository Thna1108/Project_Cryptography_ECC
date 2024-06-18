from ecdsa import ellipticcurve as ecc
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import time
import random
import os 
import json


with open("input.pdf", "rb") as re:
    inputt = re.read()
a = -35
b = 98
p = 434252269029337012720086440207
Gx = 16378704336066569231287640165
Gy = 377857010369614774097663166640
ec_order = 434252269029337012720086440208

E = ecc.CurveFp(p, a, b)
G = ecc.Point(E, Gx, Gy, ec_order)


def exchange():
    alice_secret, bob_secret = random.randint(1,pow(2,64)), random.randint(1,pow(2,64))
    aG = G * alice_secret
    bG = G * bob_secret 
    print(f'{a = }')
    print(f'{b = }')
    print(f'{p = }')
    print('Gx =', Gx)
    print('Gy =', Gy)
    print('aGx =', aG.x())
    print('aGy =', aG.y())
    print('bGx =', bG.x())
    print('bGy =', bG.y())
    shared_secret = aG * bob_secret
    return shared_secret

def encrypt(shared_secret: int):
    hash = sha256(str(shared_secret).encode()).digest()
    iv, key = hash[:16], hash[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(inputt, 16))
    return encrypted


while True:
    try:
        print("What do you want?")
        print("1. Get an encrypted flag")
        print("2. Exit")
        option = int(input("> "))
        if option == 1:
            s = exchange()
            encSend = encrypt(int(s.x()))
            with open("/output/cipher.enc", "wb") as cipher:
                cipher.write(encSend)
        elif option == 2:
            print("Exit!")
            break
        print()
    except Exception as ex:
        print("Error")
        print(ex)
        break