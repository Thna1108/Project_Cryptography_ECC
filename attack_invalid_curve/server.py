from elliptic_curve import Curve, Point
from Crypto.Util.number import bytes_to_long
import os
from random import choice
from secrets import randbelow

flag = os.environb[b"FLAG"]
assert flag.startswith(b"MMH{")
assert flag.endswith(b"}")
flag += os.urandom(64 - len(flag))

# NIST P-256
a = -3
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
p = 2**256 - 2**224 + 2**192 + 2**96 - 1
E = Curve(p, a, b)
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
Gx = 48439561293906451759052585252797914202762949526041747995844080717082404635286
Gy = 36134250956749795798585127919587881956611106672985015071877198253568414405109
G = Point(E, Gx, Gy)

d = randbelow(n)
P = G * d


def point_to_bytes(P):
    return P.x.to_bytes(32, "big") + P.y.to_bytes(32, "big")


def encrypt(P, m):
    key = point_to_bytes(P)
    return bytes([x ^ y for x, y in zip(m.ljust(64, b"\0"), key)])


quotes = [
    "Lap trinh mAng Can ban truong Dai HOC CoNg NGe tHOng tiN +++_+++",
    "NT 219 Mat ma hoc, Mat ma hoc",
    "Nhom do an!",
    "ky niem 70 nam chien thang Dien Bien Phu",
    "HA↑HA↑HA↓HA↓HA↓",
    "HA↑HA↑HA↑HA↑",
    "it's me group sixxx!",
    "imPleMentAtION_%_1",
]

print("Show public key: %s" % P)

while True:
    try:
        print("What do you want?")
        print("1. Start a Diffie-Hellman key exchange")
        print("2. Get an encrypted flag")
        print("3. Exit")
        option = int(input("> "))
        if option == 1:
            print("Public key wo kudasai!")
            x = int(input("x: "))
            y = int(input("y: "))
            S = Point(E, x, y) * d
            print(encrypt(S, choice(quotes).encode()).hex())
        elif option == 2:
            r = randbelow(n)
            C1 = r * G
            C2 = encrypt(r * P, flag)
            print(point_to_bytes(C1).hex())
            print(C2.hex())
        elif option == 3:
            print("otsupeko!")
            break
        print()
    except Exception as ex:
        print("kusa peko")
        print(ex)
        break
