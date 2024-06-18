from sage.all_cmdline import *
from sage.all import *
from Crypto.Util.number import *
import random
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad
from hashlib import sha3_512

def check(prime):
    if not isPrime(prime):
        print("Not a prime!!!")
        return False
    if prime <= (2**35):
        print("Prime too small!!!")
        return False
    return True

def genPara(p):
    while True:
        a,b = random.randrange(0, p-1), random.randrange(0, p-1)
        E = EllipticCurve(GF(p), [a,b])
        if (4*a**3 + 27*b**2) % p != 0 and isPrime(int(E.order())):
            return a,b
        
def encrypt(key, mess):
    key = sha3_512(str(key).encode()).digest()[:16]
    iv = random.randbytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(mess, AES.block_size))
    return iv + ct

while True:
    p = int(input("Enter prime: "))
    if check(p):
        break

F = GF(p)
a,b = genPara(p)
E = EllipticCurve(F, [a,b])
P = E.gens()[0] 
secret = random.randint(1, P.order()-1)
Q = P * secret

print(f'{a = }')
print(f'{b = }')
print(f'{p = }')
print('P =', P.xy())
print('Q =', Q.xy())


with open("input.pdf", 'rb') as file:
    pt = file.read()

ciphertext = encrypt(secret, pt)
with open("/output/cipher.enc", "wb") as file:
    file.write(ciphertext)
    print("Write ciphertext to cipher.enc successfully!")