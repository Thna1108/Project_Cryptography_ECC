from sage.all import *
from pwn import *
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import * 
from hashlib import sha3_512

def func_f(X_i, P, Q, E):
    if int(X_i[0]) % 3 == 2:
        return X_i + Q
    elif int(X_i[0]) % 3 == 0:
        return 2 * X_i
    elif int(X_i[0]) % 3 == 1:
        return X_i + P
    else:
        print("[-] Something's Wrong!")
        return -1

def func_g(a, P, X_i, E):
    n = P.order()
    if int(X_i[0]) % 3 == 2:
        return a
    elif int(X_i[0]) % 3 == 0:
        return 2 * a % n
    elif int(X_i[0]) % 3 == 1:
        return (a + 1) % n
    else:
        print("[-] Something's Wrong!")
        return None

def func_h(b, P, X_i, E):
    n = P.order()
    if int(X_i[0]) % 3 == 2:
        return (b + 1) % n
    elif int(X_i[0]) % 3 == 0:
        return 2 * b % n
    elif int(X_i[0]) % 3 == 1:
        return b
    else:
        print("[-] Something's Wrong!")
        return None

def pollardrho(P, Q, E):
    n = P.order()

    for j in range(100):
        a_i = random.randint(2, P.order() - 2)
        b_i = random.randint(2, P.order() - 2)
        a_2i = random.randint(2, P.order() - 2)
        b_2i = random.randint(2, P.order() - 2)

        X_i = a_i * P + b_i * Q
        X_2i = a_2i * P + b_2i * Q

        i = 1
        while i <= n:
            a_i = func_g(a_i, P, X_i, E)
            b_i = func_h(b_i, P, X_i, E)
            X_i = func_f(X_i, P, Q, E)

            a_2i = func_g(func_g(a_2i, P, X_2i, E), P, func_f(X_2i, P, Q, E), E)
            b_2i = func_h(func_h(b_2i, P, X_2i, E), P, func_f(X_2i, P, Q, E), E)
            X_2i = func_f(func_f(X_2i, P, Q, E), P, Q, E)

            if X_i == X_2i:
                if b_i == b_2i:
                    break
                if GCD(b_2i - b_i, n) != 1:
                    break
                print(f"Collision found at iteration {j}")
                return ((a_i - a_2i) * inverse_mod(b_2i - b_i, n)) % n
            else:
                i += 1
                continue
        print(f"No collision found in iteration {j}")
    return None

def decrypt(ciphertext, key):
    key = sha3_512(str(key).encode()).digest()[:16]
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    return plaintext

if __name__ == "__main__":
    # Read parameters from the file
    r = remote('localhost', 6003)
    p = getPrime(36)
    r.sendlineafter(b'Enter prime: ', str(p).encode())
    a = int(r.recvlineS().split('=')[1].strip())
    b = int(r.recvlineS().split('=')[1].strip())
    p = int(r.recvlineS().split('=')[1].strip())
    P_coords = eval(r.recvlineS().split('=')[1].strip())
    Q_coords = eval(r.recvlineS().split('=')[1].strip())
    r.recvline()

    # Convert to elliptic curve points
    E = EllipticCurve(GF(p), [a, b])
    P = E(P_coords)
    Q = E(Q_coords)
    print(f'{a = }')
    print(f'{b = }')
    print(f'{p = }')
    print('P =', P.xy())
    print('Q =', Q.xy())
    # Use Pollard Rho to find the secret key
    found_x = pollardrho(P, Q, E)
    if found_x is not None:
        print(f"Found secret key: {found_x}")
        with open("output/cipher.enc", "rb") as f:
            ciphertext = f.read()
        try:
            plaintext = decrypt(ciphertext, found_x)
            with open("recovered.pdf", "wb") as f:
                f.write(plaintext)
            print("Successfully decrypted and saved to recovered.pdf")
        except Exception as e:
            print(f"Decryption failed: {e}")
    else:
        print("Secret key not found")