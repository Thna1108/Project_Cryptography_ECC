from sage.all import *
from pwn import *
from Cryptodome.Cipher import AES
from hashlib import sha3_512
from Crypto.Util.Padding import unpad
from random import randint

def smart_attack(P, Q, p):
    E = P.curve()
    # Randomize the lift to avoid the canonical case where Q_p and F_p are isomorphic
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) + randint(0, p) * p for t in E.a_invariants()])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)  # gets all lifted points with coordinate x

    # search for the point with the same y modulo p
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break
    p_times_P = p * P_Qp
    p_times_Q = p * Q_Qp
    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()
    phi_P = -(x_P / y_P)
    phi_Q = -(x_Q / y_Q)
    k = phi_Q / phi_P
    return ZZ(k)

# Định nghĩa đường cong elliptic
r = remote('localhost', 8888)
a = int(r.recvlineS().split('=')[1].strip())
b = int(r.recvlineS().split('=')[1].strip())
p = int(r.recvlineS().split('=')[1].strip())
P = eval(r.recvlineS().split('=')[1].strip())
Q = eval(r.recvlineS().split('=')[1].strip())
E = EllipticCurve(GF(p), [a, b])
P = E(*P)
Q = E(*Q)

# Định nghĩa điểm P và Q

#Q = E.gen(0)
# Đọc file cipher.enc
with open("output/cipher.enc", "rb") as cipher_file:
    enc = cipher_file.read()
def decrypt(key, enc):
    try:
        key = sha3_512(str(key).encode()).digest()[:16]
        iv = enc[:16]
        enc = enc[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc),16)  
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return None
# Tính secret từ P và Q
secret = smart_attack(P, Q, p)
assert P * secret == Q
print(f'Secret: {secret}')
# Giải mã dữ liệu
decryptText = decrypt(secret, enc)
with open("recovered.txt", "wb") as recover_file:
    if decryptText is not None:
        recover_file.write(decryptText)
        print("Write to recovered.txt successfully!!!")
    else:
        print("Write to recovered.txt failed!!!")
