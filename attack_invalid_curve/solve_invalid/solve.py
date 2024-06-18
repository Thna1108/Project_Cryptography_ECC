#!/usr/bin/python3 
from sage.all import*
from pwn import*
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import ARC4 
import ast

params = [(80126308155102803040478570376906442686921859017883980036125899221131542032735, (60951029624907543743328761707496203763017768511996411880388613028141771255965, 35658616661022200744592917203424409380959808543194073966475913910564426865705), 115792089210356248762697446949407573529907778114464860960412845879832558000698, [2, 43, 23767, 12170551, 257467541]), (73633465256250339103776962879052917369957363386373067311696537523933666695863, (66922455478597897894127940901177470957287673051154013353887537189231208193155, 85029470445415931836492075159786397176150665395801003553453219789533790126715), 115792089210356248762697446949407573529857663267054825531822012915561336157038, [2, 13, 1103, 601333, 1735271, 3850373]), (80463878268200288270757577505298185669035709877255855862263440097314911653584, (99399161282312222740607958557772531960564604469523803707045166843278714847761, 82058730668719590356657191188195104632551031446405152250578167208191082783525), 115792089210356248762697446949407573529666375951892135695880102052942111304580, [4, 3, 5, 529, 283, 336143, 15597487]), (6759871680847809782271110194234668451992108185471980919599226530970565598430, (80008728693834753251850165818207831918165606705344238545676455149555857909464, 46820154043591045334042968315862352214157940584746624878038327257119406507413), 115792089210356248762697446949407573530281662543941483467918923678014399108888, [8, 3, 19, 3061, 997739, 19310171, 54620359, 125716051])]

p = 2**256 - 2**224 + 2**192 + 2**96 - 1

r = remote("localhost", 6001)
#r = process(["python", "server.py"], env={"FLAG": "FLAG{testing}"})
r.recvuntil(b"Show public key: ")
pub = ast.literal_eval(r.recvlineS())
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

def xor(x, y):
    return bytes([a ^ b for a, b in zip(x, y)])

def bytes_to_point(b : bytes):
    return bytes_to_long(b[:32]), bytes_to_long(b[32:])

def point_to_bytes(P):
    return P[0].to_bytes(32, "big") + P[1].to_bytes(32, "big")

def get_dlp(b, x, y):
    E = EllipticCurve(GF(p), [-3, b])
    Q = E(x, y)
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"x: ", str(x).encode())
    r.sendlineafter(b"y: ", str(y).encode())
    ct = bytes.fromhex(r.recvlineS().strip())
    for m in quotes:
        xy = xor(m.encode().ljust(64, b"\0"), ct)
        try:
            P = E(*bytes_to_point(xy))
            return P, Q
        except:
            pass

def get_flag():
    r.sendlineafter(b'> ', b'2')
    E = EllipticCurve(GF(p), [-3, 41058363725152142129326129780047268409114441015993725554835256314039467401291])
    C1 = E(*bytes_to_point(bytes.fromhex(r.recvlineS().strip())))
    C2 = bytes.fromhex(r.recvlineS().strip())
    return C1, C2 

C1, C2 = get_flag()
# E(Fp), p = f1.f2...fn (factor)
# CRT sol: x(p/fn)P = (p/fn)Q
def get_d():
    sec = []
    mod = []
    for b, (x,y), od, subgroups in params:
    	print(f"\nTrying y^2 = x^3 - 3x + {b}")
    	P,Q = get_dlp(b,x,y)
    	for subgroup in subgroups:
    		print(f"solving size {subgroup}")
    		tmp = od // subgroup
    		k = discrete_log(tmp * P, tmp * Q, ord=ZZ(subgroup), operation="+")
    		print(f"d: {k} mod {subgroup}")
    		sec.append(k)
    		mod.append(subgroup)
    return crt(sec,mod)   
       
    	
d = get_d()
print(f"Secret key = {d}")


# P = dG, C1 = rG => dC1 = rdG = rP
K = d*C1
key = point_to_bytes(list(map(int, K.xy())))
output = xor(key, C2)
secret = output[:57]
print(f"Secret plaintext: {secret}")
r.close()
