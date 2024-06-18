#!/usr/bin/python3 
from sage.all import * 
from Crypto.Util.number import getPrime
import random

p = 2**256 - 2**224 + 2**192 + 2**96 - 1
F = GF(p)
a = -3
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
ar = []
while 1:
    b = random.randint(0, p-1)
    print("Executing...")
    E = EllipticCurve(F, [a, b])
    G = E.gen(0)
    od = G.order()
    fac = list(od.factor())
    sub_group = []
    for f, e in fac:
        if(f**e < 2**32):
            sub_group.append(f**e)
    if prod(sub_group) >= 2**64:
        ar.append((b, G.xy(), od, sub_group))
        print(f"Choosing b: {b}")
        print(f"sub group: {sub_group}")
    if len(ar) == 4:
        break

print(ar)
