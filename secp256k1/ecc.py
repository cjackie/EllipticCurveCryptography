# ECC stands for Elliptic Curve Cryptography
from .secp256k1 import Params
from copy import copy
import os
import random


# Section 2.3.6 in https://www.secg.org/sec1-v2.pdf
def _convert(m: bytes) -> int:
    x = 0
    mlen = len(m)
    for i in range(mlen):
        x += (2**8)**(mlen-1-i)*m[i]
    return x

assert Params.G[0] == 4

class ECPoint():
    def __init__(self, x, y, inf=False):
        self.x = x
        self.y = y
        self.inf = inf

class ECC():
    def __init__(self):
        self.p = Params.p
        self.a = Params.a
        self.b = Params.b
        self.G_x = _convert(Params.G[1:33])
        self.G_y = _convert(Params.G[33:])
        self.n = _convert(Params.n)
        self.h = Params.h

        s = random.randint(1, self.n)
        self._privkey = s.to_bytes(32, "big")
        self._pubkey = None

    # Section 2.2.1 in https://www.secg.org/sec1-v2.pdf
    def _add(self, pt1: ECPoint, pt2: ECPoint):
        if pt1.inf and pt2.inf:
            return ECPoint(None, None, inf=True)
        
        if pt1.inf:
            return copy(pt2)

        if pt2.inf:
            return copy(pt1)

        if pt1.x == pt2.x and pt1.y == -pt2.y:
            return ECPoint(None, None, inf=True)

        p = self.p
        a = self.a
        if pt1.x != pt2.x:
            # (x / y) % p = (x * (y**(-1) % p)) % p where  y**(-1) % p is called Modular multiplicative inverse. 
            # Likely in python3, we can use pow(y, -1, p) to get "y**(-1) % p"
            # ref: 
            #   1. https://stackoverflow.com/questions/12235110/modulo-of-division-of-two-numbers
            #   2. https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
            l = ((pt2.y - pt1.y) * pow(pt2.x - pt1.x, -1, p)) % p
            assert type(l) == int, "{} must be an int".format(l)

            x3 = (l**2 - pt1.x - pt2.x) % p

            y3 = (l*(pt1.x - x3) - pt1.y) % p
            return ECPoint(x3, y3)

        if pt1.x == pt2.x and pt1.y == pt2.y:
            l = ((3*pt1.x**2 + a) * pow(2*pt1.y, -1, p)) % p
            assert type(l) == int, "{} must be an int".format(l)

            x3 = (l**2 - 2*pt1.x) % p
            y3 = (l*(pt1.x - x3) - pt1.y) % p
            return ECPoint(x3, y3)

        raise Exception("Not rules for addition of two EC points ({}, {}) and ({}, {})".format(pt1.x, pt1.y, pt2.x, pt2.y))

    def _mult(self, n, pt):
        assert n > 0
        r = copy(pt)
        for _ in range(1, n):
            r = self._add(r, pt)
        return r
    
    def privkey(self) -> bytes:
        return self._privkey

    def pubkey(self) -> bytes:
        if self._pubkey:
            return b"\x04" + self._pubkey.x.to_bytes(32, "big")  + self._pubkey.y.to_bytes(32, "big") 
        s = _convert(self._privkey)
        g = ECPoint(self.G_x, self.G_y)
        # FIXME: this will take forever to finish....
        self._pubkey = self._mult(s, g)
        return self.pubkey()

    def set_privkey(self, privkey: bytes):
        self._privkey = privkey
        self._pubkey = None

        
