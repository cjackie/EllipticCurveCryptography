# ECC stands for Elliptic Curve Cryptography
from .secp256k1 import Params
from copy import copy
import os
import random


# Section 2.3.6 in https://www.secg.org/sec1-v2.pdf
def _be(m: bytes) -> int:
    '''
    Intepret the bytes as a big endian number.
    '''
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
        self.G_x = _be(Params.G[1:33])
        self.G_y = _be(Params.G[33:])
        self.n = _be(Params.n)
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
        '''
        Efficiently multiply n*pt. The time complexity is O(log(n))
        This may be called Double-and-add (https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication)
        '''
        # Assume n is 32 bytes big endian number.
        assert n < 2**256 and n > 0

        # Pre-compute the table for 2*n*pt 
        table = [ECPoint(None, None, inf=True)]*256
        table[1] = pt
        for i in range(2, 256):
            table[i] = self._add(table[i-1], table[i-1])

        # n * pt = (I_0*2^0 + I_1*2^1 + I_2*2^2 ... I_256*2^256) * pt, where I_k is 1 or 0.
        # So we can adding I_k*2^k * pt together for I_k = 1, and I_k*2^k * pt can be looked up with 
        # `table`
        k = 0
        r = ECPoint(None, None, inf=True)
        while n > 0:
            if n % 2 == 1:
                r = self._add(r, table[k])
            k += 1
            n //= 2

        return r
    
    def privkey(self) -> bytes:
        return self._privkey

    def pubkey(self) -> bytes:
        if self._pubkey:
            return b"\x04" + self._pubkey.x.to_bytes(32, "big")  + self._pubkey.y.to_bytes(32, "big") 
        s = _be(self._privkey)
        g = ECPoint(self.G_x, self.G_y)
        # FIXME: this will take forever to finish....
        self._pubkey = self._mult(s, g)
        return self.pubkey()

    def set_privkey(self, privkey: bytes):
        self._privkey = privkey
        self._pubkey = None

        
