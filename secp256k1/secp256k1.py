
import binascii
import re

# Taken from Section 2.4.1 in https://www.secg.org/sec2-v2.pdf
class Params:
    p = 2**256 - 2**32 - 977

    # E: y^2 = x^3 + a*x + b
    a = 0
    b = 7

    # Uncompressed form
    G = binascii.unhexlify(re.sub('\W', '',
    '''
        04 
        79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
        483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
    '''))

    n = binascii.unhexlify(re.sub('\W', '', 
        'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141'))

    h = 1



