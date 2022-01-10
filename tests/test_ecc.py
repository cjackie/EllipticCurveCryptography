from secp256k1.ecc import ECC, ECPoint
import unittest
from .key import CECKey

class ECCTest(unittest.TestCase):
    def test_pubkey_derivation_with_small_number(self):
        ecc = ECC()

        # s (private key) is intentionaly set to a small, for easier to compute.
        s = 29
        privkey = s.to_bytes(32, "big")
        ecc.set_privkey(privkey)
        pubkey = ecc.pubkey()

        # Cross check
        key = CECKey()
        key.set_secretbytes(privkey)
        expected = pubkey = key.get_pubkey()
        self.assertEqual(pubkey, expected)

    def test_pubkey_derivation(self):
        ecc = ECC()

        # Cross check
        key = CECKey()
        key.set_secretbytes(ecc.privkey())
        expected = pubkey = key.get_pubkey()
        self.assertEqual(pubkey, expected)

