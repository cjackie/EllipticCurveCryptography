# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2012-2015 The python-bitcoinlib developers
#
# This file is taken from python-bitcoinlib bitcoin.core.key with removing bitcoin specific parts.
# This for testing purpose.

"""ECC secp256k1 crypto routines
WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!
"""
import ctypes
import ctypes.util
import hashlib
from os import urandom

_ssl = ctypes.cdll.LoadLibrary(
    ctypes.util.find_library('ssl.35') or ctypes.util.find_library('ssl') or 'libeay32'
)

_libsecp256k1_path = ctypes.util.find_library('secp256k1')
_libsecp256k1_enable_signing = False
_libsecp256k1_context = None
_libsecp256k1 = None


class OpenSSLException(EnvironmentError):
    pass

# Thx to Sam Devlin for the ctypes magic 64-bit fix (FIXME: should this
# be applied to every OpenSSL call whose return type is a pointer?)
def _check_res_void_p(val, func, args): # pylint: disable=unused-argument
    if val == 0:
        errno = _ssl.ERR_get_error()
        errmsg = ctypes.create_string_buffer(120)
        _ssl.ERR_error_string_n(errno, errmsg, 120)
        raise OpenSSLException(errno, str(errmsg.value))

    return ctypes.c_void_p(val)

_ssl.BN_add.restype = ctypes.c_int
_ssl.BN_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_bin2bn.restype = ctypes.c_void_p
_ssl.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]

_ssl.BN_cmp.restype = ctypes.c_int
_ssl.BN_cmp.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_copy.restype = ctypes.c_void_p
_ssl.BN_copy.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_free.restype = None
_ssl.BN_free.argtypes = [ctypes.c_void_p]

_ssl.BN_mod_inverse.restype = ctypes.c_void_p
_ssl.BN_mod_inverse.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_mod_mul.restype = ctypes.c_int
_ssl.BN_mod_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_mod_sub.restype = ctypes.c_int
_ssl.BN_mod_sub.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_mul_word.restype = ctypes.c_int
_ssl.BN_mul_word.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_new.errcheck = _check_res_void_p
_ssl.BN_new.restype = ctypes.c_void_p
_ssl.BN_new.argtypes = []

_ssl.BN_rshift.restype = ctypes.c_int
_ssl.BN_rshift.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]

_ssl.BN_rshift1.restype = ctypes.c_int
_ssl.BN_rshift1.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.BN_sub.restype = ctypes.c_int
_ssl.BN_sub.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

# _ssl.BN_zero.restype = ctypes.c_int
# _ssl.BN_zero.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_free.restype = None
_ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_get.restype = ctypes.c_void_p
_ssl.BN_CTX_get.argtypes = [ctypes.c_void_p]

_ssl.BN_CTX_new.errcheck = _check_res_void_p
_ssl.BN_CTX_new.restype = ctypes.c_void_p
_ssl.BN_CTX_new.argtypes = []

_ssl.EC_GROUP_get_curve_GFp.restype = ctypes.c_int
_ssl.EC_GROUP_get_curve_GFp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_GROUP_get_degree.restype = ctypes.c_int
_ssl.EC_GROUP_get_degree.argtypes = [ctypes.c_void_p]

_ssl.EC_GROUP_get_order.restype = ctypes.c_int
_ssl.EC_GROUP_get_order.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_KEY_free.restype = None
_ssl.EC_KEY_free.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_new_by_curve_name.errcheck = _check_res_void_p
_ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
_ssl.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]

_ssl.EC_KEY_get0_group.restype = ctypes.c_void_p
_ssl.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_get0_public_key.restype = ctypes.c_void_p
_ssl.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]

_ssl.EC_KEY_set_conv_form.restype = None
_ssl.EC_KEY_set_conv_form.argtypes = [ctypes.c_void_p, ctypes.c_int]

_ssl.EC_KEY_set_private_key.restype = ctypes.c_int
_ssl.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_KEY_set_public_key.restype = ctypes.c_int
_ssl.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_POINT_free.restype = None
_ssl.EC_POINT_free.argtypes = [ctypes.c_void_p]

_ssl.EC_POINT_is_at_infinity.restype = ctypes.c_int
_ssl.EC_POINT_is_at_infinity.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_POINT_new.errcheck = _check_res_void_p
_ssl.EC_POINT_new.restype = ctypes.c_void_p
_ssl.EC_POINT_new.argtypes = [ctypes.c_void_p]

_ssl.EC_POINT_mul.restype = ctypes.c_int
_ssl.EC_POINT_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.EC_POINT_set_compressed_coordinates_GFp.restype = ctypes.c_int
_ssl.EC_POINT_set_compressed_coordinates_GFp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]

_ssl.ECDSA_sign.restype = ctypes.c_int
_ssl.ECDSA_sign.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

_ssl.ECDSA_size.restype = ctypes.c_int
_ssl.ECDSA_size.argtypes = [ctypes.c_void_p]

_ssl.ECDSA_verify.restype = ctypes.c_int
_ssl.ECDSA_verify.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]

_ssl.ECDSA_SIG_free.restype = None
_ssl.ECDSA_SIG_free.argtypes = [ctypes.c_void_p]

_ssl.ECDH_compute_key.restype = ctypes.c_int
_ssl.ECDH_compute_key.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

_ssl.ERR_error_string_n.restype = None
_ssl.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

_ssl.ERR_get_error.restype = ctypes.c_ulong
_ssl.ERR_get_error.argtypes = []

_ssl.d2i_ECDSA_SIG.restype = ctypes.c_void_p
_ssl.d2i_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

_ssl.d2i_ECPrivateKey.restype = ctypes.c_void_p
_ssl.d2i_ECPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

_ssl.i2d_ECDSA_SIG.restype = ctypes.c_int
_ssl.i2d_ECDSA_SIG.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.i2d_ECPrivateKey.restype = ctypes.c_int
_ssl.i2d_ECPrivateKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.i2o_ECPublicKey.restype = ctypes.c_void_p
_ssl.i2o_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_ssl.o2i_ECPublicKey.restype = ctypes.c_void_p
_ssl.o2i_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]

_ssl.BN_num_bits.restype = ctypes.c_int
_ssl.BN_num_bits.argtypes = [ctypes.c_void_p]
_ssl.EC_KEY_get0_private_key.restype = ctypes.c_void_p

# this specifies the curve used with ECDSA.
_NID_secp256k1 = 714 # from openssl/obj_mac.h

# test that OpenSSL supports secp256k1
_ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)

SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
SECP256K1_CONTEXT_SIGN = \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)


def is_libsec256k1_available():
    return _libsecp256k1_path is not None


def use_libsecp256k1_for_signing(do_use):
    global _libsecp256k1
    global _libsecp256k1_context
    global _libsecp256k1_enable_signing

    if not do_use:
        _libsecp256k1_enable_signing = False
        return

    if not is_libsec256k1_available():
        raise ImportError("unable to locate libsecp256k1")

    if _libsecp256k1_context is None:
        _libsecp256k1 = ctypes.cdll.LoadLibrary(_libsecp256k1_path)
        _libsecp256k1.secp256k1_context_create.restype = ctypes.c_void_p
        _libsecp256k1.secp256k1_context_create.errcheck = _check_res_void_p
        _libsecp256k1.secp256k1_context_randomize.restype = ctypes.c_int
        _libsecp256k1.secp256k1_context_randomize.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _libsecp256k1_context = _libsecp256k1.secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
        assert(_libsecp256k1_context is not None)
        seed = urandom(32)
        result = _libsecp256k1.secp256k1_context_randomize(_libsecp256k1_context, seed)
        assert 1 == result



    _libsecp256k1_enable_signing = True



# From openssl/ecdsa.h
class ECDSA_SIG_st(ctypes.Structure):
    _fields_ = [("r", ctypes.c_void_p),
                ("s", ctypes.c_void_p)]

class CECKey:
    """Wrapper around OpenSSL's EC_KEY"""

    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    def __init__(self):
        self.k = _ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)

    def __del__(self):
        if _ssl:
            _ssl.EC_KEY_free(self.k)
        self.k = None

    def set_secretbytes(self, secret):
        priv_key = _ssl.BN_bin2bn(secret, 32, None)
        group = _ssl.EC_KEY_get0_group(self.k)
        pub_key = _ssl.EC_POINT_new(group)
        ctx = _ssl.BN_CTX_new()
        if not _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx):
            raise ValueError("Could not derive public key from the supplied secret.")
        _ssl.EC_KEY_set_private_key(self.k, priv_key)
        _ssl.EC_KEY_set_public_key(self.k, pub_key)
        _ssl.EC_POINT_free(pub_key)
        _ssl.BN_free(priv_key)
        _ssl.BN_CTX_free(ctx)
        return self.k

    def set_privkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def set_pubkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def get_privkey(self):
        size = _ssl.i2d_ECPrivateKey(self.k, 0)
        mb_pri = ctypes.create_string_buffer(size)
        _ssl.i2d_ECPrivateKey(self.k, ctypes.byref(ctypes.pointer(mb_pri)))
        return mb_pri.raw

    def get_pubkey(self):
        size = _ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        _ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_raw_ecdh_key(self, other_pubkey):
        ecdh_keybuffer = ctypes.create_string_buffer(32)
        r = _ssl.ECDH_compute_key(ctypes.pointer(ecdh_keybuffer), 32,
                                 _ssl.EC_KEY_get0_public_key(other_pubkey.k),
                                 self.k, 0)
        if r != 32:
            raise Exception('CKey.get_ecdh_key(): ECDH_compute_key() failed')
        return ecdh_keybuffer.raw

    def get_ecdh_key(self, other_pubkey, kdf=lambda k: hashlib.sha256(k).digest()):
        # FIXME: be warned it's not clear what the kdf should be as a default
        r = self.get_raw_ecdh_key(other_pubkey)
        return kdf(r)

    def get_raw_privkey(self):
        bn = _ssl.EC_KEY_get0_private_key(self.k)
        bn = ctypes.c_void_p(bn)
        size = (_ssl.BN_num_bits(bn) + 7) / 8
        mb = ctypes.create_string_buffer(int(size))
        _ssl.BN_bn2bin(bn, mb)
        return mb.raw.rjust(32, b'\x00')

    def _sign_with_libsecp256k1(self, hash):
        raw_sig = ctypes.create_string_buffer(64)
        result = _libsecp256k1.secp256k1_ecdsa_sign(
            _libsecp256k1_context, raw_sig, hash, self.get_raw_privkey(), None, None)
        assert 1 == result
        sig_size0 = ctypes.c_size_t()
        sig_size0.value = 75
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = _libsecp256k1.secp256k1_ecdsa_signature_serialize_der(
            _libsecp256k1_context, mb_sig, ctypes.byref(sig_size0), raw_sig)
        assert 1 == result
        # libsecp256k1 creates signatures already in lower-S form, no further
        # conversion needed.
        return mb_sig.raw[:sig_size0.value]


    def verify(self, hash, sig): # pylint: disable=redefined-builtin
        """Verify a DER signature"""
        if not sig:
          return False

        # New versions of OpenSSL will reject non-canonical DER signatures. de/re-serialize first.
        norm_sig = ctypes.c_void_p(0)
        _ssl.d2i_ECDSA_SIG(ctypes.byref(norm_sig), ctypes.byref(ctypes.c_char_p(sig)), len(sig))

        derlen = _ssl.i2d_ECDSA_SIG(norm_sig, 0)
        if derlen == 0:
            _ssl.ECDSA_SIG_free(norm_sig)
            return False

        norm_der = ctypes.create_string_buffer(derlen)
        _ssl.i2d_ECDSA_SIG(norm_sig, ctypes.byref(ctypes.pointer(norm_der)))
        _ssl.ECDSA_SIG_free(norm_sig)

        # -1 = error, 0 = bad sig, 1 = good
        return _ssl.ECDSA_verify(0, hash, len(hash), norm_der, derlen, self.k) == 1

    def set_compressed(self, compressed):
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        _ssl.EC_KEY_set_conv_form(self.k, form)

    def recover(self, sigR, sigS, msg, msglen, recid, check):
        """
        Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
        recid selects which key is recovered
        if check is non-zero, additional checks are performed
        """
        i = int(recid / 2)

        r = None
        s = None
        ctx = None
        R = None
        O = None
        Q = None

        assert len(sigR) == 32, len(sigR)
        assert len(sigS) == 32, len(sigS)

        try:
            r = _ssl.BN_bin2bn(bytes(sigR), len(sigR), _ssl.BN_new())
            s = _ssl.BN_bin2bn(bytes(   sigS), len(sigS), _ssl.BN_new())

            group = _ssl.EC_KEY_get0_group(self.k)
            ctx = _ssl.BN_CTX_new()
            order = _ssl.BN_CTX_get(ctx)
            ctx = _ssl.BN_CTX_new()

            if not _ssl.EC_GROUP_get_order(group, order, ctx):
                return -2

            x = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_copy(x, order):
                return -1
            if not _ssl.BN_mul_word(x, i):
                return -1
            if not _ssl.BN_add(x, x, r):
                return -1

            field = _ssl.BN_CTX_get(ctx)
            if not _ssl.EC_GROUP_get_curve_GFp(group, field, None, None, ctx):
                return -2

            if _ssl.BN_cmp(x, field) >= 0:
                return 0

            R = _ssl.EC_POINT_new(group)
            if R is None:
                return -2
            if not _ssl.EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx):
                return 0

            if check:
                O = _ssl.EC_POINT_new(group)
                if O is None:
                    return -2
                if not _ssl.EC_POINT_mul(group, O, None, R, order, ctx):
                    return -2
                if not _ssl.EC_POINT_is_at_infinity(group, O):
                    return 0

            Q = _ssl.EC_POINT_new(group)
            if Q is None:
                return -2

            n = _ssl.EC_GROUP_get_degree(group)
            e = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_bin2bn(msg, msglen, e):
                return -1

            if 8 * msglen > n:
                _ssl.BN_rshift(e, e, 8 - (n & 7))

            zero = _ssl.BN_CTX_get(ctx)
            # if not _ssl.BN_zero(zero):
            #     return -1
            if not _ssl.BN_mod_sub(e, zero, e, order, ctx):
                return -1
            rr = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_inverse(rr, r, order, ctx):
                return -1
            sor = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_mul(sor, s, rr, order, ctx):
                return -1
            eor = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_mul(eor, e, rr, order, ctx):
                return -1
            if not _ssl.EC_POINT_mul(group, Q, eor, R, sor, ctx):
                return -2

            if not _ssl.EC_KEY_set_public_key(self.k, Q):
                return -2

            return 1
        finally:
            if r: _ssl.BN_free(r)
            if s: _ssl.BN_free(s)
            if ctx: _ssl.BN_CTX_free(ctx)
            if R: _ssl.EC_POINT_free(R)
            if O: _ssl.EC_POINT_free(O)
            if Q: _ssl.EC_POINT_free(Q)

class CPubKey(bytes):
    """An encapsulated public key
    Attributes:
    is_valid      - Corresponds to CPubKey.IsValid()
    is_fullyvalid - Corresponds to CPubKey.IsFullyValid()
    is_compressed - Corresponds to CPubKey.IsCompressed()
    """

    def __new__(cls, buf, _cec_key=None):
        self = super(CPubKey, cls).__new__(cls, buf)
        if _cec_key is None:
            _cec_key = CECKey()
        self._cec_key = _cec_key
        self.is_fullyvalid = _cec_key.set_pubkey(self) is not None
        return self

    @classmethod
    def recover_compact(cls, hash, sig): # pylint: disable=redefined-builtin
        """Recover a public key from a compact signature."""
        if len(sig) != 65:
            raise ValueError("Signature should be 65 characters, not [%d]" % (len(sig), ))

        recid = (sig[0] - 27) & 3
        compressed = (sig[0] - 27) & 4 != 0

        cec_key = CECKey()
        cec_key.set_compressed(compressed)

        sigR = sig[1:33]
        sigS = sig[33:65]

        result = cec_key.recover(sigR, sigS, hash, len(hash), recid, 0)

        if result < 1:
            return False

        pubkey = cec_key.get_pubkey()

        return CPubKey(pubkey, _cec_key=cec_key)

    @property
    def is_valid(self):
        return len(self) > 0

    @property
    def is_compressed(self):
        return len(self) == 33

    def verify(self, hash, sig): # pylint: disable=redefined-builtin
        return self._cec_key.verify(hash, sig)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())
