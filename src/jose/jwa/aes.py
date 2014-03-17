from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto.Util.strxor import strxor
from struct import pack
from jose import BaseContentEncryptor

slice = lambda s, n: [s[i:i + n] for i in range(0, len(s), n)]
AES_IV = b'\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6'


def aes_key_wrap(K, P):
    """
    aes key wrap : :rfc:`3394` 2.2.1

        :param str K: key encrytpion key
        :param str P: plaintext
    """

    assert len(K) * 8 in [128, 192, 256]  # key bits
    assert len(P) % 8 == 0     # 64 bit blok

    n = len(P) / 8      # 64 bit blocks
    A = AES_IV          # Set A = IV
    R = [b'\0\0\0\0\0\0\0\0'
         ] + slice(P, 8)     # copy of slice every 8 octets
                        # For i = 1 to n ; R[i] = P[i]

    _AES = AES.AESCipher(K)
    for j in range(0, 6):               # For j=0 to 5
        for i in range(1, n + 1):       # For i=1 to n
            B = _AES.encrypt(A + R[i])  # B = AES(K, A | R[i])
            R[i] = B[8:]                # R[i] = LSB(64, B)

            t = pack("!q", (n * j) + i)
            A = strxor(B[:8], t)
            # A = MSB(64, B) ^ t where t = (n*j)+i

    R[0] = A            # Set C[0] = A
    return "".join(R)   # For i = 1 to n C[i] = R[i]


def aes_key_unwrap(K, C):
    """
    aes key unwrap : :rfc:`3394` 2.2.2

        :param str K: key encrytpion key
        :param str C: ciphertext
    """

    assert len(K) * 8 in [128, 192, 256]  # key bits
    assert len(C) % 8 == 0     # 64 bit blok

    n = len(C) / 8 - 1         # 64bit blocks
    R = slice(C, 8)
    A = R[0]                   # Set A = C[0] (=R[0])
    R[0] = [b'\0\0\0\0\0\0\0\0']
                               # init R[0]
                               # For i = 1 to n ; R[i] = C[i]

    _AES = AES.AESCipher(K)
    for j in range(5, -1, -1):           # For j = 5 to 0
        for i in range(n, 0, -1):        # For i = n to 1
            t = pack("!q", (n * j) + i)  # t = n * j + i
            src = strxor(A, t) + R[i]             # A ^ t
            B = _AES.decrypt(src)
            # B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i

            A = B[:8]                    # A = MSB(64, B)
            R[i] = B[8:]                 # R[i] = LSB(64, B)

    if A == AES_IV:
        return "".join(R[1:])   # For i = 1 to n; P[i] = R[i]
    else:
        raise Exception("unwrap failed: Invalid IV")

### Key Encryption

from jose import BaseKeyEncryptor


class AesKeyEncryptor(BaseKeyEncryptor):
    @classmethod
    def key_length(cls):
        return cls._KEY_LEN

    @classmethod
    def encrypt(cls, jwk, cek, *args, **kwargs):
        key = jwk.key.shared_key[:cls._KEY_LEN]
        return aes_key_wrap(key, cek)

    @classmethod
    def decrypt(cls, jwk, cek_ci, *args, **kwargs):
        key = jwk.key.shared_key[:cls._KEY_LEN]
        return aes_key_unwrap(key, cek_ci)

    @classmethod
    def provide(cls, jwk, jwe, cek=None, iv=None, *args, **kwargs):
        _enc = jwe.enc.encryptor
        if cek:
            #:TODO check iv lenth and validity
            pass
        else:
            cek, iv = _enc.create_key_iv()
        cek_ci = cls.encrypt(jwk, cek, iv, "")

        return (cek, iv, cek_ci)

    @classmethod
    def agree(cls, jwk, jwe, cek_ci, *args, **kwargs):
        cek = cls.decrypt(jwk, cek_ci)
        return cek


class A128KW(AesKeyEncryptor):
    _KEY_LEN = 16
    _IV_LEN = 16


class A192KW(AesKeyEncryptor):
    _KEY_LEN = 24
    _IV_LEN = 16


class A256KW(AesKeyEncryptor):
    _KEY_LEN = 32
    _IV_LEN = 16


### Content Encryption

_BS = 16
pkcs5_pad = lambda s: s + (_BS - len(s) % _BS) * chr(_BS - len(s) % _BS)
pkcs5_unpad = lambda s: s[0:-ord(s[-1])]
to_al = lambda x:  pack("!Q", 8 * len(x))


class AesContentEncrypor(BaseContentEncryptor):
    ''' AES_CBC_HMAC_SHA2 (Jwa 5.2)

    '''

    @classmethod
    def unpack_key(cls, cek):
        return (
            cek[:cls._MAC_KEY_LEN],
            cek[-1 * cls._ENC_KEY_LEN:]
        )

    @classmethod
    def mac_input(cls, ciphert, iv, assoc):
        al = to_al(assoc)
        return assoc + iv + ciphert + al

    @classmethod
    def make_tag(cls, mac_k, ciphert, iv, aad):
        mac_i = cls.mac_input(ciphert, iv, aad)
        hmac = HMAC.new(mac_k, digestmod=cls._HASH)
        hmac.update(mac_i)
        return hmac.digest()[:cls._TAG_LEN]

    @classmethod
    def encrypt(cls, cek, plaint, iv, aad):
        mac_k, enc_k = cls.unpack_key(cek)
        ci = AES.new(enc_k, AES.MODE_CBC, iv)
        ciphert = ci.encrypt(pkcs5_pad(plaint))
        tag = cls.make_tag(mac_k, ciphert, iv, aad)

        return (ciphert, tag)

    @classmethod
    def decrypt(cls, cek, ciphert, iv, aad, tag):
        mac_k, enc_k = cls.unpack_key(cek)
        if tag != cls.make_tag(mac_k, ciphert, iv, aad):
            return (None, False)

        ci = AES.new(enc_k, AES.MODE_CBC, iv)
        plaint = pkcs5_unpad(ci.decrypt(ciphert))
        return (plaint, True)


class A128CBC_HS256(AesContentEncrypor):
    ''' AES_128_CBC_HMAC_SHA_256 (Jwa 5.2.3)
    '''
    _KEY_LEN = 32
    _IV_LEN = 16
    _ENC_KEY_LEN = 16
    _MAC_KEY_LEN = 16
    _HASH = SHA256
    _TAG_LEN = 16


class A192CBC_HS384(AesContentEncrypor):
    ''' AES_192_CBC_HMAC_SHA_384 (Jwa 5.2.4)
    '''
    _KEY_LEN = 48
    _IV_LEN = 16
    _ENC_KEY_LEN = 24
    _MAC_KEY_LEN = 24
    _TAG_LEN = 24       # Authentication Tag Length
    _HASH = SHA384


class A256CBC_HS512(AesContentEncrypor):
    ''' AES_256_CBC_HMAC_SHA_512 (Jwa 5.2.5)
    '''
    _KEY_LEN = 64
    _IV_LEN = 16
    _ENC_KEY_LEN = 32
    _MAC_KEY_LEN = 32
    _HASH = SHA512
    _TAG_LEN = 32


if __name__ == '__main__':

    from jose.jwa.encs import KeyEncEnum, EncEnum

    encs = ['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512']
    algs = ['A128KW', 'A192KW', 'A256KW']

    from jose.utils import base64
    for e in encs:
        enc = EncEnum.create(e).encryptor
        cek, iv = enc.create_key_iv()
        assert len(cek) == enc._KEY_LEN
        assert len(iv) == enc._IV_LEN
        print enc.__name__
        print "CEK =", base64.urlsafe_b64encode(cek)
        print "IV=", base64.urlsafe_b64encode(iv)

    import itertools
    from jose.jwk import Jwk
    from jose.jwe import Jwe
    jwk = Jwk.generate(kty="oct")
    for a, e in list(itertools.product(algs, encs)):
        jwe = Jwe(
            alg=KeyEncEnum.create(a),
            enc=EncEnum.create(e),
        )
        cek, iv, cek_ci = jwe.provide_key(jwk)

        print "alg=", a, "enc=", e
        print "CEK=", base64.base64url_encode(cek)
        print "IV=", base64.base64url_encode(iv)
        print "CEK_CI=", base64.base64url_encode(cek_ci)
        print "Jwe.iv=",  jwe.iv
        print "Jwe.tag=",  jwe.tag

        cek2 = jwe.agree_key(jwk, cek_ci)
        print "CEK AGREED=", base64.base64url_encode(cek2)
