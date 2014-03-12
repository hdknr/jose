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
    def encrypt(self, key, cek, *args, **kwargs):
        return aes_key_wrap(key, cek)

    def decrypt(self, key, cek_ci, *args, **kwargs):
        return aes_key_unwrap(key, cek_ci)


class A128KW(AesKeyEncryptor):
    pass


class A192KW(AesKeyEncryptor):
    pass


class A256KW(AesKeyEncryptor):
    pass


### Content Encryption

_BS = 16
pkcs5_pad = lambda s: s + (_BS - len(s) % _BS) * chr(_BS - len(s) % _BS)
pkcs5_unpad = lambda s: s[0:-ord(s[-1])]
to_al = lambda x:  pack("!Q", 8 * len(x))


class AesContentEncrypor(BaseContentEncryptor):
    ''' AES_CBC_HMAC_SHA2 (Jwa 5.2)

    '''

    def unpack_key(self, cek):
        return (
            cek[:self._MAC_KEY_LEN],
            cek[-1 * self._ENC_KEY_LEN:]
        )

    def mac_input(self, ciphert, iv, assoc):
        al = to_al(assoc)
        return assoc + iv + ciphert + al

    def make_tag(self, mac_k, ciphert, iv, aad):
        mac_i = self.mac_input(ciphert, iv, aad)
        hmac = HMAC.new(mac_k, digestmod=self._HASH)
        hmac.update(mac_i)
        return hmac.digest()[:self._TAG_LEN]

    def encrypt(self, cek, plaint, iv, aad):
        mac_k, enc_k = self.unpack_key(cek)
        ci = AES.new(enc_k, AES.MODE_CBC, iv)
        ciphert = ci.encrypt(pkcs5_pad(plaint))
        tag = self.make_tag(mac_k, ciphert, iv, aad)

        return (ciphert, tag)

    def decrypt(self, cek, ciphert, iv, aad, tag):
        mac_k, enc_k = self.unpack_key(cek)
        if tag != self.make_tag(mac_k, ciphert, iv, aad):
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

    from jose.utils import base64
    for enc in [A128CBC_HS256, A192CBC_HS384, A256CBC_HS512]:
        cek, iv = enc.create_key_iv()
        assert len(cek) == enc._KEY_LEN
        assert len(iv) == enc._IV_LEN
        print enc.__name__
        print "CEK =", base64.urlsafe_b64encode(cek)
        print "IV=", base64.urlsafe_b64encode(iv)
