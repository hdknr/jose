from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
#from Crypto.Util.number import long_to_bytes
from struct import pack

### Key Encryption


class AesKeyEncryptor(object):
    pass


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


class AesContentEncrypor(object):
    ''' AES_CBC_HMAC_SHA2 (Jwa 5.2)

    '''
    _IV_LEN = 16

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
    _ENC_KEY_LEN = 16
    _MAC_KEY_LEN = 16
    _HASH = SHA256
    _TAG_LEN = 16


class A192CBC_HS384(AesContentEncrypor):
    ''' AES_192_CBC_HMAC_SHA_384 (Jwa 5.2.4)
    '''
    _ENC_KEY_LEN = 24
    _MAC_KEY_LEN = 24
    _TAG_LEN = 24       # Authentication Tag Length
    _HASH = SHA384


class A256CBC_HS512(AesContentEncrypor):
    ''' AES_256_CBC_HMAC_SHA_512 (Jwa 5.2.5)
    '''
    _ENC_KEY_LEN = 32
    _MAC_KEY_LEN = 32
    _HASH = SHA512
    _TAG_LEN = 32
