from Crypto.Util.number import long_to_bytes, bytes_to_long
from aes_gcm import AES_GCM, InvalidTagException
from jose import BaseContentEncryptor, BaseKeyEncryptor
from jose.utils import base64


# Content Encryption

class GcmContentEncryptor(BaseContentEncryptor):
    _IV_LEN = 12    # octs -> 96bits
    _TAG_LEN = 16   # octs -> 128bits

    @classmethod
    def encrypt(cls, cek, plaint, iv, aad, *args, **kwargs):
        assert cek and len(cek) == cls._KEY_LEN
        assert iv and len(iv) == cls._IV_LEN

        ci = AES_GCM(bytes_to_long(cek))
        ciphert, tag = ci.encrypt(bytes_to_long(iv), plaint,  aad)

        return ciphert, long_to_bytes(tag)

    @classmethod
    def decrypt(cls, cek, ciphert, iv, aad, tag, *args,  **kwargs):
        assert cek and len(cek) == cls._KEY_LEN
        assert iv and len(iv) == cls._IV_LEN
        assert tag and len(tag) == cls._TAG_LEN

        ci = AES_GCM(bytes_to_long(cek))
        try:
            plaint = ci.decrypt(bytes_to_long(iv), ciphert,
                                bytes_to_long(tag), aad)
            return plaint, True
        except InvalidTagException:
            return (None, False)


class GCMA128(GcmContentEncryptor):
    _KEY_LEN = 16   # octs -> 128bits


class GCMA192(GcmContentEncryptor):
    _KEY_LEN = 24   # octs -> 192bits


class GCMA256(GcmContentEncryptor):
    _KEY_LEN = 32   # octs -> 256bits


# Key Encryption


class GcmKeyEncryptor(BaseKeyEncryptor):
    @classmethod
    def provide(cls, jwk, jwe, *args, **kwargs):
        key = jwk.key.shared_key[:cls._enc._KEY_LEN]
        cek, iv = cls._enc.create_key_iv()
        cek_ci, tag = cls._enc.encrypt(key, cek, iv, "")

        jwe.iv = base64.base64url_encode(iv)
        jwe.tag = base64.base64url_encode(tag)

        return (cek, iv, cek_ci)

    @classmethod
    def agree(cls, jwk, jwe, cek_ci, *args, **kwargs):
        key = jwk.key.shared_key[:cls._enc._KEY_LEN]
        assert isinstance(jwe.iv, basestring)
        assert isinstance(jwe.tag, basestring)
        _iv = base64.base64url_decode(jwe.iv)
        _tag = base64.base64url_decode(jwe.tag)
        cek, isv = cls._enc.decrypt(key, cek_ci, _iv, "", _tag)
        return cek


class GCMA128KW(GcmKeyEncryptor):
    _enc = GCMA128


class GCMA192KW(GcmKeyEncryptor):
    _enc = GCMA192


class GCMA256KW(GcmKeyEncryptor):
    _enc = GCMA192


if __name__ == '__main__':

    from jose.jwa.encs import KeyEncEnum, EncEnum

    encs = ['A128GCM', 'A192GCM', 'A256GCM']
    algs = ['A128GCMKW', 'A192GCMKW', 'A256GCMKW']

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
