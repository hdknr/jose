# Password-Based Encryption
# to encrypt CEK
#
# http://tools.ietf.org/html/rfc2898
#
# PBES2
# http://tools.ietf.org/html/rfc2898#section-6.2

from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto import Random
from pbkdf2 import PBKDF2
from jose import BaseKeyEncryptor
from jose.jwa.aes import A128KW, A192KW, A256KW
from jose.utils import base64


class Pbes2KeyEncryptor(BaseKeyEncryptor):
    @classmethod
    def key_length(cls):
        return cls._wrapper._KEY_LEN

    @classmethod
    def iv_length(cls):
        return cls._wrapper._IV_LEN

    @classmethod
    def derive(cls, jwk, salt, count, *args, **kwargs):
        salt = base64.base64url_decode(salt)
        return PBKDF2(jwk.key.shared_key, salt, count,
                      digestmodule=cls._digester,
                      macmodule=cls._mac).read(cls._wrapper._KEY_LEN)

    @classmethod
    def encrypt(cls, kek, cek):
        return cls._wrapper.kek_encrypt(kek, cek)

    @classmethod
    def decrypt(cls, kek, cek_ci):
        return cls._wrapper.kek_decrypt(kek, cek_ci)

    @classmethod
    def provide(cls, jwk, jwe, cek=None, iv=None, *args, **kwargs):
        if cek:
            #: TODO: Check iv is valid or not
            pass
        else:
            cek, iv = jwe.enc.encryptor.create_key_iv()

        jwe.p2s = jwe.p2s or base64.base64url_encode(
            Random.get_random_bytes(cls._wrapper._KEY_LEN))
        jwe.p2c = jwe.p2c or 1024

        kek = cls.derive(jwk, jwe.p2s, jwe.p2c, *args, **kwargs)
        cek_ci = cls.encrypt(kek, cek)

        return cek, iv, cek_ci, kek

    @classmethod
    def agree(cls, jwk, jwe, cek_ci, *args, **kwargs):
        kek = cls.derive(jwk, jwe, *args, **kwargs)
        return cls.decrypt(kek, cek_ci)


class PBES2_HS256_A128KW(Pbes2KeyEncryptor):
    _digester = SHA256
    _mac = HMAC
    _wrapper = A128KW


class PBES2_HS384_A192KW(Pbes2KeyEncryptor):
    _digester = SHA384
    _mac = HMAC
    _wrapper = A192KW


class PBES2_HS512_A256KW(Pbes2KeyEncryptor):
    _digester = SHA512
    _mac = HMAC
    _wrapper = A256KW


if __name__ == '__main__':

    from jose.jwa.encs import KeyEncEnum, EncEnum

    algs = ['PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW']
    encs = ['A128GCM', 'A192GCM', 'A256GCM']

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
        cek, iv, cek_ci, kek = jwe.provide_key(jwk)

        print "TESTING ---- :alg=", a, "enc=", e
        print "CEK=", base64.base64url_encode(cek)
        print "IV=", base64.base64url_encode(iv)
        print "CEK_CI=", base64.base64url_encode(cek_ci)
        print "Jwe.p2s=",  jwe.p2s
        print "Jwe.p2c=",  jwe.p2c
        print "KEY=", jwk.k
        print "KEK=", base64.base64url_encode(kek)

        cek2 = jwe.agree_key(jwk, cek_ci)

        print "CEK AGREED=", base64.base64url_encode(cek2)
        assert cek == cek2
