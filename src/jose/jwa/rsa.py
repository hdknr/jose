from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Signature import PKCS1_v1_5, PKCS1_PSS
from Crypto.Cipher import (
    PKCS1_v1_5 as PKCS1_v1_5_ENC,
    PKCS1_OAEP
)
from Crypto import Random
#
from jose.utils import base64, _BE, _BD, _LBE, _LBD
from jose import BaseKey, BaseKeyEncryptor
from jose.jwk import Jwk
from jose.jwa import keys


_sentinel = Random.get_random_bytes(32)

# https://www.dlitz.net/software/pycrypto/api/current/
#   Crypto.PublicKey.RSA.RSAImplementation-class.html


def public_construct(n, e):
    return RSA.RSAImplementation().construct((n, e,))


def private_construct(n, e, d, p, q, u):
    return RSA.RSAImplementation().construct((n, e, d, p, q, u,))


def generate_key(bits=1024):
    return RSA.generate(bits)


class Key(BaseKey):

    def init_material(self, length=2048, **kwargs):
        length = length or 2048
        self.material = RSA.generate(length)

    @property
    def length(self):
        return len(_BD(_LBE(self.material.n))) * 8

    def to_jwk(self, jwk):
        jwk.kty = keys.KeyTypeEnum.RSA
        jwk.n = _LBE(self.material.n)
        jwk.e = _LBE(self.material.e)
        if self.is_private:
            jwk.d = _LBE(self.material.d)
            jwk.p = _LBE(self.material.p)
            jwk.q = _LBE(self.material.q)
            jwk.qi = _LBE(self.material.u)

    def from_jwk(self, jwk):
        if jwk.d:   #: possibly private
            self.material = private_construct(
                *[_LBD(i) for i in [
                    jwk.n, jwk.e,
                    jwk.d, jwk.p, jwk.q, jwk.qi,
                ]]
            )
        else:
            self.material = public_construct(
                *[_LBD(i) for i in [
                    jwk.n, jwk.e,
                ]]
            )

    @property
    def public_tuple(self):
        if self.material is None:
            return ()

        return (self.material.n, self.material.e, )

    @property
    def private_tuple(self):
        if self.material is None or self.is_public:
            return ()

        return (self.material.n, self.material.e,
                self.material.d, self.material.p,
                self.material.q, self.material.u, )

    @property
    def private_jwk(self):
        if not self.material:
            return None

        jwk = Jwk(
            kty="RSA",
            n=base64.long_to_b64(self.material.n),
            e=base64.long_to_b64(self.material.e),
            d=base64.long_to_b64(self.material.d),
            p=base64.long_to_b64(self.material.p),
            q=base64.long_to_b64(self.material.q),
            qi=base64.long_to_b64(self.material.u),
        )
        return jwk

    @property
    def public_jwk(self):
        if not self.material:
            return None
        jwk = Jwk(
            kty="RSA",
            n=base64.long_to_b64(self.material.n),
            e=base64.long_to_b64(self.material.e),
        )
        return jwk

    @property
    def private_key(self):
        return self.is_private and self.material or None

    @property
    def public_key(self):
        if self.is_public:
            return self.material
        if self.is_private:
            return self.material.publickey()
        return None

    @property
    def is_private(self):
        return self.material is not None and \
            self.material.d is not None

    @property
    def is_public(self):
        return self.material is not None and \
            (not hasattr(self.material, 'd') or
             not self.material.d)


class RsaSigner(object):

    @classmethod
    def digest(cls, data):
        return cls._digester.new(data).digest()

    @classmethod
    def hexdigest(cls, data):
        return cls._digester(data).hexdigest()

    @classmethod
    def sign(cls, jwk, data):
        assert jwk.key is not None and jwk.key.is_private
        dig = cls._digester.new(data)
        signer = cls._signer.new(jwk.key.private_key)
        signature = signer.sign(dig)
        return signature

    @classmethod
    def verify(cls, jwk, data, signature):
        assert jwk.key is not None
        dig = cls._digester.new(data)
        verifier = cls._signer.new(jwk.key.public_key)
        return 1 == verifier.verify(dig, signature)


class RS256(RsaSigner):
    _digester = SHA256
    _signer = PKCS1_v1_5


class RS384(RsaSigner):
    _digester = SHA384
    _signer = PKCS1_v1_5


class RS512(RsaSigner):
    _digester = SHA512
    _signer = PKCS1_v1_5


class PS256(RsaSigner):
    ''' RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    '''
    _digester = SHA256
    _signer = PKCS1_PSS


class PS384(RsaSigner):
    ''' RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    '''
    _digester = SHA384
    _signer = PKCS1_PSS


class PS512(RsaSigner):
    ''' RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    '''
    _digester = SHA512
    _signer = PKCS1_PSS


## Key Encryption

class RsaKeyEncryptor(BaseKeyEncryptor):
    @classmethod
    def encrypt(cls, jwk, cek, *args, **kwargs):
        return cls._cipher.new(jwk.key.public_key).encrypt(cek)

    @classmethod
    def provide(cls, jwk, jwe, cek=None, iv=None, *args, **kwargs):
        kek = None  #: No Key Encryption Key in RSA Key Wrapping
        if cek:
            #: TODO:chekc iv is valid
            pass
        else:
            cek, iv = jwe.enc.encryptor.create_key_iv()
        cek_ci = cls.encrypt(jwk, cek)
        return cek, iv, cek_ci, kek

    @classmethod
    def agree(cls, jwk, jwe, cek_ci, *args, **kwargs):
        return cls.decrypt(jwk, cek_ci)


class RSA1_5(RsaKeyEncryptor):
    _cipher = PKCS1_v1_5_ENC

    @classmethod
    def decrypt(cls, jwk, cek_ci, *args, **kwargs):
        assert isinstance(jwk, Jwk)
        assert Jwk.is_private
        ret = cls._cipher.new(jwk.key.private_key).decrypt(cek_ci, _sentinel)
        if ret == _sentinel:
            return None
        return ret


class RSA_OAEP(RsaKeyEncryptor):
    _cipher = PKCS1_OAEP

    @classmethod
    def decrypt(cls, jwk, cek_ci, *args, **kwargs):
        return cls._cipher.new(jwk.key.private_key).decrypt(cek_ci)

if __name__ == '__main__':
    from jose.jwe import Jwe
    from jose.jwa.keys import KeyTypeEnum

    jwk = Jwk.generate(kty=KeyTypeEnum.RSA)
    jwe = Jwe.from_json('{"alg": "RSA1_5", "enc": "A128CBC-HS256"}')
    cek, iv, cek_ci = jwe.provide_key(jwk)

    print "CEK", base64.base64url_encode(cek)
    print "IV", base64.base64url_encode(iv)
    print "CEK_CI", base64.base64url_encode(cek_ci)

    cek2 = jwe.agree_key(cek_ci, jwk)
    print "CEK2", base64.base64url_encode(cek_ci)
    print "IV", base64.base64url_encode(iv)

    assert cek == cek2
