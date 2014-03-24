from Crypto.Hash import HMAC, SHA256, SHA384, SHA512


class HmacSigner(object):
    @classmethod
    def digest(cls, jwk, data):
        mac = HMAC.new(jwk.key.shared_key,
                       digestmod=cls._digester)
        mac.update(data)
        return mac.digest()

    @classmethod
    def sign(cls, jwk, data):
        assert jwk.key is not None and jwk.key.shared_key
        return cls.digest(jwk, data)

    @classmethod
    def verify(cls, jwk, data, signature):
        assert jwk.key is not None and jwk.key.shared_key
        return cls.digest(jwk, data) == signature


class HS256(HmacSigner):
    _digester = SHA256


class HS384(HmacSigner):
    _digester = SHA384


class HS512(HmacSigner):
    _digester = SHA512


from jose import BaseKey
from jose.utils import _BE, _BD
from jose.jwk import Jwk
from Crypto import Random


class Key(BaseKey):

    def init_material(self, length=200, **kwargs):
        length = length or 200
        self.material = Random.get_random_bytes(length)

    @property
    def length(self):
        return len(self.shared_key)

    def to_jwk(self, jwk):
        jwk.k = _BE(self.material)

    def from_jwk(self, jwk):
        self.material = _BD(jwk.k)

    @property
    def public_tuple(self):
        if self.material is None:
            return ()

        return (self.material, )

    @property
    def private_tuple(self):
        return self.public_tuple()

    @property
    def private_jwk(self):
        jwk = Jwk(
            kty="oct",
            k=_BE(self.material),
        )
        return jwk

    @property
    def public_jwk(self):
        return None

    @property
    def private_key(self):
        return self.material

    @property
    def public_key(self):
        return self.material

    @property
    def is_private(self):
        return self.material is not None

    @property
    def is_public(self):
        return self.material is not None

    @property
    def shared_key(self):
        return self.material

if __name__ == '__main__':
    from jose.jwa.keys import KeyTypeEnum
    jwk = Jwk.generate(kty=KeyTypeEnum.create('oct'))
    assert len(jwk.key.shared_key) == 200

    jwk = Jwk.generate(kty=KeyTypeEnum.create('oct'), length=32)
    assert len(jwk.key.shared_key) == 32
