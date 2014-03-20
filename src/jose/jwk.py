from jose import BaseEnum, BaseObject
from jose.jwa import keys        # , Algorithm
#


class UseEnum(BaseEnum):
    sig = 'sign'
    enc = 'enc'


class KeyOpsEnum(BaseEnum):
    sign = 'sign'
    verify = 'verify'
    encrypt = 'encrypt'
    decrypt = 'decrypt'
    wrap = 'wrapKey'
    unwrap = 'unwrapKey'
    deriveKey = 'deriveKey'
    deriveBits = 'deriveBits'

_super = dict(keys.RSA._fields, **keys.EC._fields)
_super = dict(_super, **keys.Symmetric._fields)


class Jwk(BaseObject, keys.RSA, keys.EC, keys.Symmetric):
    _fields = dict(
        _super,
        kty=None,     #: jwa.keys.KeyTypeEnum
        use=None,     #: UseEnum instance
        key_ops=[],   #: array of KeyOpsEnum
        alg=None,     #: jwa.Algorithm to generate a private key
        kid="",       #: Key ID
        x5u="",       #: X.509 Url
        x5c=[],       #: X.509 Chain
        x5t="",       #: X.509 Thumprint
    )

    def __init__(self, key=None, **kwargs):
        super(Jwk, self).__init__(**kwargs)

        if isinstance(self.kty, basestring):
            self.kty = keys.KeyTypeEnum.create(self.kty)

        if isinstance(self.use, basestring):
            self.use = UseEnum.create(self.use)

        if isinstance(self.crv, basestring):
            self.crv = keys.CurveEnum.create(self.crv)

        if isinstance(self.key_ops, list):
            self.key_ops = [KeyOpsEnum(**ops)
                            for ops in self.key_ops
                            if isinstance(ops, dict)]
        if key:
            key.to_jwk(self)

    @property
    def key(self):
        if not hasattr(self, "_key"):
            self._key = self.kty.create_key(jwk=self)
        return self._key

    @property
    def public_jwk(self):
        return self.key.public_jwk

    @property
    def private_jwk(self):
        return self.key.private_jwk

    @property
    def is_public(self):
        return self.key.is_public

    @property
    def is_private(self):
        return self.key.is_private

    @classmethod
    def generate(cls, kty=keys.KeyTypeEnum.RSA, *args, **kwargs):
        if isinstance(kty, basestring):
            kty = keys.KeyTypeEnum.create(kty)
        assert kty
        key = kty.create_key(*args, **kwargs)
        jwk = Jwk(kty=kty, key=key, **kwargs)
        return jwk


class JwkSet(BaseObject):
    _fields = dict(
        keys=[]     # JwkSet list
    )

    def __init__(self, *args, **kwargs):
        super(JwkSet, self).__init__(*args, **kwargs)
        if isinstance(self.keys, list) and self.keys:
            new_keys = []
            for key in self.keys:
                if isinstance(key, Jwk):
                    new_keys.append(key)
                if isinstance(key, dict):
                    new_keys.append(Jwk(**key))
            self.keys = new_keys

    def get(self, kty, kid=None):
        if not isinstance(self.keys, list) or len(self.keys) == 0:
            return None

        for key in self.keys:
            if key.kty == kty:
                if not kid or key.kid == kid:
                    return key
        return None
