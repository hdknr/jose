from jose import BaseEnum, BaseObject
from jwa import keys        # , Algorithm
#
import requests


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

    def __init__(self, **kwargs):
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

    @property
    def material(self):
        return self.kty.create_key(jwk=self)

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        return obj

    @classmethod
    def from_uri(cls, uri):
        json_str = requests.get(uri).content
        return cls.from_json(json_str)

    @classmethod
    def from_uri_cache(cls, uri):
        return cls.load(uri) or cls.from_uri(uri)

    @property
    def public_jwk(self):
        return self.material.public_jwk

    @property
    def private_jwk(self):
        return self.material.private_jwk

    @property
    def is_public(self):
        return self.material.is_public

    @property
    def is_private(self):
        return self.material.is_private

    @classmethod
    def generate(cls, kty=keys.KeyTypeEnum.RSA, *args, **kwargs):
        key = kty.create_key()
        key.init_material(*args, **kwargs)
        return key.private_jwk


class JwkSet(BaseObject):
    _fields = dict(
        keys=[]     # JwkSet list
    )


#class JwkPair(BaseObject):
#
#    def __init__(self, pri=None, pub=None,
#                 kty=keys.KeyTypeEnum.RSA, **kwargs):
#
#        self.pri = pri or Jwk(kty=kty, **kwargs)
#        self.pub = pub or Jwk(kty=kty, **kwargs)
#
##        #if not pri:
##            kty.get_class().generate(self, **kwargs)
#
#
#class JwkPairSet(BaseObject):
#    def __init__(self, entity_id):
#        self.entity_id = entity_id
