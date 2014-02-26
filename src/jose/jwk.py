from jose import BaseEnum, BaseObject
from jwa import keys        # , Algorithm
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

    def __init__(self, **kwargs):
        super(Jwk, self).__init__(**kwargs)

        if isinstance(self.kty, basestring):
            self.kty = keys.KeyTypeEnum.create(self.kty)

        if isinstance(self.use, basestring):
            self.use = UseEnum.create(self.use)

        if isinstance(self.key_ops, list):
            self.key_ops = [KeyOpsEnum(**ops)
                            for ops in self.key_ops
                            if isinstance(ops, dict)]

    def keyobject(self):
        return self.kty.get_class(self)

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        return obj


class JwkSet(BaseObject):
    _fields = dict(
        keys=[]     # JwkSet list
    )


class JwkPair(BaseObject):

    def __init__(self, pri=None, pub=None,
                 kty=keys.KeyTypeEnum.RSA, **kwargs):

        self.pri = pri or Jwk(kty=kty, **kwargs)
        self.pub = pub or Jwk(kty=kty, **kwargs)

        if not pri:
            kty.get_class().generate(self, **kwargs)


class JwkPairSet(BaseObject):
    def __init__(self, entity_id):
        self.entity_id = entity_id
