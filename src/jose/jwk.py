from jose import BaseEnum, BaseObject
from jwa import keys    # , Algorithm
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


class Jwk(BaseObject, keys.RSA, keys.EC, keys.Symmetric):
    _fields = dict(
        kty=None,      #: jwa.keys.KeyType
        use=None,     #: UseEnum instance
        key_ops=[],   #: array of KeyOpsEnum
        alg=None,     #: jwa.Algorithm to generate a private key
        kid="",       #: Key ID
        x5u="",       #: X.509 Url
        x5c=[],       #: X.509 Chain
        x5t="",       #: X.509 Thumprint
    )

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        obj.kty = keys.KeyTypeEnum.create(obj.kty)
        obj.use = UseEnum.create(obj.use)
        if isinstance(obj.key_ops, list):
            obj.key_ops = [KeyOpsEnum(**ops)
                           for ops in obj.key_ops
                           if isinstance(ops, dict)]

        return obj


class JwkSet(BaseObject):
    _fields = dict(
        keys=[]     # JwkSet list
    )

    def save(self):
        pass


class JwkPair(BaseObject):
    @classmethod
    def create_rsa_pair(bits=2048):
        return JwkPair()


class JwkPairSet(BaseObject):
    def __init__(self, entity_id):
        self.entity_id = entity_id
