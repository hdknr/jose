from jose import BaseEnum, BaseObject
from jwa import keys    # , Algorithm
#


class Use(BaseEnum):
    sig = 'sign'
    enc = 'enc'


class KeyOperation(BaseEnum):
    sign = 'sign'
    verify = 'verify'
    encrypt = 'encrypt'
    decrypt = 'decrypt'
    wrap = 'wrapKey'
    unwrap = 'unwrapKey'
    deriveKey = 'deriveKey'
    deriveBits = 'deriveBits'


class Jwk(BaseObject, keys.RSA, keys.EC, keys.Symmetric):
    kty = None      #: jwa.keys.KeyType
    use = None      #: Use instance
    key_ops = []    #: array of KeyOperation
    alg = None      #: jwa.Algorithm to generate a private key
    kid = ""        #: Key ID
    x5u = ""        #: X.509 Url
    x5c = []        #: X.509 Chain
    x5t = ""        #: X.509 Thumprint

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        obj.kty = keys.KeyType.create(obj.kty)
        obj.use = Use.create(obj.use)
        if isinstance(obj.key_ops, list):
            obj.key_ops = [KeyOperation(**ops)
                           for ops in obj.key_ops
                           if isinstance(ops, dict)]

        return obj


class JwkSet(BaseObject):
    keys = []   #: List of Jwk (Section 4.1)

    def save(self):
        pass


class JwkPair(BaseObject):
    @classmethod
    def create_rsa_pair(bits=2048):
        return JwkPair()


class JwkPairSet(BaseObject):
    def __init__(self, entity_id):
        self.entity_id = entity_id
