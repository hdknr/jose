# from jose.base import conf, BaseEnum, BaseObject
from jose.base import (
    BaseEnum, BaseObject,
    BaseObjectSerializer,
)
from jose.jwa import keys        # , Algorithm
from jose.utils import merged, base64
import time
import struct
import json
import hashlib

#
# import traceback


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

_material = merged([
    keys.RSA._fields,
    keys.EC._fields,
    keys.Symmetric._fields])

_header = dict(
    kty=None,     #: jwa.keys.KeyTypeEnum
    use=None,     #: UseEnum instance
    key_ops=[],   #: array of KeyOpsEnum
    alg=None,     #: jwa.Algorithm to generate a private key
    kid="",       #: Key ID
    x5u="",       #: X.509 Url
    x5c=[],       #: X.509 Chain
    x5t="",       #: X.509 Thumprint
)


class ThumbprintSerializer(BaseObjectSerializer):

    def default(self, obj):
        if isinstance(obj, Jwk):
            return dict(
                (k, v) for k, v in obj.__dict__.items()
                if k in obj.key.thumbprint_fields())

        return super(ThumbprintSerializer, self).default(obj)


class Jwk(BaseObject, keys.RSA, keys.EC, keys.Symmetric):
    _fields = merged([_material, _header])

    def __init__(self, key=None, **kwargs):
        super(Jwk, self).__init__(**kwargs)

        if key:
            self._key = key
            self._key.to_jwk(self)

        self.kty = self.kty and keys.KeyTypeEnum(self.kty)
        self.use = self.use and UseEnum(self.use)
        print("@@@@@@ Jwk crv", self.crv)
        self.crv = self.crv and keys.CurveEnum(self.crv)

        if isinstance(self.key_ops, list):
            self.key_ops = [KeyOpsEnum(**ops)
                            for ops in self.key_ops
                            if isinstance(ops, dict)]

    def __eq__(self, other):
        if isinstance(other, Jwk):
            return self.key == other.key
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    @property
    def key(self):
        if not hasattr(self, "_key"):
            self._key = self.kty.create_key(jwk=self)
        return self._key

    @property
    def length(self):
        return self.key.length

    def clone(self, public=False):
        try:
            if public:
                new = self.key.public_jwk
            else:
                new = self.key.private_jwk

            for fld in _header:
                setattr(new, fld, getattr(self, fld, None))
            return new
        except:
            return None

    @property
    def public_jwk(self):
        return self.clone(public=True)

    @property
    def private_jwk(self):
        return self.clone(public=False)

    @property
    def is_public(self):
        return self.key.is_public

    @property
    def is_private(self):
        return self.key.is_private

    @classmethod
    def generate(cls, kty=keys.KeyTypeEnum.RSA, length=None, *args, **kwargs):
        if isinstance(kty, basestring):
            kty = keys.KeyTypeEnum.create(kty)
        assert kty

        key = kty.create_key(length=length, *args, **kwargs)
        jwk = Jwk(kty=kty, key=key, **kwargs)
        jwk.set_kid()
        return jwk

    def set_kid(self, kid=None):
        kid = kid or '-'.join([
            self.kty.name[0],
            struct.pack('H', self.length).encode('hex'),
            struct.pack('d', time.time()).encode('hex')])
        self.kid = kid

    def to_thumbprint_json(self):
        return json.dumps(
            self, cls=ThumbprintSerializer,
            separators=(',', ':'), sort_keys=True)

    def thumbprint(self):
        return base64.base64url_encode(
            hashlib.sha256(self.to_thumbprint_json()).digest())


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

    def get_key(self, kty, kid=None, x5t=None):
        if not isinstance(self.keys, list) or len(self.keys) == 0:
            return None

        default = None
        for key in self.keys:
            if key.kty == kty:
                if default is None:
                    default = key
                if kid and key.kid == kid:
                    return key
                if x5t and key.x5t == x5t:
                    return key
        return default

    def add_key(self, jwk):
        self.delete_key(jwk.kty, jwk.kid)
        self.keys.append(jwk)

    def delete_key(self, jwk=None, kty=None, kid=None, x5t=None):
        jwk = jwk or self.get_key(kty, kid, x5t)
        if jwk:
            self.keys = [key for key in self.keys if key != jwk]

    def select_key(self, selector=any, **kwargs):
        return [
            key for key in self.keys
            if selector([getattr(key, k, None) == v
                         for k, v in kwargs.items()])
        ]

    def index_key(self, jwk):
        return self.keys.index(jwk)

    @property
    def public_set(self):
        return JwkSet(
            keys=[key.public_jwk for key in self.keys])
