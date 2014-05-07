from jose import conf, BaseEnum, BaseObject
from jose.jwa import keys        # , Algorithm
from jose.utils import merged
#
#import traceback


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


class Jwk(BaseObject, keys.RSA, keys.EC, keys.Symmetric):
    _fields = merged([_material, _header])

    def __init__(self, key=None, **kwargs):
        super(Jwk, self).__init__(**kwargs)

        if key:
            self._key = key
            self._key.to_jwk(self)

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
        if kid:
            self.kid = kid
        elif not self.kid and self.key:
            self.kid = conf.generate_kid(self.kty, self.key.length)

    def add_to(self, owner, jku):
        jwkset = JwkSet.load(owner, jku) or JwkSet()
        jwkset.add_key(self)
        jwkset.save(owner, jku)

    def delete_from(self, owner, jku):
        jwkset = JwkSet.load(owner, jku) or JwkSet()
        jwkset.delete_key(self)
        jwkset.save(owner, jku)

    @classmethod
    def get_from(cls, owner, jku, kty, kid=None, **kwargs):
        return (JwkSet.load(owner, jku) or JwkSet()
                ).get_key(kty, kid, **kwargs)

    @classmethod
    def get_or_create_from(cls, owner, jku, kty, kid=None, **kwargs):
        key = cls.get_from(owner, jku, kty, kid, **kwargs)
        if key:
            return key
        key = cls.generate(kty=kty, **kwargs)
        key.add_to(owner, jku)
        return key


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

        for key in self.keys:
            if key.kty == kty:
                if not kid or key.kid == kid:
                    return key
                if not x5t or key.x5t == x5t:
                    return key
        return None

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
