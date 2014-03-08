from jose import BaseKey
from jose.utils import base64
from jose.jwk import Jwk
from jose.jwa.keys import CurveEnum, KeyTypeEnum

from ecc.Key import Key as EccKey

_jwk_to_pub = lambda jwk: (
    jwk.crv.bits, (
        base64.long_from_b64(jwk.x),
        base64.long_from_b64(jwk.y),
    )
)
_jwk_to_pri = lambda jwk: (
    jwk.crv.bits,
    base64.long_from_b64(jwk.d)
)


class Key(BaseKey):

    def from_jwk(self, jwk):
        if jwk.d:
            self.material = EccKey(
                public_key=_jwk_to_pub(jwk),
                private_key=_jwk_to_pri(jwk))
        else:
            self.material = EccKey(public_key=_jwk_to_pub(jwk))

    def init_material(self, curve=None, **kwargs):
        ''' generate new key material '''
        if isinstance(curve, basestring):
            curve = CurveEnum.create(curve)
        if curve:
            self.material = EccKey.generate(curve.bits)

    @property
    def is_private(self):
        return self.material and self.material.private()

    @property
    def is_public(self):
        return self.material and not self.material.private()

    @property
    def private_key(self):
        return self.is_private and self.material or None

    @property
    def public_key(self):
        if self.is_public:
            return self.material
        if self.is_private:
            return EccKey.decode(self.material.encode())
        return None

    @property
    def public_tuple(self):
        self.material._pub

    @property
    def private_tuple(self):
        return self.material._priv if self.is_private else {}

    @property
    def public_jwk(self):
        key = self.public_key
        if not key:
            return None
        jwk = Jwk(
            kty=KeyTypeEnum.EC,
            crv=CurveEnum.create("P-{:d}".format(key._pub[0])),
            x=base64.long_to_b64(key._pub[1][0]),
            y=base64.long_to_b64(key._pub[1][1]),
        )
        return jwk

    @property
    def private_jwk(self):
        jwk = self.public_jwk
        if jwk:
            jwk.d = base64.long_to_b64(self.material._priv[1])
        return jwk


class ES256(object):
    pass


class ES384(object):
    pass


class ES512(object):
    pass
