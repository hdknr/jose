from jose import BaseKey
from jose.utils import base64
from jose.jwk import Jwk
from jose.jwa.keys import CurveEnum
from ecdsa import NIST521p, NIST384p, NIST256p, SigningKey
from ecdsa.ecdsa import curve_521, curve_384, curve_256
from ecdsa.ellipticcurve import Point
from ecdsa.ecdsa import Public_key, Private_key

# each curver hast .curve nad .generator
CURVE = dict(
    P_256=NIST256p,
    P_384=NIST384p,
    P_521=NIST521p,
)


_CRV = lambda c: {
    curve_256: CurveEnum.P_256,
    curve_384: CurveEnum.P_384,
    curve_521: CurveEnum.P_521,
}[c].value


def create_point(curve, x, y):
    return Point(curve.curve, x, y)


def create_pubkey(curve, point):
    return Public_key(curve.generator, point)


def create_prikey(pubkey, secret_multiplier):
    return Private_key(pubkey, secret_multiplier)


class Key(BaseKey):

    def from_jwk(self, jwk):

        point = create_point(
            jwk.crv.get_curve(),
            base64.long_from_b64(jwk.x),
            base64.long_from_b64(jwk.y),
        )

        pubkey = create_pubkey(jwk.crv.get_curve(), point)
        if jwk.d:
            self.material = create_prikey(pubkey, base64.long_from_b64(jwk.d))
        else:
            self.material = pubkey

    def init_material(self, curve=None, **kwargs):
        if isinstance(curve, basestring):
            curve = CurveEnum.create(curve)
        if curve:
            key = SigningKey.generate(curve.get_curve())
            self.material = key.privkey

    @property
    def public_tuple(self):
        key = self.public_key
        if not key:
            return ()

        return(_CRV(key.curve), key.point.x(), key.point.y(), )

    @property
    def private_tuple(self):
        if not self.is_private:
            return ()

        return self.public_tuple + (self.material.secret_multiplier,)

    @property
    def private_jwk(self):
        jwk = self.public_jwk
        if jwk:
            jwk.d = base64.long_to_b64(self.material.secret_multiplier)
        return jwk

    @property
    def public_jwk(self):
        key = self.public_key
        if not key:
            return None

        jwk = Jwk(
            crv=_CRV(key.curve),
            x=base64.long_to_b64(key.point.x()),
            y=base64.long_to_b64(key.point.y()),
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
            return self.material.public_key
        return None

    @property
    def is_private(self):
        return self.material is not None and \
            isinstance(self.material, Private_key)

    @property
    def is_public(self):
        return self.material is not None and \
            isinstance(self.material, Public_key)


class ES256(object):
    curve = NIST256p


class ES384(object):
    curve = NIST384p


class ES512(object):
    curve = NIST521p
