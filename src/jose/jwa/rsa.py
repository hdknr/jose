from Crypto.PublicKey import RSA
from jose.utils import base64
from jose import BaseKey
from jose.jwk import Jwk

# https://www.dlitz.net/software/pycrypto/api/current/
#   Crypto.PublicKey.RSA.RSAImplementation-class.html


def public_construct(n, e):
    return RSA.RSAImplementation().construct((n, e,))


def private_construct(n, e, d, p, q, u):
    return RSA.RSAImplementation().construct((n, e, d, p, q, u,))


def generate_key(bits=1024):
    return RSA.generate(bits)


class Key(BaseKey):

    def from_jwk(self, jwk):
        if jwk.d:   #: possibly private
            self.material = private_construct(
                *[base64.long_from_b64(i) for i in [
                    jwk.n, jwk.e,
                    jwk.d, jwk.p, jwk.q, jwk.qi,
                ]]
            )
        else:
            self.material = public_construct(
                *[base64.long_from_b64(i) for i in [
                    jwk.n, jwk.e,
                ]]
            )

    def init_material(self, bits=1024, **kwargs):
        self.material = RSA.generate(bits)

    @property
    def public_tuple(self):
        if self.material is None:
            return ()

        return (self.material.n, self.material.e, )

    @property
    def private_tuple(self):
        if self.material is None or self.is_public:
            return ()

        return (self.material.n, self.material.e,
                self.material.d, self.material.p,
                self.material.q, self.material.u, )

    @property
    def private_jwk(self):
        if not self.material:
            return None

        jwk = Jwk(
            n=base64.long_to_b64(self.material.n),
            e=base64.long_to_b64(self.material.e),
            d=base64.long_to_b64(self.material.d),
            p=base64.long_to_b64(self.material.p),
            q=base64.long_to_b64(self.material.q),
            qi=base64.long_to_b64(self.material.u),
        )
        return jwk

    @property
    def public_jwk(self):
        if not self.material:
            return None
        jwk = Jwk(
            n=base64.long_to_b64(self.material.n),
            e=base64.long_to_b64(self.material.e),
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
            return self.material.publickey()
        return None

    @property
    def is_private(self):

        return self.material is not None and \
            self.material.d is not None

    @property
    def is_public(self):
        return self.material is not None and \
            self.material.d is None


class RS256(object):
    pass


class RS384(object):
    pass


class RS512(object):
    pass


class PS256(object):
    pass


class PS384(object):
    pass


class PS512(object):
    pass
