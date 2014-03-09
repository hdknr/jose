from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Signature import PKCS1_v1_5
#
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
            kty=self.kty,
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
            kty=self.kty,
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
            (not hasattr(self.material, 'd') or
             not self.material.d)


class RsaSigner(object):

    def digest(self, data):
        return self._digester.new(data).digest()

    def hexdigest(self, data):
        return self._digester(data).hexdigest()

    def sign(self, jwk, data):
        assert jwk.key is not None and jwk.key.is_private
        dig = self._digester.new(data)
        signer = self._signer.new(jwk.key.private_key)
        signature = signer.sign(dig)
        return signature

    def verify(self, jwk, data, signature):
        assert jwk.key is not None
        dig = self._digester.new(data)
        verifier = self._signer.new(jwk.key.public_key)
        return verifier.verify(dig, signature)


class RS256(RsaSigner):
    _digester = SHA256
    _signer = PKCS1_v1_5


class RS384(RsaSigner):
    _digester = SHA384
    _signer = PKCS1_v1_5


class RS512(RsaSigner):
    _digester = SHA512
    _signer = PKCS1_v1_5


class PS256(object):
    pass


class PS384(object):
    pass


class PS512(object):
    pass


from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP


class RSA1_5(object):
    _padding = PKCS1_v1_5

    def get_cipher(self):
        pass


class RSA_OAEP(object):
    _padding = PKCS1_OAEP

    def get_cipher(self):
        pass
