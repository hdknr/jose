from jose import BaseObject


class Crypto(BaseObject):
    alg = None      #: Algorithm
    jku = None      #: Uri to hosted JwkSet
    jwk = None      #: Jwk
    kid = None      #: Key Id of Jwk
    x5u = None      #: Uri to hosted X.509
    x5c = None      #: array of base64url DER X.509 Certificate
    x5t = None      #: Thumprint of X.509 Certificate
    typ = None      #: Type of objects ciphered.
    cty = None      #: Content type of object
    crit = None     #: Critical

    @classmethod
    def from_token(cls, token):
        return None

    def to_token(self):
        raise NotImplemented


def from_token(token):
    from jws import Jws
    from jwe import Jwe

    crypto = Jws.from_token(token) or \
        Jwe.from_token(token)

    return crypto
