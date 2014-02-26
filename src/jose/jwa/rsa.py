from Crypto.PublicKey import RSA
from jose.utils import base64
from jose import BaseKey

# https://www.dlitz.net/software/pycrypto/api/current/
#   Crypto.PublicKey.RSA.RSAImplementation-class.html


def public_construct(n, e):
    return RSA.RSAImplementation().construct((n, e,))


def private_construct(n, e, d, p, q, u):
    return RSA.RSAImplementation().construct((n, e, d, p, q, u,))


def generate_key(bits=1024):
    return RSA.generate(bits)


class Key(BaseKey):

    @classmethod
    def generate(cls, key_pair, bits=1024, **kwargs):
        pri = RSA.generate(bits)
        pub = pri.publickey()

        key_pair.pri.n = base64.long_to_b64(pri.n)
        key_pair.pri.e = base64.long_to_b64(pri.e)
        key_pair.pri.d = base64.long_to_b64(pri.d)
        key_pair.pri.p = base64.long_to_b64(pri.p)
        key_pair.pri.q = base64.long_to_b64(pri.q)
        key_pair.pri.qi = base64.long_to_b64(pri.u)

        key_pair.pub.n = base64.long_to_b64(pub.n)
        key_pair.pub.e = base64.long_to_b64(pub.e)

        return key_pair

    def signing_key(self):
        return self.jwk and private_construct(
            *[base64.long_from_b64(i) for i
              in [self.jwk.n, self.jwk.e,
                  self.jwk.d, self.jwk.p, self.jwk.q, self.jwk.qi]]
        )

    def verifying_key(self):
        return self.jwk and public_construct(
            *[base64.long_from_b64(i) for i in [self.jwk.n, self.jwk.e]]
        )

    def encrypting_key(self):
        return self.verifying_key()

    def decrypting_key(self):
        return self.signing_key()


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
