from Crypto.PublicKey import RSA
from jose.utils import base64
from jose import BaseKey

# https://www.dlitz.net/software/pycrypto/api/current/
#   Crypto.PublicKey.RSA.RSAImplementation-class.html


def public_construct(n, e):
    return RSA.RSAImplementation().construct((n, e,))


def private_construct(n, e, d, p, q, u):
    return RSA.RSAImplementation().construct((n, e, d, p, q, u,))


class Key(BaseKey):

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
