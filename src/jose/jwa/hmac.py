from Crypto.Hash import HMAC, SHA256, SHA384, SHA512


class HmacSigner(object):
    def digest(self, jwk, data):
        mac = HMAC.new(jwk.key.shared_key,
                       digestmod=self._digester)
        mac.update(data)
        return mac.digest()

    def sign(self, jwk, data):
        assert jwk.key is not None and jwk.key.shared_key
        return self.digest(jwk, data)

    def verify(self, jwk, data, signature):
        assert jwk.key is not None and jwk.key.shared_key
        return self.digest(jwk, data) == signature


class HS256(HmacSigner):
    _digester = SHA256


class HS384(HmacSigner):
    _digester = SHA384


class HS512(HmacSigner):
    _digester = SHA512
