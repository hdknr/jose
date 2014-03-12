from Crypto.Hash import HMAC, SHA256, SHA384, SHA512


class HmacSigner(object):
    @classmethod
    def digest(cls, jwk, data):
        mac = HMAC.new(jwk.key.shared_key,
                       digestmod=cls._digester)
        mac.update(data)
        return mac.digest()

    @classmethod
    def sign(cls, jwk, data):
        assert jwk.key is not None and jwk.key.shared_key
        return cls.digest(jwk, data)

    @classmethod
    def verify(cls, jwk, data, signature):
        assert jwk.key is not None and jwk.key.shared_key
        return cls.digest(jwk, data) == signature


class HS256(HmacSigner):
    _digester = SHA256


class HS384(HmacSigner):
    _digester = SHA384


class HS512(HmacSigner):
    _digester = SHA512
