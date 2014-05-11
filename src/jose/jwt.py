from jose.base import BaseObject
from jose.utils import _BD
from jose.crypto import Crypto


class Jwt(BaseObject):
    _fields = dict(
        iss=None,
        sub=None,
        aud=None,       # Audient: list(str) or str
        exp=None,
        nbf=None,
        iat=None,
        jti=None,
    )

    def __init__(self, **kwargs):
        super(Jwt, self).__init__(**kwargs)

    @classmethod
    def header(cls, token):
        return Crypto.from_token(token)

    @classmethod
    def parse(cls, token, sender, recipient):
        from jose.jwe import Message as JweMessage
        from jose.jws import Message as JwsMessage
        parts = token.split('.')
        if len(parts) < 2:
            # TODO: Define exception
            raise Exception("not JWT")

        obj = JweMessage.parse_token(token, sender, recipient)
        if not obj:
            obj = JwsMessage.parse_token(token, sender, recipient)
            if not obj or not obj.verify():
                return None

        header = obj.header()
        if header.cty == 'JWT':
            return cls.parse(obj.text(), sender, recipient)

        return obj and Jwt.from_json(obj.text()) or None
