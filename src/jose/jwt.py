from jose import BaseObject


class Jwt(BaseObject):
    _fields = dict(
        iss=None,
        sub=None,
        aud=None,
        exp=None,
        nbf=None,
        iat=None,
        jti=None,
    )

    def __init__(self, **kwargs):
        super(Jwt, self).__init__(**kwargs)
