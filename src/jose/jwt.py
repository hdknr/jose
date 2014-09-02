from jose.base import BaseObject
from jose.utils import _BD
from jose.crypto import Crypto
from datetime import datetime
import time
import pytz 
from dateutil.tz import tzlocal
import re

_ZONE = dict(utc=pytz.utc, local=tzlocal())
_TIME_FIELD = re.compile('^(?P<name>.+)_dt_(?P<zone>.+)$')


class Jwt(BaseObject):
    _fields = dict(
        iss=None,
        sub=None,
        aud=None,       # Audient: list(str) or str
        exp=None,
        nbf=None,
        iat=None,       # import time; time.gmtime()
        jti=None,
    )
    _excludes = ['verified']

    def __init__(self, verified=False, **kwargs):
        super(Jwt, self).__init__(**kwargs)
        self.verified = verified

    def __getattr__(self, name):
        _names = _TIME_FIELD.search(name)
        _names = _names and _names.groupdict()
        _val = _names and getattr(self, _names['name'])
        _zone  = _names and _ZONE.get(_names['zone']) 

        if _val and _zone:
            return datetime.fromtimestamp(_val).replace(tzinfo=pytz.utc).astimezone(_zone)

        return self.__getattribute__(name)
    

    def is_available(self, me, epoch=None):
        epoch = epoch or int(time.time())   # UTC
        if self.exp and self.exp < epoch:
            return False
        if self.nbf and self.nbf > epoch:
            return False
        if isinstance(self.aud, basestring) and self.aud != me:
            return False
        elif isinstance(self.aud, list) and me not in self.aud:
            return False

        return True
            

    @classmethod
    def header(cls, token):
        return Crypto.from_token(token)

    @classmethod
    def parse(cls, token, sender, recipient):
        from jose.jwe import Message as JweMessage, NotJweException
        from jose.jws import Message as JwsMessage

        parts = token.split('.')
        if len(parts) < 2:
            # TODO: Define exception
            raise Exception("not JWT")

        try:
            obj = JweMessage.parse_token(token, sender, recipient) 
        except NotJweException:
            obj = JwsMessage.parse_token(token, sender, recipient)

        if not obj:
            return None

        verified = obj.verify() 

        header = obj.header()
        if header.cty == 'JWT':
            return cls.parse(obj.text(), sender, recipient)

        return obj and cls.from_json(obj.text(), verified=verified) or None
