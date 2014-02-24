from crypto import Crypto
from jose import BaseObject, base64
from jwa.sigs import SigEnum
import re
import traceback
import copy

_component = [
    r'^(?P<protected>[^\.]+)',
    r'(?P<payload>[^\.]+)',
    r'(?P<signature>[^\.]+)$',
]

_compact = re.compile('\\.'.join(_component))


class Jws(Crypto):
    #: All members are defined in Cryptpo

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, base=cls)
        if hasattr(obj, 'alg'):
            obj.alg = obj.alg and SigEnum.create(obj.alg)
        return obj

    def merge(self, jws):
        res = copy.deepcopy(self)
        if jws:
            for k, v in jws.__dict__.items():
                if v:
                    setattr(res, k, v)
        return res


class Signature(BaseObject):
    _fields = dict(
        protected=None,    #: base64url(utf8(JWS Protected Header))
        header=None,       #: Json object of Header Claims
        signature='',      #: base64url(utf8(JWS Signature))
    )

    def __init__(self, **kwargs):
        super(Signature, self).__init__(**kwargs)

        if self.protected:
            if isinstance(self.protected, str):
                self.protected = Jws.from_json(
                    base64.base64url_decode(self.protected))

        if isinstance(self.header, dict):
            self.header = Jws(**dict)

        elif isinstance(self.header, str):
            _json = base64.base64url_decode(self.header)
            self.header = Jws.from_json(_json)

    def to_jws(self):
        #: merge protected and header(public)
        #: TODO: implement later
        return self.protected.merge(self.header)


class Message(BaseObject):
    _fields = dict(
        payload='',     # Base64url(Jws Payload
        signatures=[],  # array of Signature
    )

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        if isinstance(obj.signatures, list):
            obj.signature = [Signature(**val)
                             for val in obj.signature
                             if isinstance(val, dict)]
            #: TODO:
            #: re-construct list of Jws
            #: and return

        return obj

    @classmethod
    def from_token(cls, token):
        '''
            :param token: Serialized Jws (JSON or Compact)
        '''
        try:
            return cls.from_json(token)

        except Exception, e:
            print type(e), e

        try:
            m = _compact.search(token).groupdict()
            print "@@@@@@ token ", m
            obj = cls(signatures=[Signature(**m)], **m)
            return obj
        except Exception, e:
            print type(e), e
            print traceback.format_exc()

        return None

    def to_token(self):
        return ''
