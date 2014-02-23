from crypto import Crypto
from jose import BaseObject, base64
from jwa.sigs import Signature
import re
import traceback

_component = [
    r'^(?P<header>[^\.]+)',
    r'(?P<payload>[^\.]+)',
    r'(?P<signature>[^\.]+)$',
]

_compact = re.compile('\\.'.join(_component))


class _Signature(BaseObject):
    protected = ''      #: base64url(utf8(JWS Protected Header))
    header = None       #: Json object of Header Claims
    signature = ''      #: base64url(utf8(JWS Signature))

    def __init__(self, protected='', header=None, signature='',
                 *args, **kwargs):
        super(_Signature, self).__init__(*args, **kwargs)

        if protected:
            if isinstance(protected, str):
                self.protected = Jws.from_json(
                    base64.base64url_decode(protected))
            elif isinstance(protected, Jws):
                self.protectd = protected

        if isinstance(header, dict):
            self.header = Jws(**dict)
        elif isinstance(header, Jws):
            self.header = header
        elif isinstance(header, str):
            _json = base64.base64url_decode(header)
            self.header = Jws.from_json(_json)

        self.signature = signature

    def to_jws(self):
        #: merge protected and header(public)
        #: TODO: implement later
        return self.header


class JwsMessage(BaseObject):
    payload = ''        #: Base64url(Jws Payload)
    signatures = []     #: array of _Signature
    _jws_list = []      #: list of Jws

    def __init__(self, payload='', signatures=[], *args, **kwargs):
        super(JwsMessage, self).__init__(*args, **kwargs)
        self.payload = payload
        if isinstance(signatures, list):
            self.signatures = signatures
            self._jws_list = [s.to_jws() for s in self.signatures
                              if isinstance(s, _Signature)]

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        if isinstance(obj.signatures, list):
            obj.signature = [_Signature(**val)
                             for val in obj.signature
                             if isinstance(val, dict)]
            #: TODO:
            #: re-construct list of Jws
            #: and return

        return obj

    @property
    def jws_list(self):
        return self._jws_list

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
            obj = cls(signatures=[_Signature(**m)], **m)
            return obj
        except Exception, e:
            print type(e), e
            print traceback.format_exc()

        return None

    def to_token(self):
        return ''


class Jws(Crypto):
    #: All members are defined in Cryptpo

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        obj.alg = obj.alg and Signature.create(obj.alg)
        return obj

    def to_token(self):
        return ''
