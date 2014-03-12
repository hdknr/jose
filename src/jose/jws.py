from crypto import Crypto
from jose import BaseObject
from jose.utils import base64
from jose.jwa.sigs import SigEnum
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

    def __init__(self, **kwargs):
        super(Jws, self).__init__(**kwargs)
        if isinstance(self.alg, basestring):
            self.alg = SigEnum.create(self.alg)

    def merge(self, jws):
        res = copy.deepcopy(self)
        if jws:
            for k, v in jws.__dict__.items():
                if v:
                    setattr(res, k, v)
        return res

    def sign(self, signing_input, jwk=None):
        #: TODO: load key from store if signing_jwk  is None
        assert jwk is not None
        signer = self.alg.signer
        signature = signer.sign(jwk, signing_input)
        return signature

    def verify(self, signing_input, signature, jwk=None):
        #: TODO: load key from store if signing_jwk  is None
        assert jwk is not None
        signer = self.alg.signer
        return signer.verify(jwk, signing_input, signature)

    def create_message(self, payload):
        msg = Message(
            payload=base64.base64url_encode(payload),
            signatures=[Signature(protected=self)],
        )
        return msg


class Signature(BaseObject):
    _fields = dict(
        protected=None,    #: base64url(utf8(JWS Protected Header))
        header=None,       #: Json object of Header Claims
        signature='',      #: base64url(utf8(JWS Signature))
    )

    def __init__(self, **kwargs):
        super(Signature, self).__init__(**kwargs)

        self._protected = None
        #: Jws object from self.protected
        #: becuase json serialization results could be different
        #: in each system and framework.

        if self.protected:
            if isinstance(self.protected, basestring):
                #: this case if for veryfing a given token.
                self._protected = Jws.from_json(
                    base64.base64url_decode(self.protected))
            elif isinstance(self.protected, Jws):
                #: this case is for creating a new token.
                self._protected = self.protected

        if isinstance(self.header, dict):
            #: this case is for creating a new token.
            self.header = Jws(**dict)
        elif isinstance(self.header, str):
            #: this case if for veryfing a given token.
            _json = base64.base64url_decode(self.header)
            self.header = Jws.from_json(_json)

        if not any([self._protected, self.header]):
            #: creating default
            self._protected = Jws(alg=SigEnum.RS256)

    def to_jws(self):
        #: merge protected and header(public)
        return self._protected.merge(self.header)

    def to_compact_token(self, b64_payload, signing_jwk=None):
        self.sign(b64_payload, signing_jwk)
        return ".".join([self.protected, b64_payload, self.signature])

    def verify(self, b64_payload, verifying_jwk=None):
        b64_header = self.protected         # TODO: Check spec
        s_input = ".".join([b64_header, b64_payload])
        jws = self.to_jws()
        return jws.verify(
            s_input,
            base64.base64url_decode(self.signature),
            verifying_jwk)

    def sign(self, b64_payload, signing_jwk=None):
        #: TODO: load key from store if signing_jwk  is None
        #: only self._protected is used for Jwk parameter
        self.render_protected()
        jws = self.to_jws()
        b64_header = self.protected
        s_input = ".".join([b64_header, b64_payload])
        self.signature = base64.base64url_encode(
            jws.sign(s_input, signing_jwk))

    def render_protected(self):
        ''' convert "_protected" Jws object to
            "protected" in BASE64URL encoded string
        '''
        if self._protected:
            self.protected = base64.base64url_encode(
                self._protected.to_json())


class Message(BaseObject):
    _fields = dict(
        payload='',     # Base64url(Jws Payload
        signatures=[],  # array of Signature
    )

    def __init__(self, **kwargs):
        super(Message, self).__init__(**kwargs)
        if isinstance(self.signatures, list):
            sigs = []
            for sig in self.signatures:
                if isinstance(sig, dict):
                    sigs.append(Signature(**sig))
                elif isinstance(sig, Signature):
                    sigs.append(sig)
            self.signatures = sigs

    def add_signature(self, protected=None, header=None):
        signature = Signature(
            protected=protected, header=header)
        signature.sign(self.payload)
        self.append(signature)

    @classmethod
    def from_token(cls, token):
        '''
            :param token: Serialized Jws (JSON or Compact)
        '''

        try:
            return cls.from_json(token)

        except ValueError:
            #: fall to  compact serialization
            pass
        except Exception, e:
            print ">>>>>>", type(e)
            print traceback.format_exc()

        try:
            m = _compact.search(token).groupdict()
            obj = cls(signatures=[Signature(**m)], **m)
            return obj
        except Exception, e:
            print ">>>>>>", type(e)
            print traceback.format_exc()

        return None

    def verify(self, verify_key=None):
        '''
        .. warning:
            Because every signature MAY be signed
            with each private key,
            pubulic key MUST be located by Jws header
            information.
        '''
        return all(map(lambda sig: sig.verify(self.payload, verify_key),
                       self.signatures))

    def serialize_json(self, signing_jwk=None, **kwargs):
        ''' TODO: key shoudld be diffrent each other for
            each signature.
        '''
        for sig in self.signatures:
            sig.sign(self.payload, signing_jwk)

        return self.to_json(**kwargs)

    def serialize_compact(self, signing_jwk=None):
        ''' use the very first of Signature object
            in "signatures list.
        '''
        return self.signatures[0].to_compact_token(
            self.payload, signing_jwk)
