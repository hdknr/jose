from crypto import Crypto, CryptoMessage
from jose.base import BaseObject, JoseException
from jose.utils import base64, _BD
from jose.jwa.sigs import SigEnum
import re
import traceback

_component = [
    r'^(?P<protected>[^\.]+)',
    r'(?P<payload>[^\.]+)',
    r'(?P<signature>[^\.]*)$',
]

_compact = re.compile('\\.'.join(_component))


class Jws(Crypto):
    #: All members are defined in Cryptpo

    def __init__(self, **kwargs):
        super(Jws, self).__init__(**kwargs)
        if isinstance(self.alg, basestring):
            self.alg = SigEnum.create(self.alg)

    def sign(self, signing_input, jwk):
        #: TODO: load key from store if signing_jwk  is None
        assert jwk is not None
        signer = self.alg.signer
        signature = signer.sign(jwk, signing_input)
        return signature

    def verify(self, signing_input, signature, jwk):
        #: TODO: load key from store if signing_jwk  is None

        if not jwk:
            raise JoseException("no jwk", self)

        if not signing_input: 
            raise JoseException("no signin input", self, signing_input, signature, jwk)

        if self.alg == SigEnum.NONE and signature:
            raise JoseException(
                "none but signature specified", 
                self, signing_input, signature, jwk)

        signer = self.alg.signer
        return signer.verify(jwk, signing_input, signature)


class Signature(BaseObject):
    _fields = dict(
        protected=None,    #: base64url(utf8(JWS Protected Header))
                           #: "protected" means it is used as AAD
        header=None,       #: Json object of Header Claims
        signature='',      #: base64url(utf8(JWS Signature))
    )

    _excludes = ['sender', ]

    def __init__(self, sender=None, **kwargs):
        super(Signature, self).__init__(**kwargs)

        self.sender = sender
        self._protected = None
        #: Jws object from self.protected
        #: becuase json serialization results could be different
        #: in each system and framework.

        if self.protected:
            if isinstance(self.protected, basestring):
                #: this case if for veryfing a given token.
                self._protected = Jws.from_json(_BD(self.protected))
            elif isinstance(self.protected, Jws):
                #: this case is for creating a new token.
                self._protected = self.protected

        if isinstance(self.header, dict):
            #: this case is for creating a new token.
            self.header = Jws(**self.header)

        elif isinstance(self.header, str):
            #: this case if for veryfing a given token.
            _json = _BD(self.header)
            self.header = Jws.from_json(_json)

        if not any([self._protected, self.header]):
            #: creating default
            self._protected = Jws(alg=SigEnum.RS256)

    def all_header(self):
        #: merge protected and header(public)
        return Jws.merge(self._protected, self.header)

    def signing_input(self, b64_payload):
        b64_header = self.protected         # TODO: Check spec
        return ".".join([b64_header, b64_payload])

    def verify(self, b64_payload, jwk=None):
        s_input = self.signing_input(b64_payload)
        jws = self.all_header()
        return jws.verify(s_input, _BD(self.signature), jwk)

    def sign(self, b64_payload, jwk):
        #: TODO: load key from store if signing_jwk  is None
        #: only self._protected is used for Jwk parameter

        jws = self.all_header()
        if not jws.kid:
            if jwk.kid:
                self.header.kid = jwk.kid
        else:
            assert jws.kid == jwk.kid

        self.render_protected()
        s_input = self.signing_input(b64_payload)

        self.signature = base64.base64url_encode(
            jws.sign(s_input, jwk))

    def render_protected(self):
        ''' convert "_protected" Jws object to
            "protected" in BASE64URL encoded string
        '''
        if self._protected:
            self.protected = base64.base64url_encode(
                self._protected.to_json())

    def load_key(self):
        jws = self.all_header()
        return jws.load_key(self.sender)


class Message(CryptoMessage):
    _fields = dict(
        payload='',     # Base64url(Jws Payload)
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

    def header(self, index=0):
        return self.signatures[index].all_header()

    def add_signature(self, sender=None, protected=None, header=None):
        signature = Signature(
            sender=sender,
            protected=protected, header=header)

        jwk = signature.load_key()
        signature.sign(self.payload, jwk)
        self.signatures.append(signature)

    def text(self):
        return _BD(self.payload)

    @classmethod
    def from_token(cls, token, sender=None, receiver=None):
        '''
            :param token: Serialized Jws (JSON or Compact)
            :param str sender: Message sender identifier
        '''

        try:
            message = cls.from_json(token)
            for sig in message.signatures:
                sig.sender = sender

            return message

        except ValueError:
            #: fall to  compact serialization
            pass
        except Exception, e:
            print ">>>>>>", type(e)
            print traceback.format_exc()

        return cls.parse_token(token, sender, receiver)

    @classmethod
    def parse_token(cls, token, sender=None, recipient=None):
        '''
            :param token: Serialized Jws (JSON or Compact)
            :param str sender: Message sender identifier
        '''

        try:
            m = _compact.search(token).groupdict()
            obj = cls(signatures=[Signature(sender=sender, **m)], **m)
            return obj
        except Exception, e:
            print ">>>>>> jws.Message.parse_token", type(e)
            print traceback.format_exc()

        return None

    def verify(self):
        '''
        .. warning:
            Because every signature MAY be signed
            with each private key,
            pubulic key MUST be located by Jws header
            information.
        '''

        ret = True
        for sig in self.signatures:
            jwk = sig.load_key()
            ret = ret and sig.verify(self.payload, jwk)

        return ret

    def serialize_json(self, jwk=None, **kwargs):
        ''' TODO: key shoudld be diffrent each other for
            each signature.
        '''
        for sig in self.signatures:
            sigjwk = jwk or sig.load_key().private_jwk
            sig.sign(self.payload, sigjwk)

        return self.to_json(**kwargs)

    def serialize_compact(self, index=0, jwk=None):
        ''' use the very first of Signature object
            in "signatures list.
        '''
        sig = self.signatures[index]

        assert self.payload
        jwk = jwk or sig.load_key()

        sig.sign(self.payload, jwk)
        return ".".join([
            sig.protected,
            self.payload,
            sig.signature,
        ])
