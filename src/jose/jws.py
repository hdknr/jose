from crypto import Crypto, CryptoMessage
from jose import BaseObject
from jose.utils import base64, _BE, _BD
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
        assert jwk
        assert signing_input
        assert self.alg == SigEnum.NONE or signature is not None

        signer = self.alg.signer
        return signer.verify(jwk, signing_input, signature)

    def create_message(self, payload):
        msg = Message(
            payload=_BE(payload),
            signatures=[Signature(protected=self)],
        )
        return msg


class Signature(BaseObject):
    _fields = dict(
        protected=None,    #: base64url(utf8(JWS Protected Header))
                           #: "protected" means it is used as AAD
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
                self._protected = Jws.from_json(_BD(self.protected))
            elif isinstance(self.protected, Jws):
                #: this case is for creating a new token.
                self._protected = self.protected

        if isinstance(self.header, dict):
            #: this case is for creating a new token.
            self.header = Jws(**self.header)

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

    def to_compact_token(self, payload, jwk):
        self.sign(payload, jwk)
        return ".".join([self.protected, _BE(payload), self.signature])

    def signing_input(self, b64_payload):
        b64_header = self.protected         # TODO: Check spec
        return ".".join([b64_header, b64_payload])

    def verify(self, b64_payload, jwk=None):
        s_input = self.signing_input(b64_payload)
        jws = self.to_jws()
        return jws.verify(s_input, _BD(self.signature), jwk)

    def sign(self, b64_payload, jwk):
        #: TODO: load key from store if signing_jwk  is None
        #: only self._protected is used for Jwk parameter

        jws = self.to_jws()
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

    def load_key(self, owner):
        jws = self.to_jws()
        return jws.load_key(owner)


class Message(CryptoMessage):
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
        jwk = signature.load_key(self.sender)
        signature.sign(self.payload, jwk)
        self.signatures.append(signature)

    @classmethod
    def from_token(cls, token, sender=None, receiver=None):
        '''
            :param token: Serialized Jws (JSON or Compact)
            :param str sender: Message sender identifier
        '''

        try:
            message = cls.from_json(token)
            message.sender = sender
            message.receiver = receiver
            return message

        except ValueError:
            #: fall to  compact serialization
            pass
        except Exception, e:
            print ">>>>>>", type(e)
            print traceback.format_exc()

        try:
            m = _compact.search(token).groupdict()
            obj = cls(sender=sender, receiver=receiver,
                      signatures=[Signature(**m)], **m)
            return obj
        except Exception, e:
            print ">>>>>>", type(e)
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
            jwk = sig.load_key(self.sender)
            ret = ret and sig.verify(_BD(self.payload), jwk)
        return ret

    def load_key(self, index):
        return self.signatures[index].load_key(
            self.sender)

    def serialize_json(self, jwk=None, **kwargs):
        ''' TODO: key shoudld be diffrent each other for
            each signature.
        '''
        for sig in self.signatures:
            sigjwk = jwk or sig.load_key(self.sender).private_jwk
            sig.sign(self.payload, sigjwk)

        return self.to_json(**kwargs)

    def serialize_compact(self, jwk=None):
        ''' use the very first of Signature object
            in "signatures list.
        '''
        assert self.payload
        jwk = jwk or self.load_key(0).private_jwk
        return self.signatures[0].to_compact_token(self.payload, jwk)
