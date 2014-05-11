from jose.base import BaseObject
from jose.utils import merged, _BD
from jose.jwk import JwkSet
from jose.jwa.sigs import SigEnum
from jose.jwa.encs import KeyEncEnum


_crypto_fields = dict(
    alg=None,      #: Algorithm (KeyEncEnum, SigEnum)
    typ=None,      #: Type of objects ciphered.
    cty=None,      #: Content type of object
    crit=None,     #: Critical
)

_key_hint_fields = dict(
    jku=None,      #: Uri to hosted JwkSet
    jwk=None,      #: Jwk
    kid=None,      #: Key Id of Jwk
    x5u=None,      #: Uri to hosted X.509
    x5c=None,      #: array of base64url DER X.509 Certificate
    x5t=None,      #: Thumprint of X.509 Certificate
)


class Crypto(BaseObject):
    _fields = merged([
        _crypto_fields,
        _key_hint_fields,
    ])

    def __init__(self, **kwargs):
        super(Crypto, self).__init__(**kwargs)
        if isinstance(self.alg, basestring):
            self.alg = SigEnum.create(self.alg) or KeyEncEnum(self.alg)

    def load_key(self, owner):
        '''
            :param str owner: Owner identifier
        '''

        # If pair wise keyset is required,
        # `jku` MUST include both parties identity.
        # e.g.: https://company.com/jwkset/a_division/a_customer.jwkset
        keyset = JwkSet.load(owner, self.jku) or JwkSet()
        return keyset.get_key(self.alg.key_type, self.kid, self.x5t)

    def set_value(self, key, value):
        if key in self._fields and value:
            setattr(self, key, value)

    
    @classmethod
    def from_token(cls, token):
        return cls.from_json(_BD(token.split('.')[0]))
       


class CryptoMessage(BaseObject):
    def __init__(self, sender=None, receiver=None, *args, **kwargs):
        super(CryptoMessage, self).__init__(*args, **kwargs)
        self._sender = sender
        self._receiver = receiver

    @property
    def sender(self):
        return self._sender

    @sender.setter
    def sender(self, value):
        self._sender = value

    @property
    def receiver(self):
        return self._receiver

    @receiver.setter
    def receiver(self, value):
        self._receiver = value

    def seriaize_compact(self):
        raise NotImplemented()

    def seriaize_json(self, **kwargs):
        ''' kwargs can contain named args to json.dumps
        '''
        raise NotImplemented()

    def header(self, index=0):
        raise NotImplemented

    def text(self):
        raise NotImplemented

    @classmethod
    def parse_token(cls, sender, recipient):
        raise NotImplemented

    def veirfy(self):
        return False


def parse_message(token_or_json, sender, receiver):
    from jws import Jws
    from jwe import Jwe

    crypto = Jws.from_token(token_or_json, sender, receiver) or \
        Jwe.from_token(token_or_json, sender, receiver)
    return crypto

#def from_token(token, sender):
#    from jws import Jws
#    from jwe import Jwe
#
#    crypto = Jws.from_token(token) or \
#        Jwe.from_token(token)
#
#    return crypto
