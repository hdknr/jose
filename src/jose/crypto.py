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

# Key Identification
# - https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-28#section-6
# - https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-30#section-6
#
# 'x5t#S256' is stored in _customs dict and can be accessed thru obj['x5t#S256']

_key_hint_fields = dict(
    jku=None,      #: Uri to hosted JwkSet
    jwk=None,      #: Jwk
    kid=None,      #: Key Id of Jwk
    x5u=None,      #: Uri to hosted X.509
    x5c=None,      #: array of base64url DER X.509 Certificate
    x5t=None,      #: Thumprint of X.509 Certificate
)


class KeyOwner(object):
    def get_key(self, crypto, *args, **kwargs):  # Crypto instance
        raise NotImplemented()

#    def set_key(self, jwkset, *args, **kwargs):
#        raise NotImplemented()


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
            :type sender: KeyOwner or None
        '''

        # If pair wise keyset is required,
        # `jku` MUST include both parties identity.
        # e.g.: https://company.com/jwkset/a_division/a_customer.jwkset
        return owner.get_key(self)
        #        keyset = JwkSet.load(owner, self.jku, kid=self.kid, x5t=self.x5t) or JwkSet()
        #        return keyset.get_key(self.alg.key_type, self.kid, self.x5t)

    def set_value(self, key, value):
        if key in self._fields and value:
            setattr(self, key, value)

    @property 
    def key_type(self):
        return self.alg.key_type
    
    @classmethod
    def from_token(cls, token):
        return cls.from_json(_BD(token.split('.')[0]))


class CryptoMessage(BaseObject):
    def __init__(self, sender=None, receiver=None, *args, **kwargs):
        ''' 
            :type sender: KeyOwner or None
            :type receiver: KeyOwner or None
        '''
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
