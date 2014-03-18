from jose import BaseObject
from jose.jwk import JwkSet
import copy


class Crypto(BaseObject):
    _fields = dict(
        alg=None,      #: Algorithm
        jku=None,      #: Uri to hosted JwkSet
        jwk=None,      #: Jwk
        kid=None,      #: Key Id of Jwk
        x5u=None,      #: Uri to hosted X.509
        x5c=None,      #: array of base64url DER X.509 Certificate
        x5t=None,      #: Thumprint of X.509 Certificate
        typ=None,      #: Type of objects ciphered.
        cty=None,      #: Content type of object
        crit=None,     #: Critical
    )

    @classmethod
    def from_token(cls, token):
        return None

    def to_token(self):
        raise NotImplemented

    def load_key(self, owner):
        '''
            :param str owner: Owner identifier
        '''
        # If pair wise keyset is required,
        # `jku` MUST include both parties identity.
        # e.g.: https://company.com/jwkset/a_division/a_customer.jwkset
        keyset = JwkSet.load(owner, self.jku)
        return keyset.get(self.kty, self.kid)

    def merge(self, crypto):
        res = copy.deepcopy(self)
        if crypto and type(self) == type(crypto):
            for k, v in crypto.__dict__.items():
                if v:
                    setattr(res, k, v)
        return res


class CryptoMessage(BaseObject):
    def __init__(self, _sender=None, _receiver=None, *args, **kwargs):
        super(CryptoMessage, self).__init__(*args, **kwargs)
        self._sender = _sender
        self._receiver = _receiver

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
