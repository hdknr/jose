from crypto import Crypto
from jwa.encs import EncEnum, KeyEncEnum
from jose import BaseEnum, BaseObject
import re

_component = [
    r'^(?P<head>[^\.]+)',
    r'(?P<key>[^\.]+)',
    r'(?P<iv>[^\.]+)',
    r'(?P<ciphered>[^\.]+)',
    r'(?P<tag>[^\.]+)$',
]

_compact = re.compile('\.'.join(_component))


class ZipEnum(BaseEnum):
    zip = 'DEF'


class Jwe(Crypto):
    _fields = dict(
        enc=None,     #: EncEnum Algorithm
        zip=None,     #: ZipEnum Compression Algorithm
        **(Crypto._fields)
    )

    def __init__(self, **kwargs):
        super(Jwe, self).__init__(**kwargs)
        if isinstance(self.alg, basestring):
            self.alg = KeyEncEnum.create(self.alg)
        if isinstance(self.zip, basestring):
            self.zip = ZipEnum.create(self.zip)
        if isinstance(self.enc, basestring):
            self.enc = EncEnum.create(self.enc)

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        obj.enc = EncEnum.create(obj.enc)
        obj.zip = ZipEnum.create(obj.zip)
        return obj

    @classmethod
    def from_token(cls, token):
        m = re.search(_compact)

        return m and cls()

    def to_token(self):
        return ''


class Recipient(BaseObject):
    _fields = dict(
        header=None,            # JWE Per-Recipient Unprotected Header
        encrypted_key=None,     # BASE64URL(JWE Encrypted Key)
    )


class Message(BaseObject):
    _fields = dict(
        protected=None,     # BASE64URL(UTF8(JWE Protected Header))
        unprotected=None,   # JWE Shared Unprotected Header
        iv='',              # BASE64URL(JWE Initialization Vector)
        aad='',             # BASE64URL(JWE AAD))
        ciphertext='',      # BASE64(JWE Ciphertext)
        tag='',             # BASE64URL(JWE Authentication Tag)
        recipients=[],      # array of Recipient
    )
