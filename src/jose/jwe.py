from crypto import Crypto
from jwa.encs import Encryption
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
    enc = None      #: Encryption Algorithm
    zip = None      #: Compression Algorithm
    #: Other members are defined Crypto

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        obj.enc = Encryption.create(obj.enc)
        obj.zip = ZipEnum.create(obj.zip)

    @classmethod
    def from_token(cls, token):
        m = re.search(_compact)

        return m and cls()

    def to_token(self):
        return ''
