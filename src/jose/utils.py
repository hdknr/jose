from __future__ import print_function

import base64
from importlib import import_module

# import struct
# from binascii import hexlify  # ,unhexlify
# import re
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
import struct
from six import b, text_type


def _b(src, enc='utf8'):
    return isinstance(src, text_type) and src.encode(enc) or src


def _b64url_encode(src):
    return src and base64.urlsafe_b64encode(_b(src)).replace(b('='), b(''))


def _b64url_decode(src):
    return src and base64.urlsafe_b64decode(_b(src) + b('=') * (len(src) % 4))

base64.base64url_encode = _b64url_encode
base64.base64url_decode = _b64url_decode


def long_to_b64(n):
    data = long_to_bytes(n)
    return base64.base64url_encode(data)


def long_from_b64(s):
    data = base64.base64url_decode(s)
    return bytes_to_long(data)


base64.long_to_b64 = long_to_b64
base64.long_from_b64 = long_from_b64
#


def import_class(class_path):
    mod_name, class_name = class_path.rsplit('.', 1)
    mod = import_module(mod_name)
    return getattr(mod, class_name)


def merged(dicts):
    '''Merge list of dicts to single dict '''
    return {k: v for dic in dicts for k, v in dic.items()}

# alias
_BE = base64.base64url_encode
_BD = base64.base64url_decode
_LBE = base64.long_to_b64
_LBD = base64.long_from_b64


def nonce(prefix=''):
    prefix + base64.base64url_encode(struct.pack('!d', time.time()))

if __name__ == '__main__':
    print(nonce())
