import base64
from importlib import import_module

#import struct
#from binascii import hexlify  # ,unhexlify
#import re
from Crypto.Util.number import long_to_bytes, bytes_to_long
import time
import struct


def _ss(str_data):
    if isinstance(str_data, unicode):
        return str_data.encode('utf8')
    return str_data

base64.base64url_encode = lambda src: \
    src and base64.urlsafe_b64encode(src).replace('=', '')

base64.base64url_decode = lambda src: \
    src and base64.urlsafe_b64decode(_ss(src) + '=' * (len(src) % 4))


#def long_to_bytes(n):
#    ns = "{0:x}".format(n)
#    return [long(i, 16) for i in
#            re.findall(r'(..)', '0' * (len(ns) % 2) + ns)]
#
#
#def long_from_bytes(s):
#    return long(''.join(["%02x" % byte for byte in s]), 16)
#


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

# Merge list of dicts to single dict

merged = lambda dicts: {k: v for dic in dicts for k, v in dic.items()}

# alias
_BE = base64.base64url_encode
_BD = base64.base64url_decode
_LBE = base64.long_to_b64
_LBD = base64.long_from_b64

nonce = lambda prefix='': \
    prefix + base64.base64url_encode(struct.pack('!d', time.time()))

if __name__ == '__main__':
    print nonce()
    pass
