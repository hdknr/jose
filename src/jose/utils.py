import base64
#import struct
#from binascii import hexlify  # ,unhexlify
#import re
from Crypto.Util.number import long_to_bytes, bytes_to_long


base64.base64url_encode = \
    lambda src: base64.urlsafe_b64encode(src).replace('=', '')

base64.base64url_decode = \
    lambda src: base64.urlsafe_b64decode(src + '=' * (len(src) % 4))


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
