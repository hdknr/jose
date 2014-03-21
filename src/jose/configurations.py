import os
from utils import import_class
import time
import struct


class Configuration(object):
    def __init__(self, store=None, *args, **kwargs):
        self.store = store or import_class(
            os.environ.get(
                'JOSE_STORE_CLASS',
                'jose.store.FileStore')
        )()

    def generate_kid(self, kty, length, *args, **kwargs):
        '''
            :parma int length: field length(EC), bits(RSA), length(oct)
        '''
        return '-'.join([
            kty.name[0],
            struct.pack('H', length).encode('hex'),
            struct.pack('d', time.time()).encode('hex')])
