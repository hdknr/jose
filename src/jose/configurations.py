import os
from utils import import_class


class Configuration(object):
    def __init__(self, store=None, *args, **kwargs):
        self.store = store or import_class(
            os.environ.get(
                'JOSE_STORE_CLASS',
                'jose.store.FileStore')
        )()
