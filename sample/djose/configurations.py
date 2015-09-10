from jose.configurations import Configuration
from store import DjangoStore


class JoseConfiguration(Configuration):
    def __init__(self, store=None, *args, **kwargs):
        self.store = DjangoStore()
