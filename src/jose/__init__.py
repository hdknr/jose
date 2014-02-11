__all__ = ('__version__', '__build__', 'base64', )
__version__ = (0, 0, 1)
__build__ = ''

import base64


def get_version():
    return '.'.join(map(lambda v: str(v), __version__))


base64.base64url_encode = \
    lambda src: base64.urlsafe_b64encode(src).replace('=', '')

base64.base64url_decode = \
    lambda src: base64.urlsafe_b64decode(src + '=' * (len(src) % 4))
