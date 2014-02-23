__all__ = ('__version__', '__build__', 'base64', )
__version__ = (0, 0, 1)
__build__ = ''

import base64
import json
from enum import Enum


def get_version():
    return '.'.join(map(lambda v: str(v), __version__))


base64.base64url_encode = \
    lambda src: base64.urlsafe_b64encode(src).replace('=', '')

base64.base64url_decode = \
    lambda src: base64.urlsafe_b64decode(src + '=' * (len(src) % 4))


class BaseEnum(Enum):
    @classmethod
    def create(cls, value, default=None):
        try:
            return cls(value)

        except ValueError:
            return default

        except Exception, e:
            raise e


class BaseObjectSerializer(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, object):
            return obj.__dict__

        return super(BaseObjectSerializer, self).default(obj)


class BaseObject(object):
    _serializer = BaseObjectSerializer

    def __init__(*args, **kwargs):
        pass

    def to_json(self, *args, **kwargs):
        kwargs['cls'] = self._serializer    #: Custom Serializer
        return json.dumps(self, *args, **kwargs)

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = type('', (base or cls, ), json.loads(json_str))()
        return obj


class AlgorithmBaseEnum(BaseEnum):

    def __eq__(self, other):
        if isinstance(other, AlgorithmBaseEnum):
            return self.value == other.value
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result
