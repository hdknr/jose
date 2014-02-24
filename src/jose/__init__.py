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
            #: instance as dict
            return dict([(k, v) for k, v in obj.__dict__.items()
                         if not k.startswith('_')])

        return super(BaseObjectSerializer, self).default(obj)


class BaseObject(object):
    _serializer = BaseObjectSerializer
    _fields = {}

    def __init__(self, **kwargs):
        map(lambda (k, v): setattr(self, k, kwargs.get(k, v)),
            self._fields.items())

    def to_json(self, *args, **kwargs):
        kwargs['cls'] = self._serializer    #: Custom Serializer
        return json.dumps(self, *args, **kwargs)

    @classmethod
    def from_json(cls, json_str, base=None):
        base = base or cls
        obj = base(**json.loads(json_str))
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
