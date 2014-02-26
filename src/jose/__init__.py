__all__ = ('__version__', '__build__', 'get_version', 'conf', )
__version__ = (0, 0, 1)
__build__ = ''

import json
from enum import Enum
import os
from jose.utils import import_class


def get_version():
    return '.'.join(map(lambda v: str(v), __version__))


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
                         if not k.startswith('_') and v])

        return super(BaseObjectSerializer, self).default(obj)


class BaseObject(object):
    _serializer = BaseObjectSerializer
    _fields = {}

    def __init__(self, **kwargs):
        self.set_values(self._fields, kwargs)

    def set_values(self, inits, vals):
        map(lambda (k, v): setattr(self, k, vals.get(k, v)),
            inits.items())

    def to_json(self, *args, **kwargs):
        kwargs['cls'] = self._serializer    #: Custom Serializer
        return json.dumps(self, *args, **kwargs)

    @classmethod
    def from_json(cls, json_str, base=None):
        base = base or cls
        obj = base(**json.loads(json_str))
        return obj

    def save(self, entity_id="me", id=None, *args, **kwargs):
        conf.store.save(self, entity_id, id, *args, **kwargs)

    @classmethod
    def load(cls, entity_id="me", id=None, *args, **kwargs):
        return conf.store.load(cls, entity_id, id, *args, **kwargs)


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


class BaseKey(object):
    def __init__(self, jwk=None, *args, **kwargs):
        self.jwk = jwk


class BaseStore(object):
    def save(self, obj, entity_id="me", id=None, *args, **kwargs):
        pass

    def load(self, obj_class, entity_id="me", id=None, *args, **kwargs):
        pass


def load_configuration_instance():
    settings_class = os.environ.get(
        'JOSE_CONFIGURATION_CLASS',
        'jose.configurations.Configuration')
    return import_class(settings_class)()


conf = load_configuration_instance()
