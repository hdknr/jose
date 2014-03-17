__all__ = ('__version__', '__build__', 'get_version', 'conf', )
__version__ = (0, 0, 1)
__build__ = ''

import json
from enum import Enum
import os
from jose.utils import import_class, base64


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
            if hasattr(obj, '_customs'):
                vals = obj._customs.copy()
            else:
                vals = {}
            vals.update(obj.__dict__)
            return dict([(k, v) for k, v in vals.items()
                         if not k.startswith('_') and v])

        return super(BaseObjectSerializer, self).default(obj)


class BaseObject(object):
    _serializer = BaseObjectSerializer
    _fields = {}

    def __init__(self, **kwargs):
        self._customs = {}
        self.set_values(self._fields, kwargs)

    def __getitem__(self, key):
        return self._customs.get(key, None)

    def __setitem__(self, key, val):
        self.__customs[key] = val

    def set_values(self, inits, vals):
        keys = inits.keys()
        data = inits.copy()
        data.update(vals)
        for k, v in data.items():
            if k in keys:
                setattr(self, k, v)
            else:
                self._customs[k] = v

    def to_json(self, *args, **kwargs):
        kwargs['cls'] = self._serializer    #: Custom Serializer
        return json.dumps(self, *args, **kwargs)

    @classmethod
    def from_json(cls, json_str, base=None):
        base = base or cls
        obj = base(**json.loads(json_str))
        return obj

    @classmethod
    def from_file(cls, json_file, base=None):
        base = base or cls
        with open(json_file) as data:
            obj = base(**json.load(data))
        return obj

    @classmethod
    def from_base64(cls, b64_str, base=None):
        return cls.from_json(base64.base64url_decode(b64_str), base)

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
    def __init__(self, kty, material=None, jwk=None,
                 *args, **kwargs):
        self.kty = kty  #: KeyTypeEnum
        self.material = material
        if self.material is None and jwk:
            self.from_jwk(jwk)

    @property
    def is_public(self):
        return False

    @property
    def is_private(self):
        return False


class BaseKeyEncryptor(object):
    @classmethod
    def provide(cls, jwk, jwe, *args, **kwargs):
        raise NotImplemented()

    @classmethod
    def agree(cls, jwk, jwe, cek_ci, *args, **kwargs):
        raise NotImplemented()


class BaseContentEncryptor(object):
    _KEY_LEN = None

    @classmethod
    def create_key_iv(cls):
        from Crypto import Random
        return (
            Random.get_random_bytes(cls._KEY_LEN),
            Random.get_random_bytes(cls._IV_LEN),
        )

    @classmethod
    def key_length(cls):
        return cls._KEY_LEN


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
