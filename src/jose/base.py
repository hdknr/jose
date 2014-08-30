import json
from enum import Enum
import os
from jose.utils import import_class, base64
from urllib import quote
import urlparse
import traceback
from datetime import datetime


def urlencode(kwargs):
    return "&".join(
        "%s=%s" % (k, quote(v)) for k, v in kwargs.items()
    )


class JoseException(Exception):
    def __init__(self, message,  jobj, *args):
        super(JoseException, self).__init__(*args)
        self.jobj = jobj
        self.message = message


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
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, object):
            #: instance as dict
            ex = isinstance(obj, BaseObject) and obj._excludes or []
            if hasattr(obj, '_customs'):
                vals = obj._customs.copy()
            else:
                vals = {}
            vals.update(obj.__dict__)
            return dict([(k, v) for k, v in vals.items()
                         if k not in ex and not k.startswith('_') and v])

        return super(BaseObjectSerializer, self).default(obj)


class BaseObject(object):
    _serializer = BaseObjectSerializer
    _fields = {}
    _excludes = []

    def __init__(self, **kwargs):
        self._customs = {}
        self.set_values(self._fields, kwargs)

    def __getitem__(self, key):
        return getattr(
            self, key,
            self._customs.get(key, None))

    def __setitem__(self, key, val):
        self._customs[key] = val

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

    def to_b64u(self, *args, **kwargs):
        return base64.base64url_encode(
            self.to_json(*args, **kwargs))

    def to_dict(self, *args, **kwargs):
        return json.loads(
            self.to_json(*args, **kwargs))

    def to_qs(self, *args, **kwargs):
        return urlencode(self.to_dict(*args, **kwargs))

    @classmethod
    def merge(cls, *obj):
        vals = cls._fields.copy()
        map(lambda o: vals.update(o and o.to_dict() or {}), obj)
        return cls(**vals)

    @classmethod
    def from_json(cls, json_str, base=None, **kwargs):
        base = base or cls
        kwargs.update(json.loads(json_str))
        obj = base(**kwargs)
        return obj

    @classmethod
    def from_file(cls, json_file, base=None):
        base = base or cls
        with open(json_file) as data:
            obj = base(** json.load(data))
        return obj

    @classmethod
    def from_url(cls, url, base=None):
        base = base or cls
        return cls(
            **dict(urlparse.parse_qsl(urlparse.urlparse(url).query))
        )

    @classmethod
    def from_b64u(cls, b64_str, base=None):
        return cls.from_json(base64.base64url_decode(b64_str), base)

    def save(self, owner, id=None, *args, **kwargs):
        ''' owner  - object or identifier
        '''
        conf.store.save(self, owner, id, *args, **kwargs)

    @classmethod
    def load(cls, owner, id=None, *args, **kwargs):
        ''' owner  - object or identifier
        '''
        try:
            ret = conf.store.load(cls, owner, id, *args, **kwargs)
            return ret
        except Exception, ex:
            print ex
            return None


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
    def __init__(
            self, kty, material=None, length=None, jwk=None,
            *args, **kwargs):

        assert any([material is None,
                    isinstance(material, BaseKey)])

        self.material = material
        if not self.material:
            if jwk:
                self.from_jwk(jwk)
            else:
                self.init_material(length=length, *args, **kwargs)

    def init__material(self, length,  *args, **kwargs):
        raise NotImplemented

    def to_jwk(self, jwk):
        raise NotImplemented

    def from_jwk(self, jwk):
        raise NotImplemented

    @property
    def is_public(self):
        return False

    @property
    def is_private(self):
        return False


class BaseKeyEncryptor(object):
    @classmethod
    def provide(cls, enc, jwk, jwe, *args, **kwargs):
        raise NotImplemented()

    @classmethod
    def agree(cls, enc, jwk, jwe, cek_ci, *args, **kwargs):
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


def load_configuration_instance():
    settings_class = os.environ.get(
        'JOSE_CONFIGURATION_CLASS',
        'jose.configurations.Configuration')
    return import_class(settings_class)()


conf = load_configuration_instance()
