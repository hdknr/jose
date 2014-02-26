# -*- coding: utf-8; -*-
import os
import urllib
from jose import BaseStore


class Store(object):
    def save(self, obj, entity_id="me", id=None, *args, **kwargs):
        pass

    def load(self, obj_class, entity_id="me", id=None, *args, **kwargs):
        pass


class FileStore(BaseStore):
    def __init__(self, base=None):
        self.base = base or os.path.join(
            os.environ.get('HOME', '/tmp'), ".jose")
        if not os.path.isdir(self.base):
            os.makedirs(self.base)

    def object_path(self, obj_class, entity_id, id=None):

        id = id or 'default'
        key = "%s/%s.%s.%s.json" % (
            urllib.quote(entity_id),
            obj_class.__module__,
            obj_class.__name__,
            id,
        )
        path = os.path.join(self.base, key)
        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        return path

    def save(self, obj, entity_id="me", id=None, *args, **kwargs):
        path = self.object_path(obj.__class__, entity_id, id)
        with open(path, "w") as out:
            out.write(obj.to_json(obj.to_json(**kwargs)))

    def load(self, obj_class, entity_id, id=None, *args, **kwargs):
        path = self.object_path(obj_class, entity_id, id)
        with open(path) as input:
            obj_class.from_json(input.read())
