# -*- coding: utf-8; -*-
import os
import urllib
from jose import BaseStore
import requests


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

    def object_path(self, obj_class, entity_id, uri=None):

        uri = uri or 'default'
        key = "%s/%s.%s.%s.json" % (
            urllib.quote(entity_id),
            obj_class.__module__,
            obj_class.__name__,
            urllib.quote(uri),
        )
        path = os.path.join(self.base, key)
        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))
        return path

    def save(self, obj, entity_id="me", uri=None, *args, **kwargs):
        path = self.object_path(obj.__class__, entity_id, uri)
        with open(path, "w") as out:
            out.write(obj.to_json(obj.to_json(**kwargs)))

    def load(self, obj_class, entity_id, uri=None, *args, **kwargs):
        path = self.object_path(obj_class, entity_id, uri)
        with open(path) as input:
            return obj_class.from_json(input.read())
        #: TODO: look at conf to swith caching automatically or not.
        return self.cache(obj_class, entity_id, uri, *args, **kwargs)

    def cache(self, obj_class, entity_id, uri, *args, **kwargs):
        obj = obj_class.form_json(requests.get(uri).content)
        self.save(obj, entity_id, uri, *args, **kwargs)
        return obj
