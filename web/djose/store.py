from jose.store import FileStore
from jose.jwk import JwkSet
from models import Key


class DjangoStore(FileStore):

    def save(self, obj, entity_id="me", id=None, *args, **kwargs):
        if isinstance(obj, JwkSet):
            Key(entity=entity_id,
                uri=entity_id, data=obj.to_json()).save()
        else:
            super(DjangoStore, self).save(obj, entity_id, id, *args, **kwargs)

    def load(self, obj_class, entity_id="me", id=None, *args, **kwargs):
        if obj_class == JwkSet:
            key = Key.objects.get(uri=entity_id)
            return obj_class.from_json(key.data)
        else:
            super(DjangoStore, self).load(obj_class,
                                          entity_id, id,
                                          *args, **kwargs)
