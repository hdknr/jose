from jose.configurations import Configuration
from jose.store import Store

class JoseStore(Store):
    def save(self,entity_id,obj,id=None,node=None,*args,**kwargs):
        print "Django Jose Store",type(self),entity_id,type(obj)

