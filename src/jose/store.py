# -*- coding: utf-8; -*-
import os
import urllib

class Store(object):
    def save(self,obj,entity_id,*args,**kwargs):
        pass
    
class FileStore(Store):
    def __init__(self,base=None):
        self.base = base or os.path.join(os.environ.get('HOME','/tmp'),".jose" )
        if not os.path.isdir(self.base):
            os.makedirs(self.base)
           
    def object_path(entity_id,id=None ):
        key = urllib.quote( entity_id )
        id = id or 'default'
        path = os.path.join(self.base,node)  if node else  self.base
        path = os.path.join(path, key )
        if not path.isdir(path):
            os.makedirs(path)
        return path

    def save(self,obj,entity_id,id=None,node=None,*args,**kwargs):
        path = self.object_path(entity_id,

    def load(self,entity_id,id=None, 
