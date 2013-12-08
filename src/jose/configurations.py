#
import os
import sys
from importlib import import_module
from store import *

class Configuration(object):
    store= FileStore()

def import_class(class_path):
    mod_name, class_name = class_path.rsplit('.',1)

    if mod_name == "jose.configurations" :
        mod = sys.modules[__name__] 
    else:
        mod = import_module(mod_name)

    return getattr(mod,class_name)

def load_configuration_instance():
    settings_class = os.environ.get('JOSE_CONFIGURATION_CLASS',
                        'jose.configurations.Configuration')
    return import_class(settings_class)()

configuration= load_configuration_instance()
