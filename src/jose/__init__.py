__all__ = ('__version__', '__build__')
__version__ = (0,0,1)
__build__ = ''

#import os
#print "@@@@@",__name__

def get_version():
    return '.'.join( map( lambda v:str(v),__version__) )

#def import_class(class_path):
#    print "@@@@ import_class",class_path
#    mod_name, class_name = class_path.rsplit('.',1)
#    mod = __import__(mod_name)
#    return getattr(mod,class_name)
#
#def load_settings(): 
#    settings_class = os.environ.get('JOSE_SETTINGS_CLASS','jose.settings.Settings')
#    return import_class(settings_class)
#
#settings = load_settings()
