import sys


def list_commands(mod_name):
    return [c.replace('_command', '')
            for c in dir(sys.modules[mod_name])
            if c.endswith('_command')]
