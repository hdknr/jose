import sys
import argparse
from Crypto import Random

random_text = lambda n=32: Random.get_random_bytes(n).encode('hex')


def list_commands(mod_name):
    return [c.replace('_command', '')
            for c in dir(sys.modules[mod_name])
            if c.endswith('_command')]


def command_not_found():
    print "No such command is defined."


def dispatch(symbol_dict, description=""):
    '''  symbol_dict : globals()
    '''
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('command', help='|'.join(list_commands(__name__)),)
    args, unknown = parser.parse_known_args()

    symbol_dict.get(args.command + "_command", command_not_found)()


class StoreKeyValuePair(argparse.Action):
    def __call__(self, parser, namespace,
                 values, option_string=None, *args, **kwargs):
        print namespace, dir(namespace)
        print parser, dir(parser)
        obj = {}
        for value in values:
            k, v = value.split('=')
            obj[k.replace(' ', '')] = v.replace(' ', '')


class Command(object):
    Name = None

    def __init__(self, parser):
        command = parser.add_parser(self.Name)
        command.set_defaults(function=self.run)
        self.set_args(command)

    def set_args(self, parser):
        pass

    def run(self, args):
        raise NotImplemented

    @classmethod
    def set_global_args(cls, parser):
        pass

    @classmethod
    def dispatch(cls, commands):
        parser = argparse.ArgumentParser()
        cls.set_global_args(parser)
        subparsers = parser.add_subparsers(help='sub-command help')

        for command in commands:
            command(subparsers)

        args = parser.parse_args()
        args.function(args)
