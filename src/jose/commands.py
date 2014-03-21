import sys
from argparse import ArgumentParser
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
    parser = ArgumentParser(description=description)
    parser.add_argument('command', help='|'.join(list_commands(__name__)),)
    args, unknown = parser.parse_known_args()

    symbol_dict.get(args.command + "_command", command_not_found)()


class Command(ArgumentParser):
    Name = None

    def run(self):
        raise NotImplemented

    @classmethod
    def dispatch(cls, symbols=None):
        symbols = symbols or globals()  # dict of  name:type
        parser = ArgumentParser(description="Jwk Command")
        parser.add_argument('command', help='|'.join(list_commands(__name__)),)
        args, unknown = parser.parse_known_args()

        command = None
        for k, v in symbols.items():
            try:
                if issubclass(v, cls) and v != cls:
                    if v.Name == args.command:
                        command = v
                        break
            except:
                pass

        if command:
            return command().run()
