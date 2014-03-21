from jose import commands
from jose.jwk import Jwk, JwkSet
from jose.jwa.keys import CurveEnum, KeyTypeEnum
#from jose import conf


class JwkCommand(commands.Command):
    Name = None

    def __init__(self, description="Jwk Command",  *args, **kwargs):
        super(JwkCommand, self).__init__(description=description)
        self.add_argument(
            '-c', '--curve', dest="curve",
            default='P-256',
            help="ECDSA Key Curve")

        self.add_argument(
            '-b', '--bits', dest="bits", default=2048, type=int,
            help="RSA key bits")

        self.add_argument(
            '-l', '--lentht', dest="length", default=64, type=int,
            help="Share Key Octets")

        self.add_argument(
            '-j', '--jwk', dest="jwk",
            default=None,
            help="With no Jws file, create file")

        self.add_argument(
            '-s', '--store', dest="store",
            default=None, type=str,
            help="Key Store path")

        self.add_argument(
            '-k', '--kid', dest="kid",
            default=None, type=str,
            help="Key Store path")

        self.add_argument(
            '-i', '--id', dest="id",
            default='me', type=str,
            help="Entity Identifier")

        self.add_argument(
            '-u', '--uri', dest="jku",
            default=None, type=str,
            help="Jku")

    def init(self):
        self.args = self.parse_args()
        inits = {}
        if hasattr(self.args, 'kty'):
            self.args.kty = KeyTypeEnum.create(self.args.kty)
            inits['kty'] = self.args.kty

            if self.args.kty == KeyTypeEnum.RSA:
                inits['length'] = self.args.bits
            elif self.args.kty == KeyTypeEnum.EC:
                inits['crv'] = CurveEnum.create(self.args.curve)
            elif self.args.kty == KeyTypeEnum.OCT:
                inits['length'] = self.args.length

        if self.args.kid:
            inits['kid'] = self.args.kid
        return inits


class CreateCommand(JwkCommand):
    Name = 'create'

    def __init__(self, *args, **kwargs):
        super(CreateCommand, self).__init__(description='Jwk Create')
        self.add_argument('command', help=self.Name)
        self.add_argument('kty', help="KeyType")
        self.add_argument('params', nargs='*', help="jws-claim=value")

        self.add_argument(
            '-p', '--payload', dest="payload",
            default=None,
            help="With no payload, read stdin or generate random.")

    def run(self):
        inits = self.init()
        jwk = Jwk.generate(**inits)
        jwk.add_to(self.args.id, self.args.jku)


class SelectCommand(JwkCommand):
    Name = 'select'

    def __init__(self, *args, **kwargs):
        super(SelectCommand, self).__init__(description='Jwk Select')
        self.add_argument('command', help=self.Name)
        self.add_argument('kty', help="KeyType", nargs='?')
        self.add_argument('params', nargs='*', help="jws-claim=value")
        self.add_argument(
            '-p', '--public', dest="public", action="store_true",
            help="List Public Set")

    def run(self):
        self.init()
        jwkset = JwkSet.load(self.args.id, self.args.jku) or JwkSet()
        if self.args.public:
            jwkset = jwkset.public_set
        print jwkset.to_json(indent=2)


class DeleteCommand(JwkCommand):
    Name = 'delete'

    def __init__(self, *args, **kwargs):
        super(DeleteCommand, self).__init__(description='Jwk Select')
        self.add_argument('command', help=self.Name)
        self.add_argument('index', help="KeyType", nargs='?',
                          default=None, type=int)

    def run(self):
        self.init()
        jwkset = JwkSet.load(self.args.id, self.args.jku) or JwkSet()
        if self.args.index is not None:
            jwkset.keys.pop(self.args.index)
            jwkset.save(self.args.id, self.args.jku)


if __name__ == '__main__':
    JwkCommand.dispatch(globals())
