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

    def init(self):
        self.args = self.parse_args()
        self.args.kty = KeyTypeEnum.create(self.args.kty)
        assert self.args.kty
        inits = dict(kty=self.args.kty)

        if self.args.kty == KeyTypeEnum.RSA:
            inits['bits'] = self.args.bits
        elif self.args.kty == KeyTypeEnum.EC:
            inits['curve'] = CurveEnum.create(self.args.curve)
        elif self.args.kty == KeyTypeEnum.OCT:
            inits['length'] = self.args.length
        inits['kid'] = 'xxx'
        return inits

    def run(self):
        jwkset = JwkSet(keys=[Jwk.generate(** self.init())])
        print jwkset.to_json(indent=2)

if __name__ == '__main__':
    JwkCommand.dispatch(globals())
