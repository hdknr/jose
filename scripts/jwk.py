from jose import commands
from jose.jwk import Jwk, JwkSet
from jose.jwa.keys import CurveEnum, KeyTypeEnum
#from jose import conf


class JwkCommand(commands.Command):
    Name = None

    @classmethod
    def set_global_args(cls, parser):
        parser.add_argument(
            '-c', '--curve', dest="curve",
            default='P-256',
            help="ECDSA Key Curve")

        parser.add_argument(
            '-b', '--bits', dest="bits", default=2048, type=int,
            help="RSA key bits")

        parser.add_argument(
            '-l', '--lentht', dest="length", default=64, type=int,
            help="Share Key Octets")

        parser.add_argument(
            '-j', '--jwk', dest="jwk",
            default=None,
            help="With no Jws file, create file")

        parser.add_argument(
            '-s', '--store', dest="store",
            default=None, type=str,
            help="Key Store path")

        parser.add_argument(
            '-k', '--kid', dest="kid",
            default=None, type=str,
            help="Key Store path")

        parser.add_argument(
            '-i', '--id', dest="id",
            default='me', type=str,
            help="Entity Identifier")

        parser.add_argument(
            '-u', '--uri', dest="jku",
            default=None, type=str,
            help="Jku")

    def run(self, args):
        self.inits = {}
        if hasattr(args, 'kty'):
            args.kty = KeyTypeEnum.create(args.kty)
            self.inits['kty'] = self.args.kty

            if args.kty == KeyTypeEnum.RSA:
                self.inits['length'] = args.bits
            elif args.kty == KeyTypeEnum.EC:
                self.inits['crv'] = CurveEnum.create(args.curve)
            elif args.kty == KeyTypeEnum.OCT:
                self.inits['length'] = args.length

        self.params = {}
        if hasattr(args, 'params'):
            print "@@@@@@", args.params
            self.params = dict([
                i.split('=') for i in args.params
                if i.find('=') >= 0])

        if args.kid:
            self.inits['kid'] = self.args.kid


class CreateCommand(JwkCommand):
    Name = 'create'

    def set_args(self, parser):
        parser.add_argument('kty', help="KeyType")
        parser.add_argument('params', nargs='*', help="jws-claim=value")

        parser.add_argument(
            '-p', '--payload', dest="payload",
            default=None,
            help="With no payload, read stdin or generate random.")

    def run(self, args):
        super(CreateCommand, self).run(args)
        jwk = Jwk.generate(**self.inits)
        jwk.add_to(args.id, args.jku)


class SelectCommand(JwkCommand):
    Name = 'select'

    def set_args(self, parser):
        parser.add_argument('params', nargs='*',
                            help="jws-claim=value")
        parser.add_argument(
            '-p', '--public', dest="public", action="store_true",
            help="List Public Set")

    def run(self, args):
        super(SelectCommand, self).run(args)

        jwkset = JwkSet.load(args.id, args.jku) or JwkSet()

        if args.public:
            jwkset = jwkset.public_set

        if self.params.get('index', None) is not None:
            print jwkset.keys[int(self.params['index'])].to_json(indent=2)
        else:
            print jwkset.to_json(indent=2)


class DeleteCommand(JwkCommand):
    Name = 'delete'

    def set_args(self, parser):
        parser.add_argument('index', help="KeyType", nargs='?',
                            default=None, type=int)

    def run(self, args):
        super(DeleteCommand, self).run(args)
        jwkset = JwkSet.load(args.id, args.jku) or JwkSet()

        if self.params.get('index', None) is not None:
            removed = jwkset.keys.pop(int(self.params['index']))
            jwkset.save(args.id, args.jku)
            print removed.to_json(indent=2)
            return

if __name__ == '__main__':
    JwkCommand.dispatch([
        CreateCommand, SelectCommand, DeleteCommand
    ])
