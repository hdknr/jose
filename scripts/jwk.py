from jose import commands
from jose.jwk import Jwk, JwkSet
from jose.jwa import keys
#from jose import conf
import ast


class JwkCommand(commands.Command):
    Name = None

    def set_args(self, parser):
        parser.add_argument(
            '-c', '--curve', dest="curve",
            default='P-256',
            choices=keys.CurveDict.values(),
            help="ECDSA Key Curve")

        parser.add_argument(
            '-b', '--bits', dest="bits", default=2048, type=int,
            choices=[2048, 4096, ],
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
        if args.kid:
            self.inits['kid'] = self.args.kid

        if hasattr(args, 'kty'):
            args.kty = keys.KeyTypeEnum.create(args.kty)
            self.inits['kty'] = self.args.kty

            if args.kty == keys.KeyTypeEnum.RSA:
                self.inits['length'] = args.bits
            elif args.kty == keys.KeyTypeEnum.EC:
                self.inits['crv'] = keys.CurveEnum.create(args.curve)
            elif args.kty == keys.KeyTypeEnum.OCT:
                self.inits['length'] = args.length

        self.params = {}
        if hasattr(args, 'params'):
            for i in args.params:
                k, v = i.split('=')
                try:
                    self.params[k] = ast.literal_eval(v)
                except:
                    self.params[k] = v

            if self.params.get('kty', None):
                self.params['kty'] = keys.KeyTypeEnum.create(
                    self.params['kty'])


class CreateCommand(JwkCommand):
    Name = 'create'

    def set_args(self, parser):
        super(CreateCommand, self).set_args(parser)

        parser.add_argument('kty',
                            choices=keys.KeyTypeDict.values(),
                            help="KeyType")
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
        super(SelectCommand, self).set_args(parser)
        parser.add_argument('params', nargs='*',
                            help="jws-claim=value")
        parser.add_argument(
            '-p', '--public', dest="public", action="store_true",
            help="List Public Set")

        parser.add_argument(
            '-a', '--all', dest="all", action="store_true",
            help="all")

    def run(self, args):
        super(SelectCommand, self).run(args)

        jwkset = JwkSet.load(args.id, args.jku) or JwkSet()

        if args.public:
            jwkset = jwkset.public_set

        keys = []
        if self.params.get('index', None) is not None:
            keys = [jwkset.keys[int(self.params['index'])]]
        elif self.params != {}:
            keys = jwkset.select_key(selector=args.all and all or any,
                                     **self.params)
        else:
            keys = jwkset.keys

        for key in keys:
            print key.to_json(indent=2)


class DeleteCommand(JwkCommand):
    Name = 'delete'

    def set_args(self, parser):
        super(DeleteCommand, self).set_args(parser)
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


class ResetKidCommand(JwkCommand):
    Name = 'resetkid'

    def set_args(self, parser):
        super(ResetKidCommand, self).set_args(parser)

    def run(self, args):
        super(ResetKidCommand, self).run(args)
        jwkset = JwkSet.load(args.id, args.jku) or JwkSet()

        for key in jwkset.select_key(kid=''):
            index = jwkset.index_key(key)
            key.set_kid()
            assert key.kid
            jwkset.keys[index] = key

        jwkset.save(args.id, args.jku)

if __name__ == '__main__':
    JwkCommand.dispatch([
        CreateCommand, SelectCommand, DeleteCommand,
        ResetKidCommand,
    ])
