import sys
import os
from jose import commands
from jose.jwa import sigs
from jose.jws import Jws
from jose import jwk
from jose.jwa import keys
from jose import BaseObject, conf
from jose.utils import _BE, _BD


class Result(BaseObject):
    pass


class JwsCommand(commands.Command):

    def set_args(self, parser):
        parser.add_argument(
            '-p', '--payload', dest="payload",
            default=None,
            help="With no payload, read stdin or generate random.")

        parser.add_argument(
            '-s', '--store', dest="store",
            default=None, type=str,
            help="Key Store path")

        parser.add_argument(
            '-u', '--uri', dest="jku",
            default=None, type=str,
            help="Jku")

    def run(self, args):
        self.result = Result()

        # Key Store
        if args.store:
            conf.store.base = os.path.abspath(args.store)

        #Plaintext
        if args.payload:
            with open(args.payload) as infile:
                self.result.plaintext = infile.read()
        elif not sys.stdin.isatty():
            self.result.plaintext = sys.stdin.read()
        else:
            self.result.plaintext = commands.random_text(32)


class SampleCommand(JwsCommand):
    Name = 'sample'

    def set_args(self, parser):
        super(SampleCommand, self).set_args(parser)

        parser.add_argument('alg',
                            choices=sigs.SigDict.values(),
                            help="|".join(sigs.SigDict.values()))
        parser.add_argument('params', nargs='*', help="jws-claim=value")
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

    def run(self, args):
        super(SampleCommand, self).run(args)

        #Jws
        self.result.jws = Jws(alg=sigs.SigEnum.create(args.alg))
        print self.result.to_json(indent=2)

        # any parms
        for param in args.params:
            self.result.jws.set_value(*param.split('='))

        # Initia Value
        if self.result.jws.alg.key_type == keys.KeyTypeEnum.RSA:
            self.result.inits = dict(length=args.bits)
        elif self.result.jws.alg.key_type == keys.KeyTypeEnum.EC:
            self.result.inits = dict(
                length=keys.CurveEnum.create(args.curve).bits)
        elif self.result.jws.alg.key_type == keys.KeyTypeEnum.OCT:
            self.result.inits = dict(length=args.length)

        #key
        if args.jwk:
            self.result.jwk = jwk.Jwk.from_file(args.jwk)
        else:
            self.result.jwk = jwk.Jwk.generate(
                kty=self.result.jws.alg.key_type, **self.result.inits)

        assert self.result.jwk.kty == self.result.jws.alg.key_type

        self.result.signature = _BE(
            self.result.jws.sign(self.result.plaintext, self.result.jwk))

        self.result.verified = self.result.jws.verify(
            self.result.plaintext, _BD(self.result.signature), self.result.jwk)

        print self.result.to_json(indent=2)


class MessageCommand(JwsCommand):
    Name = 'message'

    def set_args(self, parser):
        super(MessageCommand, self).set_args(parser)
        parser.add_argument('signer',
                            type=str,
                            default="https://foo.com",
                            help="signer entity id")

    def run(self, args):
        super(MessageCommand, self).run(args)

        key_params = [
            {"kty": keys.KeyTypeEnum.EC, "length": 256, },
            {"kty": keys.KeyTypeEnum.EC, "length": 384, },
            {"kty": keys.KeyTypeEnum.EC, "length": 521, },
            {"kty": keys.KeyTypeEnum.RSA, "length": 2048, },
            {"kty": keys.KeyTypeEnum.OCT, "length": 100, },
        ]
        jwkset = jwk.JwkSet.load(args.signer, args.jku) or jwk.JwkSet()
        for keyp in key_params:
            key = jwkset.select_key(selector=all, **keyp)
            key = key[0] if len(key) > 0 else None
            if key is None:
                key = jwk.Jwk.generate(**keyp)
                print key.kty, key.length, key.to_json(indent=2)
                jwkset.add_key(key)
            keyp['jwk'] = key
        jwkset.save(args.signer, args.jku)


if __name__ == '__main__':
    JwsCommand.dispatch([
        SampleCommand,
        MessageCommand,
    ])
