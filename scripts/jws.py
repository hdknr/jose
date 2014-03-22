import sys
import os
from jose import commands
from jose.jwa import sigs
from jose.jws import Jws
from jose.jwk import Jwk
from jose.jwa.keys import CurveEnum, KeyTypeEnum
from jose import BaseObject, conf
from jose.utils import _BE, _BD


class Result(BaseObject):
    pass


class JwsCommand(commands.Command):

    @classmethod
    def set_global_args(self, parser):
        parser.add_argument(
            '-p', '--payload', dest="payload",
            default=None,
            help="With no payload, read stdin or generate random.")

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


class SampleCommand(JwsCommand):
    Name = 'sample'

    def set_args(self, parser):
        parser.add_argument('alg', help="jws 'alg' claim")
        parser.add_argument('params', nargs='*', help="jws-claim=value")

    def run(self, args):

        if args.store:
            conf.store.base = os.path.abspath(args.store)

        sample = Result()

        #Jws
        sample.jws = Jws(alg=sigs.SigEnum.create(args.alg.upper()))

        for param in args.params:
            sample.jws.set_value(*param.split('='))

        #Plaintext
        if args.payload:
            with open(args.payload) as infile:
                sample.plaintext = infile.read()
        elif not sys.stdin.isatty():
            sample.plaintext = sys.stdin.read()
        else:
            sample.plaintext = commands.random_text(32)

        if sample.jws.alg.key_type == KeyTypeEnum.RSA:
            sample.inits = dict(length=args.bits)
        elif sample.jws.alg.key_type == KeyTypeEnum.EC:
            sample.inits = dict(length=CurveEnum.create(args.curve).bits)
        elif sample.jws.alg.key_type == KeyTypeEnum.OCT:
            sample.inits = dict(length=args.length)

        #key
        if args.jwk:
            sample.jwk = Jwk.from_file(args.jwk)
        else:
            sample.jwk = Jwk.generate(
                kty=sample.jws.alg.key_type, **sample.inits)

        assert sample.jwk.kty == sample.jws.alg.key_type

        sample.signature = _BE(sample.jws.sign(sample.plaintext, sample.jwk))
        sample.verified = sample.jws.verify(
            sample.plaintext, _BD(sample.signature), sample.jwk)
        print sample.to_json(indent=2)


if __name__ == '__main__':
    JwsCommand.dispatch([
        SampleCommand,
    ])
