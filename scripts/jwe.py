import sys
import os
from jose import jwe, jwk, commands, BaseObject, conf
from jose.jwa import keys, encs
from jose.utils import _BE, _BD
import traceback


class Result(BaseObject):
    pass


class JweCommand(commands.Command):

    def set_args(self, parser):

        parser.add_argument(
            '-s', '--store', dest="store",
            default=None, type=str,
            help="Key Store path")

        parser.add_argument(
            '-u', '--uri', dest="jku",
            default=None, type=str,
            help="Jku")

    def run(self, args):

        # Key Store
        if args.store:
            conf.store.base = os.path.abspath(args.store)

        #: stdin
        if not sys.stdin.isatty():
            args.stdin = sys.stdin.read().rstrip('\n')

        #Plaintext
        if getattr(args, 'payload', None):
            with open(args.payload) as infile:
                args.payload = infile.read()
        elif not sys.stdin.isatty():
            args.payload = args.stdin.replace('\n', '')
        else:
            args.payload = commands.random_text(32)

        # Message/Token
        if getattr(args, 'message', None):
            with open(args.message) as infile:
                args.message = infile.read()
        elif not sys.stdin.isatty():
            args.message = args.stdin.replace('\n', '')

        # enc
        if getattr(args, 'enc', None):
            args.enc = encs.EncEnum.A128CBC_HS256
        else:
            args.enc = encs.EncEnum.create(args.enc)


class MultiCommand(JweCommand):
    Name = 'multi'

    def set_args(self, parser):
        super(MultiCommand, self).set_args(parser)
        parser.add_argument('enc', type=str, default='A128CBC_HS256',
                            nargs='?',
                            help="|".join(encs.EncDict.values()))

        parser.add_argument(
            '-p', '--payload', dest="payload",
            default=None,
            help="With no payload, read stdin or generate random.")

    def run(self, args):
        super(MultiCommand, self).run(args)

        message = jwe.Message(
            protected=jwe.Jwe(enc=args.enc, zip="DEF",),
            unprotected=jwe.Jwe(typ="text"),
            plaintext=_BE(args.payload)
        )

        for alg in encs.KeyEncDict.values():
            alg = encs.KeyEncEnum.create(alg)
            if alg.single:
                continue
            receiver = 'https://%s.com/' % alg.name.lower()
            jku = receiver + '/jwkset'
            jwk.Jwk.get_or_create_from(
                receiver, jku, alg.key_type, kid=None,)

            recipient = jwe.Recipient(
                header=jwe.Jwe(alg=alg, jku=jku,)
            )
            message.add_recipient(recipient, receiver)

        print message.serialize_json(indent=2)


class ParseCommand(JweCommand):
    Name = 'parse'

    def set_args(self, parser):
        super(ParseCommand, self).set_args(parser)
        parser.add_argument('message', type=str, default=None, nargs='?',
                            help="message file")

        parser.add_argument('-S', '--Sender',
                            type=str,
                            dest='sender',
                            default="https://foo.com",
                            help="signer entity id")

    def run(self, args):
        super(ParseCommand, self).run(args)
        if not getattr(args, 'message', None):
            print "no message file or stdin"
            return

        msg = jws.Message.from_token(args.message, sender=args.sender)
        if not msg:
            try:
                msg = jws.Jws.from_json(args.message)
            except:
                try:
                    msg = jws.Jws.from_base64(args.message)
                except:
                    pass

        print msg and msg.to_json(indent=2)

if __name__ == '__main__':
    JweCommand.dispatch([
        MultiCommand,
        ParseCommand,
    ])
