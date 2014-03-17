from jose.utils import base64
from jose.commands import list_commands
from jose.jwa.encs import KeyEncEnum
from jose.jwk import Jwk, keys
from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto import Random
from pbkdf2 import PBKDF2


def derive(key, salt, count=1024, klen=16, digest=SHA256):
    derived_key = PBKDF2(key, salt, count,
                         digestmodule=digest,
                         macmodule=HMAC).read(klen)

    return key, derived_key, salt, count


from argparse import ArgumentParser


def wrap_command():
    parser = ArgumentParser(description='PBES2 Key Derivation')
    parser.add_argument('command', help="wrap")
    parser.add_argument('password')
    parser.add_argument('cek', nargs='?', default=None, type=basestring)
    parser.add_argument('key_len', nargs='?', default=16, type=int)
    parser.add_argument('-f', '--foo')
    parser.add_argument('-s', '--salt', dest="salt", action="store",
                        default=None, help='base64salt')
    parser.add_argument('-a', '--alg', dest="alg", action="store",
                        default='HS256', help='HS256|HS384|HS512')
    parser.add_argument('-c', '--count', dest="count",
                        action="store", type=int,
                        default=1024, help='KDF2 counter')
    args = parser.parse_args()

    wrapper = dict(
        HS256=KeyEncEnum.PBES2_HS384_A192KW,
        HS348=KeyEncEnum.PBES2_HS384_A192KW,
        HS512=KeyEncEnum.PBES2_HS512_A256KW,
    )[args.alg].encryptor

    if args.cek:
        cek = base64.base64url_decode(args.cek)
    else:
        cek = Random.get_random_bytes(args.key_len)

    jwk = Jwk(kty=keys.KeyTypeEnum.OCT)
    if args.password == 'random':
        jwk.k = base64.base64url_encode(
            Random.get_random_bytes(wrapper.key_length()))
    elif args.password.startswith('b64url:'):
        jwk.k = args.password[6:]
    else:
        jwk.k = base64.base64url_encode(args.password)

    salt = args.salt or base64.base64url_encode(
        Random.get_random_bytes(wrapper.key_length()))

    assert len(jwk.key.shared_key) == wrapper.key_length()

    kek = wrapper.derive(jwk, salt, args.count)
    cek_ci = wrapper.encrypt(kek, cek)

    print "share key(b64url)=", base64.base64url_encode(jwk.k),
    print "cek(b64url)=", base64.base64url_encode(cek)
    print "salt(b64url)=", base64.base64url_encode(salt),
    print "kek(b64url)=", base64.base64url_encode(kek),
    print "warapped cek(b64url)=", base64.base64url_encode(cek_ci),
    print "key length=", args.key_len,
    print "alg=", args.alg, wrapper.__name__,
    print "count=", args.count


def derive_command():
    parser = ArgumentParser(description='PBES2 Key Derivation')
    parser.add_argument('command')
    parser.add_argument('password')
    parser.add_argument('key_len', nargs='?', default=16, type=int)
    parser.add_argument('-f', '--foo')
    parser.add_argument('-d', '--digest', dest="digest", action="store",
                        default='sha256', help='sha256|384|512')
    parser.add_argument('-s', '--salt', dest="salt", action="store",
                        default=None, help='base64salt')
    args = parser.parse_args()

    klen = args.key_len
    digest = dict(sha256=SHA256,
                  sha384=SHA384,
                  sha512=SHA512)[args.digest]
    if args.password == 'random':
        key = Random.get_random_bytes(klen)
    elif args.password.startswith('b64url:'):
        key = base64.base64url_decode(args.password[6:])
    else:
        key = args.password

    if isinstance(args.salt, basestring):
        salt = base64.base64url_decode(args.salt)
    else:
        salt = Random.get_random_bytes(32)

    key, derived_key, salt, count = derive(
        key, salt, klen=klen, digest=digest)

    print "passowrd(b64url)=", base64.base64url_encode(key),
    print "key(b64url)=", base64.base64url_encode(derived_key),
    print "salt(b64url)=", base64.base64url_encode(salt),
    print "key length=", klen,
    print "digest=", args.digest,
    print "count=", count


def command_not_found():
    print "command not found."


def main():
    parser = ArgumentParser(description='PBES2 Key Derivation')
    parser.add_argument('command', help='|'.join(list_commands(__name__)),)
#    parser.add_argument('command_arg', nargs='*')
    args, unknown = parser.parse_known_args()

    globals().get(args.command + "_command", command_not_found)()

if __name__ == '__main__':
    main()
