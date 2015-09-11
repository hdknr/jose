from jose.base import BaseKey, BaseKeyEncryptor
from jose.utils import base64
from jose.jwk import Jwk
from jose.jwa.aes import A128KW, A192KW, A256KW
from jose.jwa.keys import CurveEnum, KeyTypeEnum
import hashlib

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256
from ecdsa import (
    SigningKey, VerifyingKey,
    ellipticcurve as ec)
from ecdsa.ecdsa import Signature
from math import ceil

from struct import pack
import pydoc
from six import b


def ecdsa_dhZ(other_pub, my_priv):
    p = other_pub.pubkey.point * my_priv.privkey.secret_multiplier
    return p.x()


class EcdsaKey(BaseKey):
    '''PYPI ecdsa based key operation
    '''
    def curve_for_bits(self, length):
        return pydoc.locate(
            'ecdsa.curves.NIST{0}p'.format(length))

    @property
    def length(self):
        return int(self.material.curve.name[4:7])

    def generate_key(self, bits):
        self.material = SigningKey.generate(
            curve=self.curve_for_bits(bits))

    @property
    def is_private(self):
        return isinstance(self.material, SigningKey)

    @property
    def is_public(self):
        return isinstance(self.material, VerifyingKey)

    @property
    def private_key(self):
        return self.is_private and self.material or None

    @property
    def public_key(self):
        return self.is_private and \
            self.material.get_verifying_key() or self.material

    @property
    def public_key_tuple(self):
        def _cache():
            material = self.public_key
            self._public_key_tuple = material and (
                self.length,
                material.pubkey.point.x(),
                material.pubkey.point.y(),
            ) or (None, None, None,)
            return self._public_key_tuple

        return getattr(self, '_public_key_tuple', _cache())

    @property
    def private_key_tuple(self):
        def _cache():
            material = self.private_key
            self._private_key_tuple = material and (
                self.length,
                material.privkey.secret_multiplier,
            ) or (None, None, )
            return self._private_key_tuple

        return getattr(self, '_private_key_tuple', _cache())

    def create_material(self, bits, d=None, x=None, y=None):
        curve = self.curve_for_bits(bits)
        if d:
            return SigningKey.from_secret_exponent(d, curve)
        if x and y:
            point = ec.Point(curve.curve, x, y, curve.order)
            return VerifyingKey.from_public_point(point, curve)

    def dhZ(self, other_pub, my_priv):
        return ecdsa_dhZ(other_pub, my_priv)

    def sign_longdigest(self, longdigest):
        '''
        :rtype tuple:   (r, s)
        '''
        return self.private_key.sign_number(longdigest)

    def verify_longdigest(self, longdigest, signature):
        '''
        :param tuple signature: (r, s)
        '''
        return self.public_key.pubkey.verifies(
            longdigest, Signature(*signature))


class Key(EcdsaKey):

    def init_material(self, length=256, crv=CurveEnum.P_256, **kwargs):
        ''' generate new key material '''
        self.generate_key(length or crv.bits)

    def to_jwk(self, jwk, force_public=False):
        '''Set parameters to Jwk '''
        crv, x, y = self.public_key_tuple
        if crv:
            jwk.kty = KeyTypeEnum.EC
            jwk.crv = CurveEnum.create("P-{:d}".format(crv))
            jwk.x = base64.long_to_b64(x)
            jwk.y = base64.long_to_b64(y)

        crv, d = self.private_key_tuple
        if d:
            jwk.d = base64.long_to_b64(d)

    def from_jwk(self, jwk):
        self.material = jwk.d and \
            self.create_material(
                jwk.crv.bits,
                d=base64.long_from_b64(jwk.d)) or \
            self.create_material(
                jwk.crv.bits,
                x=base64.long_from_b64(jwk.x),
                y=base64.long_from_b64(jwk.y),)

    @property
    def block_size(self):
        return int(ceil(self.length / 8.0))

    @property
    def public_jwk(self):
        crv, x, y = self.public_key_tuple
        if crv:
            return Jwk(
                kty=KeyTypeEnum.EC,
                crv=CurveEnum("P-{:d}".format(crv)),
                x=base64.long_to_b64(x),
                y=base64.long_to_b64(y),
            )

    @property
    def private_jwk(self):
        jwk = self.public_jwk
        if jwk:
            crv, d = self.private_key_tuple
            jwk.d = base64.long_to_b64(d)
        return jwk

    def agreement_to(self, other_key, in_bytes=True):
        z = self.dhZ(other_key.public_key, self.private_key)
        if in_bytes:
            return long_to_bytes(z, self.block_size)
        return z

    def thumbprint_fields(self):
        return ['crv', 'kty', 'x', 'y', ]


class EcdsaSigner(object):

    @classmethod
    def decode_signature(cls, bytes_sig):
        length = len(bytes_sig) / 2
        return (
            bytes_to_long(bytes_sig[:length]),
            bytes_to_long(bytes_sig[length:])
        )

    @classmethod
    def encode_signature(cls, signature, block_size=None):
        '''
            :param cls:
            :param tuple signature: signagure tuple (r, s)
            :param int block_size: Key block size to pad "\00"s
        '''
        r, s = signature
        sig = "".join([
            long_to_bytes(r, block_size),
            long_to_bytes(s, block_size),
        ])
        return sig

    @classmethod
    def digest(cls, data):
        return hashlib.new(cls._digester, data).digest()

    @classmethod
    def longdigest(cls, data):
        return int(cls.hexdigest(data), 16)

    @classmethod
    def hexdigest(cls, data):
        return hashlib.new(cls._digester, data).hexdigest()

    @classmethod
    def sign_to_tuple(cls, jwk, data):
        assert jwk.key is not None and jwk.key.is_private
        dig_long = cls.longdigest(data)
        return jwk.key.sign_longdigest(dig_long)

    @classmethod
    def verify_from_tuple(cls, jwk, data, sig_in_tuple):
        assert jwk.key is not None
        assert type(sig_in_tuple) == tuple

        dig_long = cls.longdigest(data)
        return jwk.key.verify_logndigest(dig_long, sig_in_tuple)

    @classmethod
    def sign(cls, jwk, data):
        tuple_sig = cls.sign_to_tuple(jwk, data)
        return cls.encode_signature(tuple_sig, jwk.key.block_size)

    @classmethod
    def verify(cls, jwk, data, signature):
        '''
            :param Jwk jwk: Jwk instannce
            :param str data: source data byte array
            :param str signature: dignature byte array

        '''
        assert jwk.key is not None
        tuple_sig = cls.decode_signature(signature)
        return cls.verify_from_tuple(jwk, data, tuple_sig)


class ES256(EcdsaSigner):
    _digester = 'sha256'


class ES384(EcdsaSigner):
    _digester = 'sha384'


class ES512(EcdsaSigner):
    _digester = 'sha512'


# Other Information used in Concat KDF
# AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo

def other_info(alg, pu, pv, klen):
    return b('').join([
        pack("!I", len(alg)), alg,
        pack("!I", len(pu)), pu,
        pack("!I", len(pv)), pv,
        pack("!I", klen), ])


# Coccat KDF : NIST defines SHA256

def ConcatKDF(agr, dklen, oi, digest_method=SHA256):

    # Digest source
    # counter(in bytes), agreement(in bytes), otherinfo
    def _src(cbn):
        return b("").join([cbn, agr, oi])

    from math import ceil
    from struct import pack

    dkm = b''   # Derived Key Material
    counter = 0
    klen = int(ceil(dklen / 8.0))
    while len(dkm) < klen:
        counter += 1
        counter_b = pack("!I", counter)
        dkm += digest_method.new(_src(counter_b)).digest()

    return dkm[:klen]


# Key Encryptor

class EcdhKeyEncryotor(BaseKeyEncryptor):
    _KEY_WRAP = None

    @classmethod
    def digest_key_bitlength(cls, enc):
        if cls._KEY_WRAP:
            return 8 * cls._KEY_WRAP.key_length()
        else:
            return 8 * enc.encryptor.key_length()

    @classmethod
    def other_info(cls, algid, apu, apv,  klen):
        #: AlgorithmID : enc(ECDH-ES), alg(ECDH-AnnnKW)
        return other_info(algid, apu, apv, klen)

    @classmethod
    def create_key(cls, agr, klen, other_info, cek=None):

        dkey = ConcatKDF(agr, klen, other_info)

        if cls._KEY_WRAP and cek:
            cek_ci = cls._KEY_WRAP.kek_encrypt(dkey, cek)
            return (dkey, cek_ci)
        else:
            return (dkey, None)

    @classmethod
    def provide(cls, enc, jwk, jwe, cek=None, iv=None, *args, **kwargs):
        if cls._KEY_WRAP is None and cek is not None:
            #: CEK must be None for ECDH_ES
            return None

        jwe.apu = jwe.apu or "TODO:RANDOM APU"
        jwe.apv = jwe.apv or "TODO:RANDOM APv"

        if cek:
            pass
        else:
            cek, iv = enc.encryptor.create_key_iv()

        #: parmeters for ECDH
        epk = Jwk.generate(kty=KeyTypeEnum.EC)      # new adhoc key
        agr = epk.key.agreement_to(jwk.key)
        klen = cls.digest_key_bitlength(enc)
        algid = jwe.alg.value if cls._KEY_WRAP else enc.value
        other_info = cls.other_info(algid, jwe.apu, jwe.apv, klen)

        #: create or derived key
        key, cek_ci = cls.create_key(agr, klen, other_info, cek)
        cek = cek if cls._KEY_WRAP else key

        jwe.epk = epk.public_jwk

        return (cek, iv, cek_ci, key)

    @classmethod
    def agree(cls, enc, jwk, jwe, cek_ci, *args, **kwargs):
        agr = jwk.key.agreement_to(jwe.epk.key)  # epk.key == public
        klen = cls.digest_key_bitlength(enc)
        algid = jwe.alg.value if cls._KEY_WRAP else enc.value
        other_info = cls.other_info(algid, jwe.apu, jwe.apv, klen)

        key, _dmy = cls.create_key(agr, klen, other_info)
        if cls._KEY_WRAP:
            return cls._KEY_WRAP.kek_decrypt(key, cek_ci)
        else:
            return key


class ECDH_ES(EcdhKeyEncryotor):
    #: TODO: CEK is produced by Static Public + Ephemeral Private
    #:       but, CEK is not deliverd ( means CEK == '' in message )
    _KEY_WRAP = None


#: TODO: CEK is given
#       and wrapped by secret from Static Public + Ephemeral Private

class ECDH_ES_A128KW(EcdhKeyEncryotor):
    _KEY_WRAP = A128KW


class ECDH_ES_A192KW(EcdhKeyEncryotor):
    _KEY_WRAP = A192KW


class ECDH_ES_A256KW(EcdhKeyEncryotor):
    _KEY_WRAP = A256KW
