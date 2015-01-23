from jose.base import BaseKey, BaseKeyEncryptor
from jose.utils import base64
from jose.jwk import Jwk
from jose.jwa.aes import A128KW, A192KW, A256KW
from jose.jwa.keys import CurveEnum, KeyTypeEnum
import hashlib

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256
from ecc.Key import Key as EccKey
from ecc import ecdsa, elliptic, curves
from math import ceil

from struct import pack


def _jwk_to_pub(jwk):
    return (
        jwk.crv.bits, (
            base64.long_from_b64(jwk.x),
            base64.long_from_b64(jwk.y),)
    )


def _jwk_to_pri(jwk):
    return (
        jwk.crv.bits,
        base64.long_from_b64(jwk.d)
    )


# Compute ECDH
def dhZ(crv, pub, pri):
    return elliptic.mulp(
        crv['a'], crv['b'], crv['p'], pub, pri)[0]


# Curve Parameter
def curve_parameter(fields):
    return dict(
        zip(('bits', 'p', 'N', 'a', 'b', 'G'),
            curves.get_curve(fields)))


class Key(BaseKey):

    def init_material(self, length=256, crv=CurveEnum.P_256, **kwargs):
        ''' generate new key material '''
        length = length or crv.bits
        self.material = EccKey.generate(length)

    @property
    def length(self):
        if self.is_public:
            return self.material._pub[0]
        if self.is_private:
            return self.material._priv[0]
        return 0

    def to_jwk(self, jwk):
        key = self.public_key
        if key:
            jwk.kty = KeyTypeEnum.EC
            jwk.crv = CurveEnum.create("P-{:d}".format(key._pub[0]))
            jwk.x = base64.long_to_b64(key._pub[1][0])
            jwk.y = base64.long_to_b64(key._pub[1][1])

        key = self.private_key
        if key:
            jwk.d = base64.long_to_b64(key._priv[1])

    def from_jwk(self, jwk):
        if jwk.d:
            self.material = EccKey(
                public_key=_jwk_to_pub(jwk),
                private_key=_jwk_to_pri(jwk))
        else:
            self.material = EccKey(public_key=_jwk_to_pub(jwk))

    @property
    def block_size(self):
        return int(ceil(self.public_key._pub[0] / 8.0))

    @property
    def is_private(self):
        return self.material and self.material.private()

    @property
    def is_public(self):
        return self.material and not self.material.private()

    @property
    def private_key(self):
        return self.is_private and self.material or None

    @property
    def public_key(self):
        if self.is_public:
            return self.material
        if self.is_private:
            return EccKey.decode(self.material.encode())
        return None

    @property
    def public_tuple(self):
        self.material._pub

    @property
    def private_tuple(self):
        return self.material._priv if self.is_private else {}

    @property
    def public_jwk(self):
        key = self.public_key
        if not key:
            return None
        jwk = Jwk(
            kty=KeyTypeEnum.EC,
            crv=CurveEnum.create("P-{:d}".format(key._pub[0])),
            x=base64.long_to_b64(key._pub[1][0]),
            y=base64.long_to_b64(key._pub[1][1]),
        )
        return jwk

    @property
    def private_jwk(self):
        jwk = self.public_jwk
        if jwk:
            jwk.d = base64.long_to_b64(self.material._priv[1])
        return jwk

    def agreement_to(self, other_key, in_bytes=True):
        pri = self.private_key
        if pri is None:
            raise Exception("no private key")

        pub = other_key.public_key
        _crv = curve_parameter(pri._priv[0])
        z = dhZ(_crv, pub._pub[1], pri._priv[1])

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
    def encode_signature(cls, (r, s), block_size=None):
        '''
            :param cls:
            :param (r, s): signagure tuple
            :param int block_size: Key block size to pad "\00"s
        '''
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
        r, s = ecdsa.sign(dig_long,
                          jwk.key.private_key._priv)
        return (r, s)

    @classmethod
    def verify_from_tuple(cls, jwk, data, sig_in_tuple):
        assert jwk.key is not None
        assert type(sig_in_tuple) == tuple

        dig_long = cls.longdigest(data)
        return ecdsa.verify(dig_long, sig_in_tuple,
                            jwk.key.public_key._pub)

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
    return ''.join([
        pack("!I", len(alg)), alg,
        pack("!I", len(pu)), pu,
        pack("!I", len(pv)), pv,
        pack("!I", klen), ])


# Coccat KDF : NIST defines SHA256

def ConcatKDF(agr, dklen, oi, digest_method=SHA256):

    # Digest source
    # counter(in bytes), agreement(in bytes), otherinfo
    def _src(cbn):
        return "".join([cbn, agr, oi])

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
        epk = Jwk.generate(kty=KeyTypeEnum.EC)
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
        agr = jwk.key.agreement_to(jwe.epk.key)  #: epk.key == public
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
