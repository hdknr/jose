from jose import BaseKey
from jose.utils import base64
from jose.jwk import Jwk
from jose.jwa.keys import CurveEnum, KeyTypeEnum
import hashlib

from Crypto.Util.number import long_to_bytes, bytes_to_long
from ecc.Key import Key as EccKey
from ecc import ecdsa
from math import ceil

_jwk_to_pub = lambda jwk: (
    jwk.crv.bits, (
        base64.long_from_b64(jwk.x),
        base64.long_from_b64(jwk.y),
    )
)
_jwk_to_pri = lambda jwk: (
    jwk.crv.bits,
    base64.long_from_b64(jwk.d)
)


class Key(BaseKey):

    def from_jwk(self, jwk):
        if jwk.d:
            self.material = EccKey(
                public_key=_jwk_to_pub(jwk),
                private_key=_jwk_to_pri(jwk))
        else:
            self.material = EccKey(public_key=_jwk_to_pub(jwk))

    def init_material(self, curve=None, **kwargs):
        ''' generate new key material '''
        if isinstance(curve, basestring):
            curve = CurveEnum.create(curve)
        if curve:
            self.material = EccKey.generate(curve.bits)

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

    def digest(self, data):
        return hashlib.new(self._digester, data).digest()

    def longdigest(self, data):
        return int(self.hexdigest(data), 16)

    def hexdigest(self, data):
        return hashlib.new(self._digester, data).hexdigest()

    def sign_to_tuple(self, jwk, data):
        assert jwk.key is not None and jwk.key.is_private
        dig_long = self.longdigest(data)
        r, s = ecdsa.sign(dig_long,
                          jwk.key.private_key._priv)
        return (r, s)

    def verify_from_tuple(self, jwk, data, sig_in_tuple):
        assert jwk.key is not None
        assert type(sig_in_tuple) == tuple

        dig_long = self.longdigest(data)
        return ecdsa.verify(dig_long, sig_in_tuple,
                            jwk.key.public_key._pub)

    def sign(self, jwk, data):
        tuple_sig = self.sign_to_tuple(jwk, data)
        return self.encode_signature(tuple_sig, jwk.key.block_size)

    def verify(self, jwk, data, signature):
        '''
            :param Jwk jwk: Jwk instannce
            :param str data: source data byte array
            :param str signature: dignature byte array

        '''
        assert jwk.key is not None
        tuple_sig = self.decode_signature(signature)
        return self.verify_from_tuple(jwk, data, tuple_sig)


class ES256(EcdsaSigner):
    _digester = 'sha256'


class ES384(EcdsaSigner):
    _digester = 'sha384'


class ES512(EcdsaSigner):
    _digester = 'sha512'


class EcdhKeyEncryotor(object):
    pass


class ECDH_ES(EcdhKeyEncryotor):
    pass


class ECDH_ES_A128KW(EcdhKeyEncryotor):
    pass


class ECDH_ES_A192KW(EcdhKeyEncryotor):
    pass


class ECDH_ES_A245KW(EcdhKeyEncryotor):
    pass
