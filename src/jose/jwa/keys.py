from jose.base import BaseEnum
from enum import Enum


# kty

class KeyTypeEnum(Enum):
    EC = 'EC'
    RSA = 'RSA'
    OCT = 'oct'

    def get_key_class(self, *args, **kwargs):
        from . import (rsa, ec, hmac)
        return dict(
            RSA=rsa.Key,
            EC=ec.Key,
            OCT=hmac.Key,
        )[self.name]

    def create_key(self, *args, **kwargs):
        return self.get_key_class()(self, *args, **kwargs)


# crv


class CurveEnum(Enum):
    P_256 = 'P-256'
    P_384 = 'P-384'
    P_521 = 'P-521'

    @property
    def bits(self):
        return int(self.name[2:])

    @classmethod
    def from_bits(cls, bits):
        if isinstance(bits, int):
            return cls.create('P-%d' % bits)


class RSAOtherPrime(object):
    _fields = dict(
        r="",  #: Prime Factor
        d="",  #: Factor CRT Exponent
        t="",  #: Factor CRT Coefficient
    )


class RSA(object):
    _fields = dict(
        n="",      #: Modulus
        e="",      #: Exponent
        d="",      #: Private Exponent
        p="",      #: First Prime Factor
        q="",      #: Second Prime Factor
        dp="",     #: Second Factor CRT Exponent
        dq="",     #: Second Factor CRT Exponent
        qi="",     #: First CRT Coefficient
        oth=None,  #: List of OtherPrime
    )


class EC(object):
    _fields = dict(
        crv="",    #: jwa.CurveEnum
        x="",      #: X Coordinate
        y="",      #: Y Coordinate
        d="",      #: ECC Private Key
    )


class Symmetric(object):
    _fields = dict(
        k="",      #: Shared key
    )


if __name__ == '__main__':
    for kty in ['RSA', 'EC', 'oct']:
        assert KeyTypeEnum.create(kty) is not None
