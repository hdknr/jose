from jose import BaseEnum
import rsa
import ec
import oct


# kty

KeyTypeDict = dict(
    EC='EC',
    RSA='RSA',
    OCT='oct',
)


class BaseKeyTypeEnum(BaseEnum):

    def get_class(self, *args, **kwargs):
        return dict(
            RSA=rsa.Key,
            EC=ec.Key,
            oct=oct.Key,
        )[self.value]

    def get_loader(self, *args, **kwargs):
        return self.get_class()(*args, **kwargs)


KeyTypeEnum = type('KeyTypeEnum', (BaseKeyTypeEnum,), KeyTypeDict)

# crv

CurveDict = dict(
    P_256='P-256',
    P_384='P-384',
    P_521='P-521',
)

CurveEnum = type('Curve', (BaseEnum,), CurveDict)


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
