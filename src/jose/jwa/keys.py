from jose import BaseEnum

# kty

KeyTypeDict = dict(
    EC='EC',
    RSA='RSA',
    OCT='oct',
)

KeyTypeEnum = type('KeyType', (BaseEnum,), KeyTypeDict)

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
        crv="",    #: jwa.Curve
        x="",      #: X Coordinate
        y="",      #: Y Coordinate
        d="",      #: ECC Private Key
    )


class Symmetric(object):
    _fields = dict(
        k="",      #: Shared key
    )