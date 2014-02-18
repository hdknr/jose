from jose import BaseEnum

# kty

KeyTypes = dict(
    EC='EC',
    RSA='RSA',
    OCT='oct',
)

KeyType = type('KeyType', (BaseEnum,), KeyTypes)

# crv

Curves = dict(
    P_256='P-256',
    P_384='P-384',
    P_521='P-521',
)

Curve = type('Curve', (BaseEnum,), Curves)


class RSA(object):
    n = ""      #: Modulus
    e = ""      #: Exponent

    class OtherPrime:
        ''' Other Primes Info class '''
        r = ""  #: Prime Factor
        d = ""  #: Factor CRT Exponent
        t = ""  #: Factor CRT Coefficient

    d = ""      #: Private Exponent
    p = ""      #: First Prime Factor
    q = ""      #: Second Prime Factor
    dp = ""     #: Second Factor CRT Exponent
    dq = ""     #: Second Factor CRT Exponent
    qi = ""     #: First CRT Coefficient
    oth = None  #: List of OtherPrime


class EC(object):
    crv = ""    #: jwa.Curve
    x = ""      #: X Coordinate
    y = ""      #: Y Coordinate
    d = ""      #: ECC Private Key


class Symmetric(object):
    k = ''      #: Key Value
