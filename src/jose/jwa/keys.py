from jose import BaseEnum
#


class KeyType(BaseEnum):
    ''' Key Type : JWA Section 6.1 '''
    EC = 'EC'
    RSA = 'RSA'
    oct = 'oct'


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
    crv = ""    #: Curve
    x = ""      #: X Coordinate
    y = ""      #: Y Coordinate
    d = ""      #: ECC Private Key


class Symmetric(object):
    k = ''      #: Key Value
