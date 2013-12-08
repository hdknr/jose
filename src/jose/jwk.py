from configurations import  configuration
#
class RSA:
    class OtherPrime:
        r = ""
        d = ""
        t = ""

    n   = ""
    e   = ""
    p   = ""
    q   = ""
    dp  = ""
    dq  = ""
    qi  = ""
    oth = None  #: List of OtherPrime

class EC:
    crt =""
    x   =""
    y   =""

class Jwk(RSA,EC):
    kty=""
    use=""
    alg=""
    kid=""
    d  =""     #: Private Key(EC) , Private Exponent(RSA)
    k  =""     #: shared key

class JwkSet:
    def save(self):
        pass

class JwkPair:
    @classmethod
    def create_rsa_pair(bits = 2048):
        return JwkPair()

class JwkPairSet:
    def __init__(self,entity_id):
        self.entity_id = entity_id 
