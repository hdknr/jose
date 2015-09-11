from jose.jwa import keys
from enum import Enum
import pydoc
#


class KeyEncEnum(Enum):
    # JWA 4.2/3 - Encrytpion with RSA
    RSA1_5 = 'RSA1_5'
    RSA_OAEP = 'RSA-OAEP'

    # JWA 4.4 - Wrapping with AES
    A128KW = 'A128KW'
    A192KW = 'A192KW'
    A256KW = 'A256KW'

    # JWA 4.5 - Direct
    DIR = 'dir'

    # JWA 4.6 - Derivation ECDH-ES
    ECDH_ES = 'ECDH-ES'                      # Direct
    ECDH_ES_A128KW = 'ECDH-ES+A128KW'        # Key Wrapping
    ECDH_ES_A192KW = 'ECDH-ES+A192KW'        # Key Wrapping
    ECDH_ES_A256KW = 'ECDH-ES+A256KW'        # Key Wrapping

    # JWA 4.7 - Encryption AES GCM
    GCMA128KW = 'A128GCMKW'
    GCMA192KW = 'A192GCMKW'
    GCMA256KW = 'A256GCMKW'

    # JWA 4.8 - Encryption PBES2
    PBES2_HS256_A128KW = 'PBES2-HS256+A128KW'
    PBES2_HS384_A192KW = 'PBES2-HS384+A192KW'
    PBES2_HS512_A256KW = 'PBES2-HS512+A256KW'

    @property
    def encryptor(self):
        modname = dict(
            A='aes', G='gcm', R='rsa', D='misc',
            E='ec', P='pbes2',
        )[self.name[0]]
        return pydoc.locate("jose.jwa.{0}.{1}".format(modname, self.name))

    @property
    def key_type(self):
        return dict(
            R=keys.KeyTypeEnum.RSA,
            D=keys.KeyTypeEnum.OCT,
            E=keys.KeyTypeEnum.EC,
            G=keys.KeyTypeEnum.OCT,
            P=keys.KeyTypeEnum.OCT,
            A=keys.KeyTypeEnum.OCT,
        )[self.name[0]]

    @property
    def single(self):
        ''' cab be usd for single recipient'''
        return self.name in [
            'ECDH_ES', 'DIR',
        ]

    @classmethod
    def all(cls):
        return [i for i in cls]

    @classmethod
    def values(cls):
        return [i.name for i in cls]

    def __eq__(self, other):
        if isinstance(other, KeyEncEnum):
            return self.value == other.value
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result


KeyEncDict = dict((i.name, i.name) for i in KeyEncEnum)


class EncEnum(Enum):
    A128CBC_HS256 = 'A128CBC-HS256'
    A192CBC_HS384 = 'A192CBC-HS384'
    A256CBC_HS512 = 'A256CBC-HS512'
    GCMA128 = 'A128GCM'
    GCMA192 = 'A192GCM'
    GCMA256 = 'A256GCM'

    @property
    def encryptor(self):
        modname = dict(A='aes', G='gcm')[self.name[0]]
        return pydoc.locate("jose.jwa.{0}.{1}".format(modname, self.name))

    @classmethod
    def all(cls):
        return [i for i in cls]

    @classmethod
    def values(cls):
        return [i.name for i in cls]
