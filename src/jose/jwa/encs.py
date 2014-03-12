from jose import AlgorithmBaseEnum, BaseEnum
#

KeyEncDict = dict(
    # JWA 4.2/3 - Encrytpion with RSA
    RSA1_5='RSA1_5',
    RSA_OAEP='RSA-OAEP',

    # JWA 4.4 - Wrapping with AES
    A128KW='A128KW',
    A192KW='A192KW',
    A256KW='A256KW',

    # JWA 4.5 - Direct
    DIR='dir',

    # JWA 4.6 - Derivation ECDH-ES
    ECDH_ES='ECDH-ES',                      # Direct
    ECDH_ES_A128KW='ECDH-ES+A128KW',        # Key Wrapping
    ECDH_ES_A192KW='ECDH-ES+A192KW',        # Key Wrapping
    ECDH_ES_A256KW='ECDH-ES+A256KW',        # Key Wrapping

    # JWA 4.7 - Encryption AES GCM
    GCMA128KW='A128GCMKW',
    GCMA192KW='A192GCMKW',
    GCMA256KW='A256GCMKW',

    # JWA 4.8 - Encryption PBES2
    PBES2_HS256_A128KW='PBES2-HS256+A128KW',
    PBES2_HS384_A192KW='PBES2-HS384+A192KW',
    PBES2_HS512_A256KW='PBES2-HS512+A256KW',
)


class KeyEncEnumBase(AlgorithmBaseEnum):
    @classmethod
    def encryptor(self):
        import rsa
        import ec
        import pbes2
        import gcm
        import aes
        return getattr(
            dict(R=rsa, E=ec, A=aes, P=pbes2, G=gcm)[self.name[0]],
            self.name)

#    def get_encryptor(self):
#        return self.encryptor()

KeyEncEnum = type('KeyEncEnum', (KeyEncEnumBase,), KeyEncDict)


# enc
EncDict = dict(
    A128CBC_HS256='A128CBC-HS256',
    A192CBC_HS384='A192CBC-HS384',
    A256CBC_HS512='A256CBC-HS512',
    GCMA128='A128GCM',
    GCMA192='A192GCM',
    GCMA256='A256GCM',
)


class EncEnumBase(BaseEnum):
    def encryptor(self):
        import gcm
        import aes
        return getattr(
            dict(A=aes, G=gcm)[self.name[0]],
            self.name)

    def get_encryptor(self):
        return self.encryptor()


EncEnum = type('EncEnum', (EncEnumBase,), EncDict)
