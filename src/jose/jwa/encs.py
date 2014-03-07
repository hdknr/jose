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
    A128GCMKW='A128GCMKW',
    A192GCMKW='A192GCMKW',
    A256GCMKW='A256GCMKW',

    # JWA 4.8 - Encryption PBES2
    PBES2_HS256_A128KW='PBES2-HS256+A128KW',
    PBES2_HS384_A192KW='PBES2-HS384+A192KW',
    PBES2_HS512_A256KW='PBES2-HS512+A256KW',
)

KeyEncEnum = type('KeyEncEnum', (AlgorithmBaseEnum,), KeyEncDict)


# enc
EncDict = dict(
    A128CBC_HS256='A128CBC-HS256',
    A192CBC_HS384='A192CBC-HS384',
    A256CBC_HS512='A256CBC-HS512',
    A128GCM='A128GCM',
    A192GCM='A192GCM',
    A256GCM='A256GCM',
)

EncEnum = type('EncEnum', (BaseEnum,), EncDict)
