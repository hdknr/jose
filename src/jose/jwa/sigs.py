from jose.base import AlgorithmBaseEnum
from jose.jwa import keys

__all__ = ['SigDict', 'SigEnum', ]
#
SigDict = dict(
    HS256='HS256',
    HS384='HS384',
    HS512='HS512',

    RS256='RS256',
    RS384='RS384',
    RS512='RS512',

    PS256='PS256',
    PS384='PS384',
    PS512='PS512',

    ES256='ES256',
    ES384='ES384',
    ES512='ES512',

    NONE='none',
)


class SigAlgorithmEnum(AlgorithmBaseEnum):
    @property
    def signer(self):
        import rsa
        import ec
        import hmac
        import misc
        mod = dict(H=hmac, R=rsa,
                   P=rsa, E=ec, N=misc)[self.name[0]]
        return getattr(mod, self.name)

    @property
    def key_type(self):
        return dict(
            H=keys.KeyTypeEnum.OCT,
            N=keys.KeyTypeEnum.OCT,
            R=keys.KeyTypeEnum.RSA,
            P=keys.KeyTypeEnum.RSA,
            E=keys.KeyTypeEnum.EC,)[self.name[0]]


SigEnum = type('SigEnum', (SigAlgorithmEnum,), SigDict)
