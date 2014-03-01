from jose import AlgorithmBaseEnum

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
    def get_class(self):
        import rsa
        import ec
        import hmac
        import misc
        mod = dict(H=hmac, R=rsa,
                   P=rsa, E=ec, N=misc)[self.name[0]]
        return getattr(mod, self.name)


SigEnum = type('SigEnum', (SigAlgorithmEnum,), SigDict)
