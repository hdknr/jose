from jose.base import AlgorithmBaseEnum
from jose.jwa.encs import KeyEncDict
from jose.jwa.sigs import SigDict

__all__ = ['Algorithm', ]

# alg
AlgDict = dict(SigDict, **KeyEncDict)
AlgEnum = type('AlgEnum', (AlgorithmBaseEnum,), AlgDict)
