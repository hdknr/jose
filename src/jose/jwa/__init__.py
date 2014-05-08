from jose.base import AlgorithmBaseEnum
from encs import KeyEncDict
from sigs import SigDict

__all__ = ['Algorithm', ]

# alg
AlgDict = dict(SigDict, **KeyEncDict)
AlgEnum = type('AlgEnum', (AlgorithmBaseEnum,), AlgDict)
