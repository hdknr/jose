from jose import AlgorithmBaseEnum
from encs import KeyEncDict
from sigs import SigDict

__all__ = ['Algorithm', ]

# alg
Algorithm = type('Algorithm',
                 (AlgorithmBaseEnum,), dict(SigDict, **KeyEncDict))
