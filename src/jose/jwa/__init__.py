from jose import AlgorithmBaseEnum
from encs import KeyEncs
from sigs import Sigs

__all__ = ['Algorithm', ]

# alg
Algorithm = type('Algorithm', (AlgorithmBaseEnum,), dict(Sigs, **KeyEncs))
