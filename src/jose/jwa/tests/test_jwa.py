# -*- coding: utf-8 -*-

import unittest
from jose.jwa import AlgEnum


class TestJwa(unittest.TestCase):

    def test_enum(self):
        hoge = dict(A='a', B='b',)
        Hoge = type('BaseEnum', (), dict(hoge))
        self.assertEquals(Hoge.A, 'a')

    def test_alg(self):
        print dir(AlgEnum)
        alg = AlgEnum.create('RS256')
        self.assertIsNotNone(alg)
        self.assertEqual(alg, AlgEnum.RS256)

if __name__ == '__main__':
    unittest.main()
