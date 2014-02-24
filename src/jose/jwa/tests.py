# -*- coding: utf-8 -*-

import unittest
from jose.jwa import Algorithm


class TestJwa(unittest.TestCase):

    def test_enum(self):
        hoge = dict(A='a', B='b',)
        Hoge = type('BaseEnum', (), dict(hoge))
        self.assertEquals(Hoge.A, 'a')

    def test_alg(self):
        print dir(Algorithm)
        alg = Algorithm.create('RS256')
        self.assertIsNotNone(alg)
        self.assertEqual(alg, Algorithm.RS256)


if __name__ == '__main__':
    unittest.main()
