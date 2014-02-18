# -*- coding: utf-8 -*-

import unittest
from jose import BaseEnum


class TestJwa(unittest.TestCase):

    def test_enum(self):
        hoge = dict(A='a', B='b',)
        Hoge = type('BaseEnum',(),dict(hoge))
        self.assertEquals(Hoge.A, 'a')

if __name__ == '__main__':
    unittest.main()
