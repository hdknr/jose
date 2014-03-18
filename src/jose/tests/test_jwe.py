# -*- coding: utf-8 -*-

import unittest

from jose.jwe import Jwe, ZipEnum
from jose.jwa.encs import KeyEncEnum


class TestJwe(unittest.TestCase):

    def test_simple(self):
        data = '{ "alg": "RSA1_5",  "zip": "DEF" }'
        jwe1 = Jwe.from_json(data)
        print dir(jwe1)
        self.assertEqual(jwe1.alg, KeyEncEnum.RSA1_5)

    def test_merge(self):
        jwe1 = Jwe.from_json('{ "alg": "RSA1_5"}')
        jwe2 = Jwe.from_json('{ "zip": "DEF"}')
        jwe3 = jwe1.merge(jwe2)

        self.assertEqual(jwe3.alg, KeyEncEnum.RSA1_5)
        self.assertEqual(jwe3.zip, ZipEnum.DEF)
        self.assertIsNone(jwe1.zip)
        self.assertIsNone(jwe2.alg)

if __name__ == '__main__':
    unittest.main()
