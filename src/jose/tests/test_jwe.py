# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64


from jose.jwe import Jwe
from jose.jwa.encs import KeyEncEnum


class TestJwe(unittest.TestCase):

    def test_simple(self):
        data = '{ "alg": "RSA1_5",  "zip": "DEF" }'
        jwe1 = Jwe.from_json(data)
        print dir(jwe1)
        self.assertEqual(jwe1.alg, KeyEncEnum.RSA1_5)


if __name__ == '__main__':
    unittest.main()
