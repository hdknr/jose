# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64


class TestCrypto(unittest.TestCase):
    def test_pattern(self):
        from jose.jws import _compact as jws
        from jose.jwe import _compact as jwe

        self.assertIsNotNone(jws.search('aaaa.bbb.ccc'))
        self.assertIsNotNone(jwe.search('aaaa.bbb.ccc.ddd.eee'))


if __name__ == '__main__':
    unittest.main()
