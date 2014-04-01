# -*- coding: utf-8 -*-

import unittest
from jose.tests import (
    JWT_A1, JWT_A2,
    JWS_A2,
    JWE_A2,
)

from jose.jwk import Jwk
from jose.jwt import Jwt


class TestJwt(unittest.TestCase):

    def test_appendix_a1(self):
        jwk = Jwk(**JWE_A2.jwk_dict)
        jwk.add_to("xxxx", None)

        token = Jwt.parse(JWT_A1.token, "some", "xxxx")

        self.assertEqual(token.iss, "joe")
        self.assertEqual(token.exp, 1300819380)
        self.assertTrue(token['http://example.com/is_root'])

    def test_appendix_a2(self):
        jwk = Jwk(**JWE_A2.jwk_dict)
        jwk.add_to("i_am", None)

        jwk = Jwk(**JWS_A2.jwk_dict)
        jwk.add_to("he_is", None)
        token = Jwt.parse(JWT_A2.nested_token, "he_is", "i_am")

        self.assertEqual(token.iss, "joe")
        self.assertEqual(token.exp, 1300819380)
        self.assertTrue(token['http://example.com/is_root'])


if __name__ == '__main__':
    unittest.main()
