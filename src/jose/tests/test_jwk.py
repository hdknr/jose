# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64
from jose.jwk import Jwk
from jose.jwa.keys import KeyTypeEnum


class TestJwk(unittest.TestCase):
    def test_serialize(self):
        data = ''' { "kty":"RSA" } '''

        jwk = Jwk.from_json(data)
        self.assertEquals(jwk.kty, KeyTypeEnum.RSA)
        self.assertIsNone(jwk.use)

        data = jwk.to_json()
        jwk2 = Jwk.from_json(data)
        self.assertEquals(jwk.kty, jwk2.kty)
        self.assertEquals(jwk.use, jwk2.use)



if __name__ == '__main__':
    unittest.main()
