# -*- coding: utf-8 -*-

import unittest
from jose.tests import (
    JWT_A1, JWT_A2,
    JWS_A2,
    JWE_A2,
)

from jose.jwk import Jwk, JwkSet
from jose.jwt import Jwt
from jose.crypto import KeyOwner
from jose.jwa.keys import KeyTypeEnum


class TestEntity(KeyOwner):
    def __init__(self, identifier, jku, jwkset=None):
        self.identifier = identifier 
        self.jku = jku 
        self.jwkset = jwkset or JwkSet(
            keys=[
                Jwk.generate(KeyTypeEnum.RSA),
                Jwk.generate(KeyTypeEnum.EC),
                Jwk.generate(KeyTypeEnum.OCT),
            ]   
        )   

    def get_key(self, crypto, *args, **kwargs):
        return self.jwkset.get_key(
            crypto.key_type, kid=crypto.kid
        )   

class TestJwt(unittest.TestCase):

    def test_appendix_a1(self):
        '''
        nose2 jose.tests.test_jwt.TestJwt.test_appendix_a1
        '''
        sender = TestEntity(
            "http://sender",  "http://sender/jwkset",
        )
        receiver = TestEntity(
            "http://receiver",  "http://receiver/jwkset",
            JwkSet(keys=[Jwk(**JWE_A2.jwk_dict)])
        )

        token = Jwt.parse(JWT_A1.token, sender, receiver)

        self.assertEqual(token.iss, "joe")
        self.assertEqual(token.exp, 1300819380)
        self.assertTrue(token['http://example.com/is_root'])

    def test_appendix_a2(self):
        '''
        nose2 jose.tests.test_jwt.TestJwt.test_appendix_a2

        '''
        sender = TestEntity(
            "http://sender",  "http://sender/jwkset",
            JwkSet(keys=[Jwk(**JWE_A2.jwk_dict)])
        )
        receiver = TestEntity(
            "http://receiver",  "http://receiver/jwkset",
            JwkSet(keys=[Jwk(**JWE_A2.jwk_dict)])
        )

        token = Jwt.parse(JWT_A2.nested_token, sender, receiver)

        self.assertEqual(token.iss, "joe")
        self.assertEqual(token.exp, 1300819380)
        self.assertTrue(token['http://example.com/is_root'])


if __name__ == '__main__':
    unittest.main()
