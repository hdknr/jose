# -*- coding: utf-8 -*-

import unittest
from jose.jwk import Jwk, JwkSet
from jose.jwa.keys import KeyTypeEnum
from jose.jwa import keys


class TestJwk(unittest.TestCase):
    def test_serialize(self):
        '''
        nose2 jose.tests.test_jwk.TestJwk.test_serialize
        '''

        data = ''' { "kty":"RSA" } '''

        jwk = Jwk.from_json(data)
        self.assertEquals(jwk.kty, KeyTypeEnum.RSA)
        self.assertIsNone(jwk.use)

        data = jwk.to_json()
        jwk2 = Jwk.from_json(data)
        self.assertEquals(jwk.kty, jwk2.kty)
        self.assertEquals(jwk.use, jwk2.use)

    def test_generate(self):
        '''
        nose2 jose.tests.test_jwk.TestJwk.test_generate
        '''
        for name, kty in KeyTypeEnum.__members__.items():
            jwk = Jwk.generate(kty=kty, kid="hoge")
            print jwk.to_json(indent=2)

    def test_jwkset(self):
        '''
        nose2 jose.tests.test_jwk.TestJwk.test_jwkset
        '''
        jwkset = JwkSet()
        jwkset.keys.append(Jwk(kid='kidRsa', kty=keys.KeyTypeEnum.RSA))
        jwkset.keys.append(Jwk(kid='kidEc', kty=keys.KeyTypeEnum.EC))
        jwkset.keys.append(Jwk(kid='kidOct', kty=keys.KeyTypeEnum.OCT))

        self.assertEqual(jwkset.get_key(kty=KeyTypeEnum.RSA).kid, 'kidRsa')
        self.assertEqual(jwkset.get_key(kty=KeyTypeEnum.EC).kid, 'kidEc')
        self.assertEqual(jwkset.get_key(kty=KeyTypeEnum.OCT).kid, 'kidOct')



if __name__ == '__main__':
    unittest.main()
