# -*- coding: utf-8 -*-

import unittest
from jose.jwk import Jwk, JwkSet
from jose.jwa.keys import KeyTypeEnum
from jose.jwa import keys


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

    def test_generate(self):
        for name, kty in KeyTypeEnum.__members__.items():
            jwk = Jwk.generate(kty=kty, kid="hoge")
            print jwk.to_json(indent=2)

    def test_jwkset(self):
        jwkset = JwkSet()
        jwkset.keys.append(Jwk(kid='kidRsa', kty=keys.KeyTypeEnum.RSA))
        jwkset.keys.append(Jwk(kid='kidEc', kty=keys.KeyTypeEnum.EC))
        jwkset.keys.append(Jwk(kid='kidOct', kty=keys.KeyTypeEnum.OCT))
        jwkset.save('owner')

        jwkset2 = JwkSet.load('owner')
        self.assertEqual(jwkset2.get_key(kty=KeyTypeEnum.RSA).kid, 'kidRsa')
        self.assertEqual(jwkset2.get_key(kty=KeyTypeEnum.EC).kid, 'kidEc')
        self.assertEqual(jwkset2.get_key(kty=KeyTypeEnum.OCT).kid, 'kidOct')

        jwkset3 = JwkSet()
        jwkset3.keys.append(Jwk.generate(kty=KeyTypeEnum.OCT))
        jwkset3.keys.append(Jwk.generate(kty=KeyTypeEnum.RSA))
        jwkset3.keys.append(Jwk.generate(kty=KeyTypeEnum.EC))
        jwkset3.save('owner')


if __name__ == '__main__':
    unittest.main()
