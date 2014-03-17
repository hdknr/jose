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

    def test_jwkset(self):
        jwkset = JwkSet()
        jwkset.keys.append(Jwk(kid='kidRsa', kty=keys.KeyTypeEnum.RSA))
        jwkset.keys.append(Jwk(kid='kidEc', kty=keys.KeyTypeEnum.EC))
        jwkset.keys.append(Jwk(kid='kidOct', kty=keys.KeyTypeEnum.OCT))
        jwkset.save()

        jwkset2 = JwkSet.load()
        self.assertEqual(jwkset2.get(kty=KeyTypeEnum.RSA).kid, 'kidRsa')
        self.assertEqual(jwkset2.get(kty=KeyTypeEnum.EC).kid, 'kidEc')
        self.assertEqual(jwkset2.get(kty=KeyTypeEnum.OCT).kid, 'kidOct')

        jwkset3 = JwkSet()
        jwkset3.keys.append(Jwk.generate(kty=KeyTypeEnum.OCT))
        jwkset3.keys.append(Jwk.generate(kty=KeyTypeEnum.RSA))
        jwkset3.keys.append(Jwk.generate(kty=KeyTypeEnum.EC))
        jwkset3.save()


if __name__ == '__main__':
    unittest.main()
