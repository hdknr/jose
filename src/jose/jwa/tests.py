# -*- coding: utf-8 -*-

import unittest
from jose.jwa import AlgEnum


class TestJwa(unittest.TestCase):

    def test_enum(self):
        hoge = dict(A='a', B='b',)
        Hoge = type('BaseEnum', (), dict(hoge))
        self.assertEquals(Hoge.A, 'a')

    def test_alg(self):
        print dir(AlgEnum)
        alg = AlgEnum.create('RS256')
        self.assertIsNotNone(alg)
        self.assertEqual(alg, AlgEnum.RS256)


class TestRsaKey(unittest.TestCase):

    def test_keys(self):
        from Crypto.PublicKey import RSA

        size = 1024
        pri = RSA.generate(size)
        pub = pri.publickey()
        pri_pem = pri.exportKey("PEM")
        pub_pem = pub.exportKey("PEM")
        self.assertEqual(pri.n, pub.n)
        self.assertEqual(pri.e, pub.e)

        pri2 = RSA.importKey(pri_pem)
        pub2 = RSA.importKey(pub_pem)

        self.assertEqual(pri2.exportKey('PEM'), pri_pem)
        self.assertEqual(pub2.exportKey('PEM'), pub_pem)

        pub3 = RSA.RSAImplementation().construct((pub.n, pub.e,))
        pri3 = RSA.RSAImplementation().construct(
            (pri.n, pri.e, pri.d, pri.p, pri.q, pri.u,))

        self.assertEqual(pub3.n, pub2.n)
        self.assertEqual(pub3.e, pub2.e)
        self.assertEqual(pri3.d, pri2.d)
        self.assertEqual(pri3.p, pri2.p)
        self.assertEqual(pri3.q, pri2.q)
        self.assertEqual(pri3.u, pri2.u)

        print pri.keydata, type(pri.keydata)
        print pri.key, type(pri.key)
        print (pri.d, pri.p, pri.q, pri.u, )

        print pub.keydata, type(pub.keydata)

        from uuid import uuid1
        rnd = uuid1().int
        msg = "Summer Breeze"

        from hashlib import sha256
        dig = sha256(msg).digest()
        sig = pri.sign(dig, rnd)
        print "@@@ signature", sig
        self.assertTrue(pub.verify(dig, sig))

    def test_public(self):

        n = [
            '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx',
            '4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs',
            'tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2',
            'QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI',
            'SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb',
            'w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
        ]
        e = "AQAB"

        from jose.utils import base64

        ln = base64.long_from_b64(''.join(n))
        le = base64.long_from_b64(e)

        from Crypto.PublicKey import RSA
        pub = RSA.RSAImplementation().construct((ln, le,))

        print pub.exportKey('PEM')

    def test_jwk(self):
        from jose.jwa.keys import KeyTypeEnum
        from jose.jwa.rsa import Key

        # void key
        key = KeyTypeEnum.RSA.create_key()
        self.assertTrue(isinstance(key, Key))
        self.assertEqual(key.kty, KeyTypeEnum.RSA)

        self.assertFalse(key.is_public)
        self.assertFalse(key.is_private)
        self.assertIsNone(key.material)
        self.assertIsNone(key.public_key)
        self.assertIsNone(key.private_key)
        self.assertIsNone(key.public_jwk)
        self.assertIsNone(key.private_jwk)

        # new private key
        key.init_material()
        self.assertTrue(key.is_private)
        self.assertFalse(key.is_public)
        self.assertIsNotNone(key.material)
        self.assertIsNotNone(key.public_key)
        self.assertIsNotNone(key.private_key)
        self.assertIsNotNone(key.public_jwk)
        self.assertIsNotNone(key.private_jwk)

        pri_jwk = key.private_jwk
        pub_jwk = key.public_jwk
        self.assertEqual(pri_jwk.n, pub_jwk.n)
        self.assertEqual(pri_jwk.e, pub_jwk.e)
        self.assertEqual(pub_jwk.d, '')

        pub_new = KeyTypeEnum.RSA.create_key(jwk=pub_jwk)
        pri_new = KeyTypeEnum.RSA.create_key(jwk=pri_jwk)
        self.assertEqual(key.public_tuple, pub_new.public_tuple)
        self.assertEqual(key.private_tuple, pri_new.private_tuple)


class TestEcKey(unittest.TestCase):
    def test_generate(self):
        from ecdsa import SigningKey, NIST521p

        sk = SigningKey.generate(curve=NIST521p)
        pri = sk.privkey
        pub = pri.public_key
        param = dict(
            crv=sk.curve,
            x=pub.point.x(),
            y=pub.point.y(),
            d=pri.secret_multiplier)

        # Curve
        from ecdsa.ellipticcurve import Point, CurveFp
        from ecdsa.ecdsa import curve_521

        self.assertTrue(isinstance(curve_521, CurveFp))
        self.assertTrue(isinstance(param['crv'].curve, CurveFp))
        self.assertEqual(curve_521, param['crv'].curve)
        self.assertEqual(pub.point.curve(), curve_521)

        # Point
        p_new = Point(curve_521, param['x'], param['y'])
        self.assertEqual(p_new, pub.point)
        self.assertTrue(isinstance(pub.point, Point))

        # Public Key
        from ecdsa.ecdsa import Public_key, generator_521
        self.assertEqual(generator_521, pub.generator)
        pub_new = Public_key(generator_521, p_new)

        # Private Key
        from ecdsa.ecdsa import Private_key
        pri_new = Private_key(pub_new, param['d'])

        # Signature
        from ecdsa.ecdsa import string_to_int, Signature
        from hashlib import sha512
        from uuid import uuid1
        rnd = uuid1().int
        msg = "hello, it's me."
        digest = string_to_int(sha512(msg).digest())
        signature_new = pri_new.sign(digest, rnd)
        signature_old = pri.sign(digest, rnd)
        self.assertTrue(isinstance(signature_new, Signature))
        self.assertEqual(signature_new.r, signature_old.r)
        self.assertEqual(signature_new.s, signature_old.s)
        self.assertEqual(type(signature_new.r), long)
        self.assertEqual(type(signature_new.s), long)

        #Verify
        print pub.verifies(digest, signature_new)
        print pub_new.verifies(digest, signature_old)

        #
        print dir(pri_new)
        print dir(pub_new)
        print dir(pub_new.curve)

    def test_jwk(self):
        from jose.jwa.keys import KeyTypeEnum, CurveEnum
        from jose.jwa.ec import Key

        # void key
        key = KeyTypeEnum.EC.create_key()
        self.assertTrue(isinstance(key, Key))
        self.assertEqual(key.kty, KeyTypeEnum.EC)

        self.assertFalse(key.is_public)
        self.assertFalse(key.is_private)
        self.assertIsNone(key.material)
        self.assertIsNone(key.public_key)
        self.assertIsNone(key.private_key)
        self.assertIsNone(key.public_jwk)
        self.assertIsNone(key.private_jwk)

        # new private key
        key.init_material(curve=CurveEnum.P_256)
        self.assertTrue(key.is_private)
        self.assertFalse(key.is_public)
        self.assertIsNotNone(key.material)
        self.assertIsNotNone(key.public_key)
        self.assertIsNotNone(key.private_key)
        self.assertIsNotNone(key.public_jwk)
        self.assertIsNotNone(key.private_jwk)

        pri_jwk = key.private_jwk
        pub_jwk = key.public_jwk
        print pri_jwk.to_json()
        print pub_jwk.to_json()
        self.assertEqual(pri_jwk.n, pub_jwk.n)
        self.assertEqual(pri_jwk.e, pub_jwk.e)
        self.assertEqual(pub_jwk.d, '')

        pub_new = KeyTypeEnum.EC.create_key(jwk=pub_jwk)
        pri_new = KeyTypeEnum.EC.create_key(jwk=pri_jwk)
        self.assertEqual(key.public_tuple, pub_new.public_tuple)
        self.assertEqual(key.private_tuple, pri_new.private_tuple)

        # Signature
        from ecdsa.ecdsa import string_to_int, Signature
        from hashlib import sha512
        from uuid import uuid1
        rnd = uuid1().int
        msg = "hello, it's me."
        digest = string_to_int(sha512(msg).digest())
        signature_new = pri_new.material.sign(digest, rnd)
        self.assertTrue(isinstance(signature_new, Signature))
        self.assertEqual(type(signature_new.r), long)
        self.assertEqual(type(signature_new.s), long)

        #Verify
        self.assertTrue(
            pub_new.material.verifies(digest, signature_new))

if __name__ == '__main__':
    unittest.main()
