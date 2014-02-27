# -*- coding: utf-8 -*-

import unittest
from jose.jwa import Algorithm


class TestJwa(unittest.TestCase):

    def test_enum(self):
        hoge = dict(A='a', B='b',)
        Hoge = type('BaseEnum', (), dict(hoge))
        self.assertEquals(Hoge.A, 'a')

    def test_alg(self):
        print dir(Algorithm)
        alg = Algorithm.create('RS256')
        self.assertIsNotNone(alg)
        self.assertEqual(alg, Algorithm.RS256)


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

        print "@@@@ private", dir(pri)
        print pri.keydata, type(pri.keydata)
        print pri.key, type(pri.key)
        print (pri.d, pri.p, pri.q, pri.u, )

        print "@@@@ public", dir(pub)
        print pub.keydata, type(pub.keydata)

        print "@@@ RSA", dir(RSA)

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


if __name__ == '__main__':
    unittest.main()
