# -*- coding: utf-8 -*-

import unittest


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

    def test_exchage(self):
        from ecdsa import SigningKey, NIST521p

        alice_own = SigningKey.generate(curve=NIST521p)
        bob_own = SigningKey.generate(curve=NIST521p)

        alice_pri = alice_own.privkey
        alice_pub = alice_pri.public_key

        bob_pri = bob_own.privkey
        bob_pub = bob_pri.public_key

        alice_pub_point = alice_pub.point
        bob_pub_point = bob_pub.point

        print alice_pub_point, bob_pub_point

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
