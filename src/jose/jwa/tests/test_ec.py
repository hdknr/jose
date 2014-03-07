# -*- coding: utf-8 -*-

import unittest


class TestEcKeyEcc(unittest.TestCase):

    def test_generate(self):
        from ecc.Key import Key

        pri = Key.generate(521)
        self.assertTrue(isinstance(pri, Key))
        self.assertTrue(pri.private())

        pub = Key.decode(pri.encode())
        self.assertTrue(isinstance(pub, Key))
        self.assertFalse(pub.private())

        msg = "hello, it's me."
        sig = pri.sign(msg, hashfunc='sha512')  # default sha256
        self.assertTrue(pub.verify(msg, sig, hashfunc='sha512'))

    def test_dhZ(self):
        from ecc.Key import Key

        # Party V(recepient) declares a satic key pair
        curve_bits = 521
        v_stc = Key.generate(curve_bits)

        # and advertise to Party U(Sender)
        v_pub = Key.decode(v_stc.encode())

        # Party U provides a ephemeral key
        u_epk = Key.generate(v_pub._pub[0])

        # Getting NIST Curve
        from ecc.curves import get_curve
        from ecc.elliptic import mulp

        _curve = lambda bits:  dict(
            zip(('bits', 'p', 'N', 'a', 'b', 'G'),
                get_curve(bits)))
        # Compute ECDH
        _dhZ = lambda crv, pub, pri: mulp(
            crv['a'], crv['b'], crv['p'], pub, pri)[0]

        # Party U compute
        u_crv = _curve(u_epk._priv[0])
        shared_secret_u = _dhZ(u_crv, v_pub._pub[1], u_epk._priv[1])

        # Party V recive Epemeral Public Key
        v_epk = Key.decode(u_epk.encode())
        # Party V compute
        shared_secret_v = _dhZ(u_crv, v_epk._pub[1], v_stc._priv[1])

        # Secrete Agreeed!
        self.assertEqual(shared_secret_u, shared_secret_v)

    def test_ecdh(self):
        '''
https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#appendix-C
        '''

        v_stc_material = {
            "kty": "EC",
            "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d": "0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"
        }

        u_epk_material = {
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        }

        import re
        from jose.utils import base64
        _to_pub = lambda km: (
            int(re.search(r"P-(\d+)$", "P-256").group(1)),
            (base64.long_from_b64(km['x']),
             base64.long_from_b64(km['y']))
        )
        _to_pri = lambda km: (
            int(re.search(r"P-(\d+)$", "P-256").group(1)),
            base64.long_from_b64(km['d'])
        )

        from ecc.Key import Key
        v_stc = Key(
            public_key=_to_pub(v_stc_material),
            private_key=_to_pri(v_stc_material)
        )

        v_pub = Key.decode(v_stc.encode())

        # Party U provides a ephemeral key
        u_epk = Key(
            public_key=_to_pub(u_epk_material),
            private_key=_to_pri(u_epk_material)
        )

        # Getting NIST Curve
        from ecc.curves import get_curve
        from ecc.elliptic import mulp

        _curve = lambda bits:  dict(
            zip(('bits', 'p', 'N', 'a', 'b', 'G'),
                get_curve(bits)))

        # Compute ECDH
        _dhZ = lambda crv, pub, pri: mulp(
            crv['a'], crv['b'], crv['p'], pub, pri)[0]

        # Party U compute
        u_crv = _curve(u_epk._priv[0])
        shared_secret_u = _dhZ(u_crv, v_pub._pub[1], u_epk._priv[1])

        from Crypto.Util.number import long_to_bytes
        from math import ceil

        block_size = int(ceil(u_epk._priv[0] / 8.0))
        # bit number(512 )  / 8 -> octets
        Zu = long_to_bytes(shared_secret_u, block_size)

        Z_jwa = [158, 86, 217, 29, 129, 113, 53,
                 211, 114, 131, 66, 131, 191, 132,
                 38, 156, 251, 49, 110, 163, 218,
                 128, 106, 72, 246, 218, 167, 121,
                 140, 254, 144, 196]

        self.assertEqual([ord(i) for i in Zu], Z_jwa)

        # Other Information used in Concat KDF
        # AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
        from struct import pack
        _otherInfo = lambda alg, pu, pv, klen: ''.join([
            pack("!I", len(alg)),
            alg,
            pack("!I", len(pu)),
            pu,
            pack("!I", len(pv)),
            pv,
            pack("!I", klen),
        ])

        oi_u = _otherInfo(
            "A128GCM",
            "Alice",
            "Bob",
            16 * 8,     # A128GCM
        )

        oi_jwa = [
            0, 0, 0, 7,
            65, 49, 50, 56, 71, 67, 77,
            0, 0, 0, 5,
            65, 108, 105, 99, 101,
            0, 0, 0, 3,
            66, 111, 98,
            0, 0, 0, 128]

        self.assertEqual([ord(i) for i in oi_u], oi_jwa)

        # Coccat KDF : NIST defines SHA256
        from Crypto.Hash import SHA256

        def _ConcatKDF(Z, dkLen, otherInfo,
                       digest_method=SHA256):
            _src = lambda counter_bytes: "".join([
                counter_bytes, Z, otherInfo])

            from math import ceil
            from struct import pack

            dkm = b''   # Derived Key Material
            counter = 0
            klen = int(ceil(dkLen / 8.0))
            while len(dkm) < klen:
                counter += 1
                counter_b = pack("!I", counter)
                dkm += digest_method.new(_src(counter_b)).digest()

            return dkm[:klen]

        _derived_key_u = _ConcatKDF(Zu, 16 * 8, oi_u)

        # Party V recive Epemeral Public Key
        v_epk = Key.decode(u_epk.encode())
        Zv = long_to_bytes(
            _dhZ(u_crv, v_epk._pub[1], v_stc._priv[1]),
            block_size)

        _derived_key_v = _ConcatKDF(Zv, 16 * 8, oi_u)

        self.assertEqual(_derived_key_u, _derived_key_v)

        kd_jwa = [
            86, 170, 141, 234, 248, 35, 109, 32,
            92, 34, 40, 205, 113, 167, 16, 26]

        self.assertEqual([ord(i) for i in _derived_key_u], kd_jwa)

        self.assertEqual("VqqN6vgjbSBcIijNcacQGg",
                         base64.base64url_encode(_derived_key_u))


class TestEcKeyEcdsa(unittest.TestCase):
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
