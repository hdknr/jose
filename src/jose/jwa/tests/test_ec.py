# -*- coding: utf-8 -*-
from __future__ import print_function
import unittest
from jose.utils import base64
from six import b


def _ilist(src):
    return list(
        map(lambda i: i if isinstance(i, int) else ord(i[:1]), src))


class TestEcEcc(unittest.TestCase):

    def test_generate(self):
        def hexdigest(digester, data):
            import hashlib
            return hashlib.new(digester, data).hexdigest()

        def longdigest(digester, data):
            return int(hexdigest(digester, data), 16)

        from ecdsa.keys import SigningKey, VerifyingKey
        from ecdsa.curves import NIST521p

        pri = SigningKey.generate(curve=NIST521p)
        pub = pri.get_verifying_key()
        self.assertTrue(isinstance(pub, VerifyingKey))

        data = 'what a wonderfull world.'
        digest = longdigest('sha256', b(data))

        sig = pri.sign_number(digest)
        self.assertTrue(isinstance(sig, tuple))
        self.assertEqual(len(sig), 2)

        from ecdsa.ecdsa import Signature
        sigobj = Signature(*sig)        # (r, s)
        self.assertTrue(pub.pubkey.verifies(digest, sigobj))

    def test_dhZ(self):
        from ecdsa.keys import SigningKey   # VerifyingKey
        from ecdsa.curves import NIST521p

        # Party V(recepient) declares a satic key pair
        curve = NIST521p
        v_stc = SigningKey.generate(curve=curve)

        # and advertise to Party U(Sender) ( U <--(pub key)-- V)
        v_pub = v_stc.get_verifying_key()
        self.assertEqual(v_pub.curve, curve)
        print(v_pub.curve)

        # Party U provides a ephemeral key
        u_epk = SigningKey.generate(curve=v_pub.curve)

        from jose.jwa import ec
        # Compute ECDH as shared secret
        # This shared secret itself is NOT have to be exchanged.
        shared_secret_u = ec.ecdsa_dhZ(v_pub, u_epk)

        # Party V recive Epemeral Public Key ( U --(pub key)--> V)
        v_epk = u_epk.get_verifying_key()

        # Party V compute
        shared_secret_v = ec.ecdsa_dhZ(v_epk, v_stc)

        # Secrete Agreeed!
        self.assertEqual(shared_secret_u, shared_secret_v)

    def test_ecdh_check(self):
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

        def _to_pub(km):
            return (
                int(re.search(r"P-(\d+)$", km['crv']).group(1)),
                (base64.long_from_b64(km['x']),
                 base64.long_from_b64(km['y'])),
            )

        def _to_pri(km):
            return (
                int(re.search(r"P-(\d+)$", km['crv']).group(1)),
                base64.long_from_b64(km['d']),
            )

        pub_tuple = _to_pub(v_stc_material)
        pri_tuple = _to_pri(v_stc_material)

        import pydoc
        curve = pydoc.locate('ecdsa.curves.NIST{0}p'.format(pub_tuple[0]))

        from ecdsa import (
            SigningKey, VerifyingKey,
            ellipticcurve as ec)

        x, y = pub_tuple[1]
        v_pub = VerifyingKey.from_public_point(
            ec.Point(curve.curve, x, y, curve.order),
            curve,
        )

        v_stc = SigningKey.from_secret_exponent(pri_tuple[1], curve)

        # Party U provides a ephemeral key
        pub_tuple = _to_pub(u_epk_material)
        pri_tuple = _to_pri(u_epk_material)

        x, y = pub_tuple[1]
        u_epk = SigningKey.from_secret_exponent(pri_tuple[1], curve)

        from jose.jwa.ec import ecdsa_dhZ

        # Party U compute
        shared_secret_u = ecdsa_dhZ(v_pub, u_epk)

        print("Aggreement:", base64.long_to_b64(shared_secret_u))

        from Crypto.Util.number import long_to_bytes
        from math import ceil

        block_size = int(ceil(pub_tuple[0] / 8.0))
        # bit number(512 )  / 8 -> octets

        Zu = long_to_bytes(shared_secret_u, block_size)

        Z_jwa = [158, 86, 217, 29, 129, 113, 53,
                 211, 114, 131, 66, 131, 191, 132,
                 38, 156, 251, 49, 110, 163, 218,
                 128, 106, 72, 246, 218, 167, 121,
                 140, 254, 144, 196]

        self.assertEqual(_ilist(Zu), Z_jwa)

        # Other Information used in Concat KDF
        # AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
        from struct import pack

        def _otherInfo(alg, pu, pv, klen):
            return b('').join([
                pack("!I", len(alg)),
                alg,
                pack("!I", len(pu)),
                pu,
                pack("!I", len(pv)),
                pv,
                pack("!I", klen),
            ])

        oi_u = _otherInfo(
            b("A128GCM"),
            b("Alice"),
            b("Bob"),
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

        print(">>>>>>>", type(oi_u))
        print("<<<<<<<", oi_u)
        self.assertEqual(_ilist(oi_u), oi_jwa)

        # Coccat KDF : NIST defines SHA256
        from Crypto.Hash import SHA256

        def _ConcatKDF(Z, dkLen, otherInfo,
                       digest_method=SHA256):

            def _src(counter_bytes):
                return b("").join([counter_bytes, Z, otherInfo])

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
        v_epk = u_epk.get_verifying_key()
        Zv = long_to_bytes(ecdsa_dhZ(v_epk, v_stc), block_size)

        _derived_key_v = _ConcatKDF(Zv, 16 * 8, oi_u)

        self.assertEqual(_derived_key_u, _derived_key_v)

        kd_jwa = [
            86, 170, 141, 234, 248, 35, 109, 32,
            92, 34, 40, 205, 113, 167, 16, 26]

        self.assertEqual(_ilist(_derived_key_u), kd_jwa)

        self.assertEqual(b("VqqN6vgjbSBcIijNcacQGg"),
                         base64.base64url_encode(_derived_key_u))

    def test_ecdh_impl(self):
        '''
https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#appendix-C
        python -m test_ec -q TestEcEcc.test_ecdh_impl
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

        from jose.jwk import Jwk

        v_stc_jwk = Jwk(**v_stc_material)
        u_epk_jwk = Jwk(**u_epk_material)

        #: Agreement
        Zu = u_epk_jwk.key.agreement_to(v_stc_jwk.key)
        Z_jwa = [158, 86, 217, 29, 129, 113, 53,
                 211, 114, 131, 66, 131, 191, 132,
                 38, 156, 251, 49, 110, 163, 218,
                 128, 106, 72, 246, 218, 167, 121,
                 140, 254, 144, 196]

        self.assertEqual(_ilist(Zu), Z_jwa)
        self.assertEqual(base64.base64url_encode(Zu),
                         b('nlbZHYFxNdNyg0KDv4QmnPsxbqPagGpI9tqneYz-kMQ'))

        from jose.jwe import Jwe
        from jose.jwa.ec import ECDH_ES

        jwe = Jwe(enc='A128GCM',
                  apu='Alice', apv='Bob')

        algid = jwe.enc.value
        klen = ECDH_ES.digest_key_bitlength(jwe.enc)

        oi_u = ECDH_ES.other_info(b(algid), b('Alice'), b('Bob'), klen)
        oi_jwa = [
            0, 0, 0, 7,
            65, 49, 50, 56, 71, 67, 77,
            0, 0, 0, 5,
            65, 108, 105, 99, 101,
            0, 0, 0, 3,
            66, 111, 98,
            0, 0, 0, 128]

        self.assertEqual(_ilist(oi_u), oi_jwa)

        # Derive Key for ECDH Agreement
        _derived_key_u, cek_ci_u = ECDH_ES.create_key(Zu, klen, oi_u, None)

        self.assertIsNone(cek_ci_u)

        # --- Party V
        # Agreement
        Zv = v_stc_jwk.key.agreement_to(u_epk_jwk.key)
        _derived_key_v, cek_ci_v = ECDH_ES.create_key(Zv, klen, oi_u, None)
        self.assertIsNone(cek_ci_v)

        self.assertEqual(_derived_key_u, _derived_key_v)

        kd_jwa = [
            86, 170, 141, 234, 248, 35, 109, 32,
            92, 34, 40, 205, 113, 167, 16, 26]

        self.assertEqual(len(_derived_key_v), len(kd_jwa))
        self.assertEqual(_ilist(_derived_key_u), kd_jwa)
        self.assertEqual(b("VqqN6vgjbSBcIijNcacQGg"),
                         base64.base64url_encode(_derived_key_u))

    def test_jwk(self):
        from jose.jwa.keys import KeyTypeEnum, CurveEnum

        # void key
        key = KeyTypeEnum.EC.create_key()

        # new private key
        key.init_material(CurveEnum.P_256.bits)
        self.assertTrue(key.is_private)
        self.assertFalse(key.is_public)
        self.assertIsNotNone(key.material)
        self.assertIsNotNone(key.public_key)
        self.assertIsNotNone(key.private_key)
        self.assertIsNotNone(key.public_jwk)
        self.assertIsNotNone(key.private_jwk)

        pri_jwk = key.private_jwk
        pub_jwk = key.public_jwk
        print(pri_jwk.to_json())
        print(pub_jwk.to_json())
        self.assertEqual(pri_jwk.n, pub_jwk.n)
        self.assertEqual(pri_jwk.e, pub_jwk.e)
        self.assertEqual(pub_jwk.d, '')

        print(pub_jwk.to_json())
        pub_new = KeyTypeEnum.EC.create_key(jwk=pub_jwk)
        pri_new = KeyTypeEnum.EC.create_key(jwk=pri_jwk)
        self.assertEqual(key.public_key_tuple, pub_new.public_key_tuple)
        self.assertEqual(key.private_key_tuple, pri_new.private_key_tuple)

        # Signature
        msg = b("hello, it's me.")
        signature_new = pri_new.material.sign(msg)
        print(type(signature_new))

        # Verify
        self.assertTrue(
            pub_new.material.verify(signature_new, msg))

    def test_jws_appendix_a4(self):
        header_str = '{"alg":"ES512"}'
        header_oct = [
            123, 34, 97, 108, 103, 34,
            58, 34, 69, 83, 53, 49, 50, 34, 125]
        self.assertEqual(
            [isinstance(i, int) and i or ord(i[:1]) for i in b(header_str)],
            header_oct)

        header_b64 = 'eyJhbGciOiJFUzUxMiJ9'
        self.assertEqual(
            base64.base64url_encode(header_str), b(header_b64))

        payload_str = "Payload"
        payload_oct = [
            80, 97, 121, 108, 111, 97, 100,
        ]
        self.assertEqual(
            [isinstance(i, int) and i or ord(i[:1]) for i in b(payload_str)],
            payload_oct)

        payload_b64 = "UGF5bG9hZA"
        self.assertEqual(
            base64.base64url_encode(payload_str), b(payload_b64))

        signing_input_b64 = ".".join([header_b64, payload_b64])
        signing_input_oct = [
            101, 121, 74, 104, 98, 71, 99,
            105, 79, 105, 74, 70, 85, 122, 85,
            120, 77, 105, 74, 57, 46, 85, 71,
            70, 53, 98, 71, 57, 104, 90, 65]
        self.assertEqual(_ilist(signing_input_b64), signing_input_oct)

        jwk_str = '''
 {"kty":"EC",
  "crv":"P-521",
  "x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
  "y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
  "d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
 }'''

        from jose.jwk import Jwk
        jwk = Jwk.from_json(jwk_str)

        import hashlib

        # Sign
        pri = jwk.key.private_key_tuple

        self.assertEqual(pri[0], 521)
        self.assertEqual(
            pri[1],
            base64.long_from_b64(
                'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C')  # NOQA
        )

        digest = int(hashlib.new('sha512',
                                 b(signing_input_b64)).hexdigest(), 16)
        signature = jwk.key.sign_longdigest(digest)
        self.assertEqual(type(signature), tuple)
        #: This signature changes everytime.
        self.assertTrue(isinstance(signature, tuple))
        self.assertEqual(len(signature), 2)

        # Verify
        pub = jwk.key.public_key_tuple
        self.assertEqual(pub[0], 521)
        self.assertEqual(pub[1],
            base64.long_from_b64(
                "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"  # NOQA
            )
        )
        self.assertEqual(pub[2],
            base64.long_from_b64(
                "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"  # NOQA
            )
        )

        self.assertTrue(jwk.key.verify_longdigest(digest, signature))

        sig_jws_oct = (
            [1, 220, 12, 129, 231, 171, 194, 209, 232, 135, 233,
             117, 247, 105, 122, 210, 26, 125, 192, 1, 217, 21, 82,
             91, 45, 240, 255, 83, 19, 34, 239, 71, 48, 157, 147,
             152, 105, 18, 53, 108, 163, 214, 68, 231, 62, 153, 150,
             106, 194, 164, 246, 72, 143, 138, 24, 50, 129, 223, 133,
             206, 209, 172, 63, 237, 119, 109],
            [0, 111, 6, 105, 44, 5, 41, 208, 128, 61, 152, 40, 92,
             61, 152, 4, 150, 66, 60, 69, 247, 196, 170, 81, 193,
             199, 78, 59, 194, 169, 16, 124, 9, 143, 42, 142, 131,
             48, 206, 238, 34, 175, 83, 203, 220, 159, 3, 107, 155,
             22, 27, 73, 111, 68, 68, 21, 238, 144, 229, 232, 148,
             188, 222, 59, 242, 103]
        )

        sig_jws_b64 = ''.join([
            'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq',
            'wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp',
            'EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn',
        ])

        sig_jws_str = base64.base64url_decode(sig_jws_b64)
        self.assertEqual(len(sig_jws_str), 66 * 2)
        from Crypto.Util.number import bytes_to_long
        sig_jws_tuple = (bytes_to_long(sig_jws_str[:66]),
                         bytes_to_long(sig_jws_str[66:]),)

        self.assertTrue(jwk.key.verify_longdigest(digest, sig_jws_tuple))


class TestEcKeyEcdsa(unittest.TestCase):
    ''' python-ecdsa'''
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
        msg = "hello, it's me.".encode('utf8')
        digest = string_to_int(sha512(msg).digest())
        signature_new = pri_new.sign(digest, rnd)
        signature_old = pri.sign(digest, rnd)
        self.assertTrue(isinstance(signature_new, Signature))
        self.assertEqual(signature_new.r, signature_old.r)
        self.assertEqual(signature_new.s, signature_old.s)
        import six      # python3 no long
        self.assertTrue(type(signature_new.r) in six.integer_types)
        self.assertTrue(type(signature_new.s) in six.integer_types)

        # Verify
        print(pub.verifies(digest, signature_new))
        print(pub_new.verifies(digest, signature_old))

        #
        print(dir(pri_new))
        print(dir(pub_new))
        print(dir(pub_new.curve))

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

        print(alice_pub_point, bob_pub_point)


if __name__ == '__main__':
    unittest.main()
