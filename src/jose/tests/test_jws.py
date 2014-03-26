# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64, _BE

from jose.jws import Jws, Message, Signature
from jose.jwa.sigs import SigEnum, SigDict
from jose.jwa.keys import KeyTypeEnum
from jose.jwt import Jwt
from jose.jwk import Jwk


class TestJws(unittest.TestCase):

    def test_simple(self):

        jws1 = Jws.from_json('{ "alg": "RS256"}')
        self.assertIsNotNone(jws1)
        print dir(jws1)
        self.assertEqual(jws1.alg, SigEnum.RS256)

        signature = Signature()
        self.assertIsNone(signature.header)
        self.assertIsNotNone(signature._protected)
        print "`@@@", signature._protected.alg

    def test_merge(self):
        jws1 = Jws.from_json('{ "alg": "RS256"}')
        jws2 = Jws.from_json('{ "kid": "2019"}')

        self.assertIsNotNone(jws1)
        self.assertIsNotNone(jws2)
        self.assertEqual(jws1.alg, SigEnum.RS256)
        self.assertEqual(jws2.kid, "2019")

        jws3 = jws1.merge(jws2)

        self.assertEqual(jws3.alg, SigEnum.RS256)
        self.assertEqual(jws3.kid, '2019')

    def test_compact(self):
        #: http://tools.ietf.org/html/
        #:  draft-ietf-jose-json-web-signature-21#section-3.1

        data = ".".join([
            'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAs' +
            'DQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        ])

        msg = Message.from_token(data, sender=None, receiver=None)

        self.assertIsNotNone(msg)
        self.assertIsNotNone(msg.signatures)
        self.assertEqual(len(msg.signatures), 1)
        self.assertTrue(isinstance(msg.signatures[0],  Signature))

        jws0 = msg.signatures[0].to_jws()
        self.assertIsNotNone(jws0)
        self.assertEqual(jws0.typ, 'JWT')
        self.assertEqual(jws0.alg, SigEnum.HS256)

        print msg.to_json()

    def test_rs256(self):
        ''' JWS A.2
        '''

        octes = [123, 34, 97, 108, 103, 34, 58,
                 34, 82, 83, 50, 53, 54, 34, 125]

        jws_str = ''.join(chr(i) for i in octes)
        self.assertEqual(jws_str, '{"alg":"RS256"}')
        jws_new = Jws.from_json(jws_str)
        self.assertEqual(jws_new.alg, SigEnum.RS256)

        b64_header = base64.base64url_encode(jws_str)
        self.assertEqual(b64_header, 'eyJhbGciOiJSUzI1NiJ9')

        b64_payload = ''.join([
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOj',
            'EzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt',
            'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'])
        payload = base64.base64url_decode(b64_payload)

        jwt_new = Jwt.from_json(payload)
        self.assertEqual(jwt_new.iss, "joe")
        self.assertEqual(jwt_new.exp, 1300819380)
        self.assertEqual(jwt_new['http://example.com/is_root'], True)

        s_input = [
            101, 121, 74, 104, 98, 71, 99,
            105, 79, 105, 74, 83, 85, 122, 73,
            49, 78, 105, 74, 57, 46, 101, 121,
            74, 112, 99, 51, 77, 105, 79, 105,
            74, 113, 98, 50, 85, 105, 76, 65,
            48, 75, 73, 67, 74, 108, 101, 72,
            65, 105, 79, 106, 69, 122, 77, 68,
            65, 52, 77, 84, 107, 122, 79, 68,
            65, 115, 68, 81, 111, 103, 73, 109,
            104, 48, 100, 72, 65, 54, 76,
            121, 57, 108, 101, 71, 70, 116, 99,
            71, 120, 108, 76, 109, 78, 118,
            98, 83, 57, 112, 99, 49, 57, 121, 98,
            50, 57, 48, 73, 106, 112, 48,
            99, 110, 86, 108, 102, 81]

        s_input_str = "".join(chr(i) for i in s_input)
        self.assertEqual(
            s_input_str, ".".join([b64_header, b64_payload]))

        pri_json_dict = {
            "kty": "RSA",
            "n": "".join([
                "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
                "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
                "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
                "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
                "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
                "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"]),
            "e": "AQAB",
            "d": "".join([
                "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I",
                "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0",
                "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn",
                "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT",
                "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh",
                "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"]),
        }

        jwk = Jwk(**pri_json_dict)
        self.assertTrue(jwk.key.is_private)
        signer = jws_new.alg.signer
        from jose.jwa.rsa import RS256
        self.assertEqual(signer, RS256)
        sig_calc = signer.sign(jwk, s_input_str)

        sig = [
            112, 46, 33, 137, 67, 232, 143,
            209, 30, 181, 216, 45, 191, 120, 69,
            243, 65, 6, 174, 27, 129, 255, 247,
            115, 17, 22, 173, 209, 113, 125,
            131, 101, 109, 66, 10, 253, 60,
            150, 238, 221, 115, 162, 102, 62, 81,
            102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69,
            229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219,
            61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
            16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31,
            190, 127, 249, 217, 46, 10, 231,
            111, 36, 242, 91, 51, 187, 230, 244,
            74, 230, 30, 177, 4, 10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1,
            48, 121, 91, 212, 189, 59, 65, 238,
            202, 208, 102, 171, 101, 25, 129,
            253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239,
            177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
            173, 21, 145, 18, 115, 160, 95, 35,
            185, 232, 56, 250, 175, 132, 157,
            105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69,
            34, 165, 68, 200, 242, 122, 122, 45,
            184, 6, 99, 209, 108, 247, 202,
            234, 86, 222, 64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90,
            193, 167, 72, 160, 112, 223, 200,
            163, 42, 70, 149, 67, 208, 25, 238, 251, 71]

        self.assertEqual(sig, [ord(i) for i in sig_calc])

        b64_sig = "".join([
            'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7',
            'AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4',
            'BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K',
            '0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv',
            'hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB',
            'p0igcN_IoypGlUPQGe77Rw'])

        self.assertEqual(b64_sig, base64.base64url_encode(sig_calc))

        ##########################
        # implementation
        jws_impl = Jws(alg='RS256')
        msg = jws_impl.create_message(payload)

        s = msg.signatures[0]
        token = s.to_compact_token(msg.payload, jwk=jwk)
        items = token.split('.')
        self.assertEqual(len(msg.signatures), 1)
        self.assertEqual(msg.signatures[0]._protected.alg.value, 'RS256')
        self.assertEqual(len(items), 3)
        self.assertEqual(msg.signatures[0].protected, items[0])
        self.assertEqual(msg.payload, items[1])
        self.assertEqual(msg.signatures[0].signature, items[2])

        #: restore token
        msg2 = Message.from_token(token, sender=None, receiver=None)
        self.assertEqual(len(msg2.signatures), 1)
        self.assertEqual(msg2.payload, base64.base64url_encode(payload))
        self.assertEqual(len(msg2.signatures), 1)
        self.assertEqual(msg2.signatures[0]._protected.alg.value, 'RS256')
        self.assertEqual(msg2.signatures[0].protected, items[0])
        self.assertEqual(msg2.payload, items[1])
        self.assertEqual(msg2.signatures[0].signature, items[2])

        #: verify message
        s = msg2.signatures[0]
        self.assertTrue(s.verify(msg2.payload, jwk=jwk))

        #: wrong key fails
        new_jwk = Jwk.generate(KeyTypeEnum.RSA)

        self.assertFalse(s.verify(msg2.payload, jwk=new_jwk))

        #: Json Serialization
        json_str = msg.serialize_json(jwk, indent=2)

        msg3 = Message.from_token(json_str)
        self.assertEqual(len(msg3.signatures), 1)
        self.assertTrue(
            msg3.signatures[0].verify(msg3.payload, jwk.public_jwk))
        self.assertFalse(
            msg3.signatures[0].verify(msg3.payload, new_jwk.public_jwk))

    def test_jws_appendix_a1(self):
        '''{"typ":"JWT",
            "alg":"HS256"}

            {"iss":"joe",
             "exp":1300819380,
             "http://example.com/is_root":true}
        '''
        jws_oct = [
            123, 34, 116, 121, 112, 34, 58,
            34, 74, 87, 84, 34, 44, 13, 10, 32,
            34, 97, 108, 103, 34, 58, 34,
            72, 83, 50, 53, 54, 34, 125]
        jws_b64 = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
        self.assertEqual(
            ''.join(chr(i) for i in jws_oct),
            base64.base64url_decode(jws_b64))

        payload_oct = [
            123, 34, 105, 115, 115, 34, 58,
            34, 106, 111, 101, 34, 44, 13, 10,
            32, 34, 101, 120, 112, 34, 58, 49,
            51, 48, 48, 56, 49, 57, 51, 56,
            48, 44, 13, 10, 32, 34, 104, 116,
            116, 112, 58, 47, 47, 101, 120, 97,
            109, 112, 108, 101, 46, 99, 111, 109,
            47, 105, 115, 95, 114, 111,
            111, 116, 34, 58, 116, 114, 117, 101, 125]

        payload_b64 = ''.join([
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA',
            '4MTkzODAsDQogImh0dHA6Ly9leGFt',
            'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'])
        self.assertEqual(
            ''.join(chr(i) for i in payload_oct),
            base64.base64url_decode(payload_b64))

        sinput_oct = [
            101, 121, 74, 48, 101, 88, 65,
            105, 79, 105, 74, 75, 86, 49, 81,
            105, 76, 65, 48, 75, 73, 67, 74,
            104, 98, 71, 99, 105, 79, 105, 74,
            73, 85, 122, 73, 49, 78, 105, 74,
            57, 46, 101, 121, 74, 112, 99, 51,
            77, 105, 79, 105, 74, 113, 98, 50,
            85, 105, 76, 65, 48, 75, 73, 67,
            74, 108, 101, 72, 65, 105, 79, 106,
            69, 122, 77, 68, 65, 52, 77, 84,
            107, 122, 79, 68, 65, 115, 68, 81,
            111, 103, 73, 109, 104, 48, 100,
            72, 65, 54, 76, 121, 57, 108, 101,
            71, 70, 116, 99, 71, 120, 108, 76,
            109, 78, 118, 98, 83, 57, 112, 99,
            49, 57, 121, 98, 50, 57, 48, 73,
            106, 112, 48, 99, 110, 86, 108, 102, 81]
        sinput = '.'.join([jws_b64, payload_b64])
        self.assertEqual(
            ''.join(chr(i) for i in sinput_oct),
            sinput)

        jwk_dict = {
            "kty": "oct",
            "k": "".join([
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75",
                "aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"])
        }

        jwk = Jwk(**jwk_dict)
        sig_b64 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

        jws = Jws.from_b64u(jws_b64)
        sig = jws.alg.signer.sign(jwk, sinput)
        self.assertEqual(sig_b64, base64.base64url_encode(sig))

        self.assertTrue(
            jws.alg.signer.verify(jwk, sinput, sig))

    def test_jws_appendix_a4(self):

        #: Data
        header_b64 = 'eyJhbGciOiJFUzUxMiJ9'
        payload_b64 = "UGF5bG9hZA"
        signature_b64 = ''.join([
            'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq',
            'wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp',
            'EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn',
        ])

        jws = Jws.from_b64u(header_b64)
        self.assertIsNotNone(jws)
        self.assertEqual(jws.alg, SigEnum.ES512)

        jwk_dict = {
            "kty": "EC",
            "crv": "P-521",
            "x": "".join([
                "AekpBQ8ST8a8VcfVOTNl353vSrDCLL",
                "JXmPk06wTjxrrjcBpXp5EOnYG_NjFZ",
                "6OvLFV1jSfS9tsz4qUxcWceqwQGk",
            ]),
            "y": "".join([
                "ADSmRA43Z1DSNx_RvcLI87cdL07l6j",
                "QyyBXMoxVg_l2Th-x3S1WDhjDly79a",
                "jL4Kkd0AZMaZmh9ubmf63e3kyMj2",
            ]),
            "d": "".join([
                "AY5pb7A0UFiB3RELSD64fTLOSV_jaz",
                "dF7fLYyuTw8lOfRhWg6Y6rUrPAxerE",
                "zgdRhajnu0ferB0d53vM9mE15j2C"
            ])}

        from Crypto.Util.number import bytes_to_long

        #: Key
        jwk = Jwk(**jwk_dict)
        pub_jwk = jwk.public_jwk
        self.assertEqual(
            pub_jwk.key.public_key._pub[1],
            (
                bytes_to_long(base64.base64url_decode(jwk_dict['x'])),
                bytes_to_long(base64.base64url_decode(jwk_dict['y'])),
            )
        )

        # Verify
        jws_token = ".".join([header_b64, payload_b64, signature_b64])
        msg = Message.from_token(jws_token, sender=None, receiver=None)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signatures), 1)
        self.assertEqual(msg.signatures[0].signature, signature_b64)

        from jose.jwa.ec import EcdsaSigner
        sigbytes = base64.base64url_decode(msg.signatures[0].signature)
        self.assertEqual(len(sigbytes), 132)
        (r, s) = EcdsaSigner.decode_signature(sigbytes)

        R = [
            1, 220, 12, 129, 231, 171, 194, 209, 232, 135, 233,
            117, 247, 105, 122, 210, 26, 125, 192, 1, 217, 21, 82,
            91, 45, 240, 255, 83, 19, 34, 239, 71, 48, 157, 147,
            152, 105, 18, 53, 108, 163, 214, 68, 231, 62, 153, 150,
            106, 194, 164, 246, 72, 143, 138, 24, 50, 129, 223, 133,
            206, 209, 172, 63, 237, 119, 109]

        S = [
            0, 111, 6, 105, 44, 5, 41, 208, 128, 61, 152, 40, 92,
            61, 152, 4, 150, 66, 60, 69, 247, 196, 170, 81, 193,
            199, 78, 59, 194, 169, 16, 124, 9, 143, 42, 142, 131,
            48, 206, 238, 34, 175, 83, 203, 220, 159, 3, 107, 155,
            22, 27, 73, 111, 68, 68, 21, 238, 144, 229, 232, 148,
            188, 222, 59, 242, 103]

        self.assertEqual(r, bytes_to_long("".join(chr(i) for i in R)))
        self.assertEqual(s, bytes_to_long("".join(chr(i) for i in S)))

        self.assertTrue(msg.signatures[0].verify(
                        msg.payload, jwk=jwk))


class TestJwsMessage(unittest.TestCase):

    def test_algs(self):
        for alg in SigDict.values():
            alg = SigEnum.create(alg)

            signer = "https://%s.com" % alg.name
            jku = signer + "/jwkset"
            jwk = Jwk.get_or_create_from(
                signer, jku, alg.key_type, kid=None,)

            plaintext = "This is a message to be signed by %s" % alg.value

            signature = alg.signer.sign(jwk, plaintext)
            self.assertTrue(alg.signer.verify(jwk, plaintext, signature))
            print alg.value, jwk.kty.value, len(signature), _BE(signature)

    def test_compact(self):
        for alg in SigDict.values():
            alg = SigEnum.create(alg)

            signer = "https://%s.com" % alg.name
            jku = signer + "/jwkset"
            jwk = Jwk.get_or_create_from(
                signer, jku, alg.key_type, kid=None,)

            plaintext = "This is a message to be signed by %s" % alg.value
            msg = Message(
                payload=plaintext, sender=signer)
            msg.add_signature(
                protected=Jws(alg=alg, kid=None, jku=jku),
                header=Jws(typ="text"),
            )
            token = msg.serialize_compact()

            msg2 = Message.from_token(token, sender=signer)
            print alg.value, jwk.kty.value, token
            self.assertTrue(msg2.verify())

    def test_json(self):
        plaintext = "This is a message to be signed by me"
        signer = "https://me.com"
        jku = signer + "/jwkset"

        msg = Message(payload=plaintext, sender=signer)

        for alg in SigDict.values():
            alg = SigEnum.create(alg)

            jwk = Jwk.get_or_create_from(
                signer, jku, alg.key_type, kid=None,)

            msg.add_signature(
                protected=Jws(alg=alg, kid=None, jku=jku),
                header=Jws(typ="text"),
            )

        json_msg = msg.serialize_json(indent=2)
        print json_msg
        msg2 = Message.from_token(json_msg, sender=signer)
        self.assertTrue(msg2.verify())


if __name__ == '__main__':
    unittest.main()
