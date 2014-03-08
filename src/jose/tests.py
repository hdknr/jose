# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64


class TestBase64(unittest.TestCase):
    def test_base64(self):
        self.assertEquals('QWxpY2U', base64.base64url_encode('Alice'))
        self.assertEquals('Qm9i', base64.base64url_encode('Bob'))

        self.assertEquals('Alice', base64.base64url_decode('QWxpY2U'))
        self.assertEquals('Bob', base64.base64url_decode('Qm9i'))

        self.assertEquals(
            '=',
            base64.base64url_decode(base64.base64url_encode('=')))

from jose.jwk import Jwk
from jose.jwa.keys import KeyTypeEnum


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


class TestCrypto(unittest.TestCase):
    def test_pattern(self):
        from jws import _compact as jws
        from jwe import _compact as jwe

        self.assertIsNotNone(jws.search('aaaa.bbb.ccc'))
        self.assertIsNotNone(jwe.search('aaaa.bbb.ccc.ddd.eee'))


from jws import Jws, Message, Signature
from jwa.sigs import SigEnum


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

        msg = Message.from_token(data)

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
        signer = jws_new.alg.create_signer()
        from jose.jwa.rsa import RS256
        self.assertTrue(isinstance(signer, RS256))
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
        token = msg.serialize_compact(jwk)
        items = token.split('.')
        self.assertEqual(len(msg.signatures), 1)
        self.assertEqual(msg.signatures[0]._protected.alg.value, 'RS256')
        self.assertEqual(len(items), 3)
        self.assertEqual(msg.signatures[0].protected, items[0])
        self.assertEqual(msg.payload, items[1])
        self.assertEqual(msg.signatures[0].signature, items[2])

        #: restore token
        msg2 = Message.from_token(token)
        self.assertEqual(len(msg2.signatures), 1)
        self.assertEqual(msg2.payload, base64.base64url_encode(payload))
        self.assertEqual(len(msg2.signatures), 1)
        self.assertEqual(msg2.signatures[0]._protected.alg.value, 'RS256')
        self.assertEqual(msg2.signatures[0].protected, items[0])
        self.assertEqual(msg2.payload, items[1])
        self.assertEqual(msg2.signatures[0].signature, items[2])

        #: verify message
        pub_jwk = jwk.public_jwk
        self.assertTrue(pub_jwk.is_public)
        self.assertTrue(msg2.verify(pub_jwk))

        #: wrong key fails
        new_jwk = Jwk.generate(KeyTypeEnum.RSA)
        self.assertIsNotNone(new_jwk)
        new_pub = new_jwk.public_jwk
        self.assertTrue(new_pub.is_public)
        self.assertFalse(msg2.verify(new_pub))

        #: Json Serialization
        json_str = msg.serialize_json(jwk, indent=2)

        msg3 = Message.from_token(json_str)
        self.assertEqual(len(msg3.signatures), 1)
        self.assertTrue(msg3.verify(pub_jwk))
        self.assertFalse(msg3.verify(new_pub))

from jwe import Jwe
from jwa.encs import KeyEncEnum


class TestJwe(unittest.TestCase):

    def test_simple(self):
        data = '{ "alg": "RSA1_5",  "zip": "DEF" }'
        jwe1 = Jwe.from_json(data)
        print dir(jwe1)
        self.assertEqual(jwe1.alg, KeyEncEnum.RSA1_5)


class TestUtils(unittest.TestCase):

    def test_biglong(self):
        import time
        l = long(time.time()) ** 32

        from jose.utils import base64

        b = base64.long_to_b64(l)
        l2 = base64.long_from_b64(b)

        self.assertEqual(l, l2)

from store import FileStore


class TestStore(unittest.TestCase):

    def test_save_and_load(self):
        fs = FileStore()
        jwk = Jwk()
        fs.save(jwk)


from jose.jwt import Jwt


class TestJwt(unittest.TestCase):

    def test_simple(self):

        vals = {
            'iss': 'joe',
            'exp': 1300819380,
            "http://example.com/is_root": True,
        }
        jwt_org = Jwt(**vals)
        jwt_json = jwt_org.to_json()

        jwt_new = Jwt.from_json(jwt_json)
        self.assertEqual(jwt_new.iss, jwt_org.iss)
        self.assertEqual(jwt_new.exp, jwt_org.exp)
        self.assertEqual(jwt_new['http://example.com/is_root'], True)

    def test_serialize(self):
        jwt_json = '''
           {"iss":"joe",
                 "exp":1300819380,
                       "http://example.com/is_root":true}'''
        jwt_new = Jwt.from_json(jwt_json)
        self.assertEqual(jwt_new['http://example.com/is_root'], True)

    def test_sample(self):
        '''
        https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-16
        #section-3.1
        '''
        vals = [
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
            32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
            48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120,
            97,
            109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
            111, 116, 34, 58, 116, 114, 117, 101, 125]

        str_vals = "".join(chr(i) for i in vals)
        jwt_new = Jwt.from_json(str_vals)
        self.assertEqual(jwt_new.iss, "joe")
        self.assertEqual(jwt_new.exp, 1300819380)
        self.assertEqual(jwt_new['http://example.com/is_root'], True)

        b64 = "".join([
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly',
            '9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
        ])
        self.assertEqual(base64.base64url_encode(str_vals), b64)


if __name__ == '__main__':
    unittest.main()
