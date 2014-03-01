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
        self.assertIsNotNone(signature.protected)
        print "`@@@", signature.protected.alg

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
