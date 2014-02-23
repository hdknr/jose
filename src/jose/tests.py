# -*- coding: utf-8 -*-

import unittest
from jose import base64


class TestBase64(unittest.TestCase):
    def test_base64(self):
        self.assertEquals('QWxpY2U', base64.base64url_encode('Alice'))
        self.assertEquals('Qm9i', base64.base64url_encode('Bob'))

        self.assertEquals('Alice', base64.base64url_decode('QWxpY2U'))
        self.assertEquals('Bob', base64.base64url_decode('Qm9i'))

        self.assertEquals(
            '=',
            base64.base64url_decode(base64.base64url_encode('=')))


class TestJwk(unittest.TestCase):
    def test_serialize(self):
        data = ''' { "kty":"RSA" } '''

        from jose.jwk import Jwk
        from jose.jwa.keys import KeyType

        jwk = Jwk.from_json(data)
        self.assertEquals(jwk.kty, KeyType.RSA)
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


class TestJws(unittest.TestCase):
    def test_compact(self):
        #: http://tools.ietf.org/html/
        #:  draft-ietf-jose-json-web-signature-21#section-3.1

        data = ".".join([
            'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9',
            'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAs' +
            'DQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ',
            'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        ])

        from jws import JwsMessage
        from jwa.sigs import Signature
        msg = JwsMessage.from_token(data)
        self.assertIsNotNone(msg)
        self.assertIsNotNone(msg.jws_list)
        self.assertEqual(len(msg.jws_list), 1)

        jws0 = msg.jws_list[0]
        self.assertEqual(jws0.typ, 'JWT')
        self.assertEqual(jws0.alg, Signature.HS256)

        print msg.to_json()

if __name__ == '__main__':
    unittest.main()
