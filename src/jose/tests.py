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

if __name__ == '__main__':
    unittest.main()
