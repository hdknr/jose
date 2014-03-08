# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64
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
