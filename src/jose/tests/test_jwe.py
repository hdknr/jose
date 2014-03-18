# -*- coding: utf-8 -*-

import unittest

from jose.jwe import Jwe, ZipEnum
from jose.jwa.encs import KeyEncEnum, EncEnum
from jose.utils import base64


_S = lambda o: ''.join([chr(i) for i in o])
_BE = lambda s: base64.base64url_encode(s)
_BD = lambda s: base64.base64url_decode(s)


class A3:
    plaint_oct = [
        76, 105, 118, 101, 32, 108,
        111, 110, 103, 32, 97, 110, 100, 32,
        112, 114, 111, 115, 112, 101, 114, 46]
    plaint = _S(plaint_oct)

    iv_oct = [
        3, 22, 60, 12, 43, 67, 104, 105,
        108, 108, 105, 99, 111, 116, 104, 101]
    iv = _S(iv_oct)
    iv_b64 = _BE(iv)


class B:
    cek_oct = [
        4, 211, 31, 197, 84, 157, 252, 254,
        11, 100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9,
        219, 200, 177, 0, 240, 143, 156,
        44, 207]
    cek = _S(cek_oct)


class TestJwe(unittest.TestCase):

    def test_simple(self):
        data = '{ "alg": "RSA1_5",  "zip": "DEF" }'
        jwe1 = Jwe.from_json(data)
        print dir(jwe1)
        self.assertEqual(jwe1.alg, KeyEncEnum.RSA1_5)

    def test_merge(self):
        ''' Jwe specs 3 jwe objects(2 in Message, 1 on Signature)
        '''
        jwe1 = Jwe.from_json('{ "alg": "RSA1_5"}')
        jwe2 = Jwe.from_json('{ "zip": "DEF"}')
        jwe3 = jwe1.merge(jwe2)

        self.assertEqual(jwe3.alg, KeyEncEnum.RSA1_5)
        self.assertEqual(jwe3.zip, ZipEnum.DEF)
        self.assertIsNone(jwe1.zip)
        self.assertIsNone(jwe2.alg)

    def test_jwa_appendix_a4(self):
        import os
        json_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'jwe_appendix_a4.json')

        from jose.jwe import Message
        msg = Message.from_file(json_file)

        # A.4.1 - JWE Per-Recipient Unprotected Headers

        self.assertEqual(len(msg.recipients), 2)
        rec0, rec1 = msg.recipients

        self.assertEqual(rec0.header.alg, KeyEncEnum.RSA1_5)
#        self.assertEqual(rec0.header.kid, "2011-04-29")
        self.assertEqual(rec1.header.alg, KeyEncEnum.A128KW)
#        self.assertEqual(rec1.header.kid, "7")

        # A.4.2 - JWE Protected Header
        self.assertEqual(
            msg._protected.enc, EncEnum.A128CBC_HS256)

        # A.4.3 - JWE Unprotected Header
        self.assertEqual(
            msg.unprotected.jku,
            "https://server.example.com/keys.jwks")

        # A.4.4 - Complete JWE Header Values
        # kid is missing....
        dict0 = msg.header(0).to_dict()
        dict1 = msg.header(1).to_dict()
        self.assertEqual(dict0['alg'], "RSA1_5")
        self.assertEqual(dict0['enc'], "A128CBC-HS256")
        self.assertEqual(dict0["jku"], "https://server.example.com/keys.jwks")
        self.assertEqual(dict1['alg'], "A128KW")
        self.assertEqual(dict1['enc'], "A128CBC-HS256")
        self.assertEqual(dict1["jku"], "https://server.example.com/keys.jwks")

        # A.4.5 - Additional Authenticated Data
        aad_oct = [
            101, 121, 74, 108, 98, 109, 77,
            105, 79, 105, 74, 66, 77, 84, 73,
            52, 81, 48, 74, 68, 76, 85, 104, 84,
            77, 106, 85, 50, 73, 110, 48]
        aad = _S(aad_oct)
        self.assertEqual(aad, msg.auth_data)

        # A.4.6 - Content Encryption
        self.assertEqual(msg.iv, A3.iv_b64)
        tag_oct = [
            51, 63, 149, 60, 252, 148, 225,
            25, 92, 185, 139, 245, 35, 2, 47, 207]
        self.assertEqual(msg.tag, _BE(_S(tag_oct)))

        ciphert_oct = [
            40, 57, 83, 181, 119, 33,
            133, 148, 198, 185, 243, 24, 152, 230, 6,
            75, 129, 223, 127, 19, 210, 82, 183,
            230, 168, 33, 215, 104, 143,
            112, 56, 102]

        self.assertEqual(msg.ciphertext, _BE(_S(ciphert_oct)))
        self.assertIsNone(msg._plaintext)
        self.assertIsNone(msg.cek)
        self.assertEqual(msg.tag, "Mz-VPPyU4RlcuYv1IwIvzw")
        self.assertEqual(msg.iv, "AxY8DCtDaGlsbGljb3RoZQ")

        #: give CEK manually
        msg.cek = B.cek
        self.assertEqual(msg.plaintext, A3.plaint)

        #:
        print msg.to_json(indent=2)

if __name__ == '__main__':
    unittest.main()
