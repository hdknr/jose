# -*- coding: utf-8 -*-

import unittest


class TestAes(unittest.TestCase):
    def test_jwe_appendix_b2(self):
        plaint_oct = [
            76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
            112, 114, 111, 115, 112, 101, 114, 46]
        plaint = ''.join(chr(i) for i in plaint_oct)
        self.assertEqual(plaint, 'Live long and prosper.')

        cek_oct = [
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250,
            63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219,
            200, 177, 0, 240, 143, 156, 44, 207]
        cek = ''.join(chr(i) for i in cek_oct)

        iv_oct = [
            3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
            101]
        iv = ''.join(chr(i) for i in iv_oct)

        aad_oct = [
            101, 121, 74, 104, 98, 71, 99, 105,
            79, 105, 74, 66, 77, 84, 73, 52,
            83, 49, 99, 105, 76, 67, 74, 108,
            98, 109, 77, 105, 79, 105, 74, 66,
            77, 84, 73, 52, 81, 48, 74, 68, 76,
            85, 104, 84, 77, 106, 85, 50, 73,
            110, 48]
        aad = ''.join(chr(i) for i in aad_oct)

        from jose.jwa.aes import A128CBC_HS256

        enc = A128CBC_HS256()

        ciphert, tag = enc.encrypt(cek, plaint, iv, aad)

        ciphert_oct = [
            40, 57, 83, 181, 119, 33, 133,
            148, 198, 185, 243, 24, 152,
            230, 6, 75, 129, 223, 127, 19,
            210, 82, 183, 230, 168,
            33, 215, 104, 143, 112, 56, 102]

        self.assertEqual([ord(i) for i in ciphert], ciphert_oct)

        tag_oct = [
            83, 73, 191, 98, 104, 205, 211,
            128, 201, 189, 199, 133, 32, 38, 194, 85]

        self.assertEqual([ord(i) for i in tag], tag_oct)

        plaint_dec, is_valid = enc.decrypt(cek, ciphert, iv, aad, tag)

        self.assertEqual(plaint, plaint_dec)
        self.assertTrue(is_valid)

if __name__ == '__main__':
    unittest.main()
