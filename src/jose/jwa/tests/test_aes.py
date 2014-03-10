# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64
from jose.jwk import Jwk
from jose.jwe import Jwe


class TestAes(unittest.TestCase):
    def test_jwe_appendix_a2(self):
        plaint_oct = [
            76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
            112, 114, 111, 115, 112, 101, 114, 46]
        plaint = ''.join(chr(i) for i in plaint_oct)

        # Appendix A.2.1
        jwe_json = '{"alg":"RSA1_5","enc":"A128CBC-HS256"}'
        jwe_b64 = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0'
        self.assertEqual(jwe_json, base64.base64url_decode(jwe_b64))
        jwe = Jwe.from_json(jwe_json)

        # Appendix A.2.2
        cek_oct = [
            4, 211, 31, 197, 84, 157, 252, 254,
            11, 100, 157, 250, 63, 170, 106,
            206, 107, 124, 212, 45, 111, 107, 9,
            219, 200, 177, 0, 240, 143, 156,
            44, 207]
        cek = ''.join(chr(i) for i in cek_oct)

        # Appendix A.2.3
        jwk_dict = {
            "kty": "RSA",
            "n": "".join([
                "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl",
                "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre",
                "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_",
                "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI",
                "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU",
                "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw"]),
            "e": "AQAB",
            "d": "".join([
                "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq",
                "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry",
                "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_",
                "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj",
                "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj",
                "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ"])
        }

        jwk = Jwk(**jwk_dict)

        pri = jwk.key.private_key
        pub = jwk.key.public_key

        cek_enc_oct = [
            80, 104, 72, 58, 11, 130, 236, 139,
            132, 189, 255, 205, 61, 86, 151,
            176, 99, 40, 44, 233, 176, 189, 205,
            70, 202, 169, 72, 40, 226, 181,
            156, 223, 120, 156, 115, 232, 150,
            209, 145, 133, 104, 112, 237, 156,
            116, 250, 65, 102, 212, 210, 103,
            240, 177, 61, 93, 40, 71, 231, 223,
            226, 240, 157, 15, 31, 150, 89, 200,
            215, 198, 203, 108, 70, 117, 66,
            212, 238, 193, 205, 23, 161, 169,
            218, 243, 203, 128, 214, 127, 253,
            215, 139, 43, 17, 135, 103, 179, 220,
            28, 2, 212, 206, 131, 158, 128,
            66, 62, 240, 78, 186, 141, 125, 132,
            227, 60, 137, 43, 31, 152, 199,
            54, 72, 34, 212, 115, 11, 152, 101,
            70, 42, 219, 233, 142, 66, 151,
            250, 126, 146, 141, 216, 190, 73, 50,
            177, 146, 5, 52, 247, 28, 197,
            21, 59, 170, 247, 181, 89, 131, 241,
            169, 182, 246, 99, 15, 36, 102,
            166, 182, 172, 197, 136, 230, 120, 60,
            58, 219, 243, 149, 94, 222,
            150, 154, 194, 110, 227, 225, 112, 39,
            89, 233, 112, 207, 211, 241,
            124, 174, 69, 221, 179, 107, 196, 225,
            127, 167, 112, 226, 12, 242,
            16, 24, 28, 120, 182, 244, 213, 244,
            153, 194, 162, 69, 160, 244,
            248, 63, 165, 141, 4, 207, 249, 193,
            79, 131, 0, 169, 233, 127, 167,
            101, 151, 125, 56, 112, 111, 248, 29,
            232, 90, 29, 147, 110, 169,
            146, 114, 165, 204, 71, 136, 41, 252]
        cek_enc = ''.join(chr(i) for i in cek_enc_oct)
        key_enc = jwe.alg.get_encryptor()
        cek_restore = key_enc.decrypt(pri, cek_enc)
        self.assertEqual(cek, cek_restore)
        cek_enc_2 = key_enc.encrypt(pub, cek)
        cek_restore_2 = key_enc.decrypt(pri, cek_enc_2)
        self.assertEqual(cek, cek_restore_2)

        # Appendix A.2.4
        iv_oct = [
            3, 22, 60, 12, 43, 67, 104, 105,
            108, 108, 105, 99, 111, 116, 104, 101]
        iv = ''.join(chr(i) for i in iv_oct)
        iv_b64 = 'AxY8DCtDaGlsbGljb3RoZQ'
        self.assertEqual(base64.base64url_decode(iv_b64), iv)

        # Appendix A.2.5
        aad_oct = [
            101, 121, 74, 104, 98, 71, 99,
            105, 79, 105, 74, 83, 85, 48, 69,
            120, 88, 122, 85, 105, 76, 67, 74,
            108, 98, 109, 77, 105, 79, 105,
            74, 66, 77, 84, 73, 52, 81, 48,
            74, 68, 76, 85, 104, 84, 77, 106, 85,
            50, 73, 110, 48]
        aad = ''.join(chr(i) for i in aad_oct)

        # Appendix 2.6

        ciphert_oct = [
            40, 57, 83, 181, 119, 33, 133,
            148, 198, 185, 243, 24, 152, 230, 6,
            75, 129, 223, 127, 19, 210, 82,
            183, 230, 168, 33, 215, 104, 143,
            112, 56, 102]
        ciphert = ''.join(chr(i) for i in ciphert_oct)

        tag_oct = [
            246, 17, 244, 190, 4, 95, 98,
            3, 231, 0, 115, 157, 242, 203, 100, 191]
        tag = ''.join(chr(i) for i in tag_oct)

        # decrypt
        cenc = jwe.enc.get_encryptor()
        p_new, is_valid = cenc.decrypt(cek, ciphert, iv, aad, tag)
        self.assertTrue(is_valid)
        self.assertEqual(p_new, plaint)
        print p_new
        c_new, tag_new = cenc.encrypt(cek, plaint, iv, aad)
        p_new_2, is_valid_2 = cenc.decrypt(cek, c_new, iv, aad, tag_new)
        self.assertTrue(is_valid_2)
        self.assertEqual(p_new_2, plaint)
        print p_new_2

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
