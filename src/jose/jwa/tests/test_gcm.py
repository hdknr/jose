# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64
from jose.jwe import Jwe
from jose.jwa.encs import EncEnum,  KeyEncEnum
from jose.jwa.keys import KeyTypeEnum
from jose.jwk import Jwk


class TestGcm(unittest.TestCase):
    def test_jwe_appendix_a1(self):

        # A.1
        plaint_oct = [
            84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32,
            111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99,
            101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108,
            101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105,
            110, 97, 116, 105, 111, 110, 46]
        plaint = ''.join(chr(i) for i in plaint_oct)

        self.assertEqual(
            plaint,
            'The true sign of intelligence is not knowledge but imagination.')

        # A.1.1
        jwe_json = '{"alg":"RSA-OAEP","enc":"A256GCM"}'
        jwe_b64 = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ'
        self.assertEqual(jwe_b64, base64.base64url_encode(jwe_json))
        jwe = Jwe.from_json(jwe_json)
        self.assertEqual(jwe.alg, KeyEncEnum.RSA_OAEP)
        self.assertEqual(jwe.enc, EncEnum.GCMA256)

        # A.1.2.
        cek_oct = [
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
            212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
            234, 64, 252]
        cek = ''.join(chr(i) for i in cek_oct)

        jwk_dict = {
            'kty': "RSA",
            "n": ''.join([
                'oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW',
                'cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S',
                'psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a',
                'sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS',
                'tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj',
                'YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw',
            ]),
            "e": "AQAB",
            "d": ''.join([
                'kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N',
                'WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9',
                '3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk',
                'qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl',
                't3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd',
                'VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ',
            ])
        }
        jwk = Jwk(**jwk_dict)
        self.assertEqual(jwk.kty, KeyTypeEnum.RSA)
        self.assertTrue(jwk.key.is_private)

        cek_enc_oct = [
            56, 163, 154, 192, 58, 53, 222, 4,
            105, 218, 136, 218, 29, 94, 203,
            22, 150, 92, 129, 94, 211, 232, 53,
            89, 41, 60, 138, 56, 196, 216,
            82, 98, 168, 76, 37, 73, 70, 7, 36,
            8, 191, 100, 136, 196, 244, 220,
            145, 158, 138, 155, 4, 117, 141, 230,
            199, 247, 173, 45, 182, 214,
            74, 177, 107, 211, 153, 11, 205, 196,
            171, 226, 162, 128, 171, 182,
            13, 237, 239, 99, 193, 4, 91, 219, 121,
            223, 107, 167, 61, 119, 228,
            173, 156, 137, 134, 200, 80, 219, 74,
            253, 56, 185, 91, 177, 34, 158,
            89, 154, 205, 96, 55, 18, 138, 43, 96,
            218, 215, 128, 124, 75, 138,
            243, 85, 25, 109, 117, 140, 26, 155,
            249, 67, 167, 149, 231, 100, 6,
            41, 65, 214, 251, 232, 87, 72, 40, 182,
            149, 154, 168, 31, 193, 126,
            215, 89, 28, 111, 219, 125, 182, 139,
            235, 195, 197, 23, 234, 55, 58,
            63, 180, 68, 202, 206, 149, 75, 205,
            248, 176, 67, 39, 178, 60, 98,
            193, 32, 238, 122, 96, 158, 222, 57,
            183, 111, 210, 55, 188, 215,
            206, 180, 166, 150, 166, 106, 250, 55,
            229, 72, 40, 69, 214, 216,
            104, 23, 40, 135, 212, 28, 127, 41, 80,
            175, 174, 168, 115, 171, 197,
            89, 116, 92, 103, 246, 83, 216, 182, 176,
            84, 37, 147, 35, 45, 219,
            172, 99, 226, 233, 73, 37, 124, 42, 72, 49,
            242, 35, 127, 184, 134,
            117, 114, 135, 206]

        cek_enc_b64 = ''.join([
            'OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe',
            'ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb',
            'Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV',
            'mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8',
            '1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi',
            '6UklfCpIMfIjf7iGdXKHzg',
        ])
        cek_enc_bytes = ''.join(chr(i) for i in cek_enc_oct)
        self.assertEqual(cek_enc_bytes, base64.base64url_decode(cek_enc_b64))

        self.assertEqual(len(cek) * 8, 256)
        key_enc = jwe.alg.get_encryptor()
        from jose.jwa.rsa import RSA_OAEP
        self.assertTrue(isinstance(key_enc, RSA_OAEP))
        pub = jwk.key.public_key
        pri = jwk.key.private_key
        self.assertEqual(base64.long_to_b64(pub.n), jwk_dict['n'])

        # decrypt and encrypt CEK
        dec_cek = key_enc.decrypt(pri, cek_enc_bytes)
        self.assertEqual(dec_cek, cek)      # Appendix OK
        # --- encryption outcome MAY changes,
        #      but decrypted plaint is same as the original
        enc_cek = key_enc.encrypt(pub, cek)
        dec_cek_2 = key_enc.decrypt(pri, enc_cek)
        self.assertEqual(dec_cek, dec_cek_2)

        # Appendix A.1.4
        iv_oct = [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]
        iv = ''.join(chr(i) for i in iv_oct)
        iv_b64url = '48V1_ALb6US04U3b'
        self.assertEqual(iv_b64url, base64.base64url_encode(iv))

        # Appendix A.1.5
        aad_oct = [
            101, 121, 74, 104, 98, 71, 99, 105,
            79, 105, 74, 83, 85, 48, 69,
            116, 84, 48, 70, 70, 85, 67, 73,
            115, 73, 109, 86, 117, 89, 121, 73,
            54, 73, 107, 69, 121, 78, 84, 90,
            72, 81, 48, 48, 105, 102, 81]
        aad = ''.join(chr(i) for i in aad_oct)

        # Appendix A.1.6
        cenc = jwe.enc.get_encryptor()
        from jose.jwa.gcm import GCMA256
        self.assertTrue(isinstance(cenc, GCMA256))

        ciphert_oct = [
            229, 236, 166, 241, 53, 191, 115,
            196, 174, 43, 73, 109, 39, 122,
            233, 96, 140, 206, 120, 52, 51, 237,
            48, 11, 190, 219, 186, 80, 111,
            104, 50, 142, 47, 167, 59, 61, 181,
            127, 196, 21, 40, 82, 242, 32,
            123, 143, 168, 226, 73, 216, 176,
            144, 138, 247, 106, 60, 16, 205,
            160, 109, 64, 63, 192]

        ciphert = "".join(chr(i) for i in ciphert_oct)

        tag_oct = [
            92, 80, 104, 49, 133, 25, 161,
            215, 173, 101, 219, 211, 136, 91,
            210, 145]
        tag = "".join(chr(i) for i in tag_oct)

        # Content Decrytion
        pt, is_valid = cenc.decrypt(cek, ciphert, iv, aad, tag)
        self.assertEqual(pt, plaint)        # consistent with the spec
        self.assertTrue(is_valid)
        #:  encryt and decryt
        ct, tag2 = cenc.encrypt(cek, plaint, iv, aad)
        pt2, is_valid2 = cenc.decrypt(cek, ct, iv, aad, tag2)
        self.assertEqual(pt2, plaint)        # consistent with the spec
        self.assertTrue(is_valid2)

if __name__ == '__main__':
    unittest.main()
