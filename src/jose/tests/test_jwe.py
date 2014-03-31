# -*- coding: utf-8 -*-

import unittest

from jose.jwk import Jwk
from jose.jwe import Jwe, ZipEnum, Message, Recipient
from jose.jwa.encs import KeyEncEnum, EncEnum
from jose.jwa.keys import KeyTypeEnum
from jose.utils import base64
import traceback


_S = lambda o: ''.join([chr(i) for i in o])
_BE = lambda s: base64.base64url_encode(s)
_BD = lambda s: base64.base64url_decode(s)


class A2:
    plaint_oct = [
        76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32,
        112, 114, 111, 115, 112, 101, 114, 46]
    plaint = _S(plaint_oct)
    jwe_header = '{"alg":"RSA1_5","enc":"A128CBC-HS256"}'
    jwe_header_b64u = 'eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0'
    cek_oct = [
        4, 211, 31, 197, 84, 157, 252, 254, 11,
        100, 157, 250, 63, 170, 106,
        206, 107, 124, 212, 45, 111, 107, 9, 219,
        200, 177, 0, 240, 143, 156, 44, 207]
    cek = _S(cek_oct)
    jwk_dict = dict(
        kty="RSA",
        n="".join([
            "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl",
            "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre",
            "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_",
            "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI",
            "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU",
            "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
        ]),
        e="AQAB",
        d="".join([
            "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq",
            "1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-ry",
            "nq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_",
            "0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj",
            "-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-Kyvj",
            "T1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
        ])
    )
    jwe_enc_key_oct = [
        80, 104, 72, 58, 11, 130, 236, 139, 132, 189, 255, 205, 61, 86, 151,
        176, 99, 40, 44, 233, 176, 189, 205, 70, 202, 169, 72, 40, 226, 181,
        156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156,
        116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223,
        226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66,
        212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253,
        215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128,
        66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199,
        54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151,
        250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197,
        21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102,
        166, 182, 172, 197, 136, 230, 120, 60, 58, 219, 243, 149, 94, 222,
        150, 154, 194, 110, 227, 225, 112, 39, 89, 233, 112, 207, 211, 241,
        124, 174, 69, 221, 179, 107, 196, 225, 127, 167, 112, 226, 12, 242,
        16, 24, 28, 120, 182, 244, 213, 244, 153, 194, 162, 69, 160, 244,
        248, 63, 165, 141, 4, 207, 249, 193, 79, 131, 0, 169, 233, 127, 167,
        101, 151, 125, 56, 112, 111, 248, 29, 232, 90, 29, 147, 110, 169,
        146, 114, 165, 204, 71, 136, 41, 252]
    jwe_enc_key = _S(jwe_enc_key_oct)
    jwe_enc_key_b64u = ''.join([
        "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm",
        "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc",
        "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF",
        "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8",
        "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv",
        "-B3oWh2TbqmScqXMR4gp_A",
    ])
    iv_oct = [
        3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]
    iv = _S(iv_oct)
    iv_b64u = 'AxY8DCtDaGlsbGljb3RoZQ'
    jwe_protected_header_oct = [
        101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
        120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105,
        74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85,
        50, 73, 110, 48]
    ciphert_oct = [
        40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
        75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
        112, 56, 102]
    ciphert = _S(ciphert_oct)
    ciphert_b64u = 'KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY'
    auth_tag_oct = [
        246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100,
        191]
    auth_tag = _S(auth_tag_oct)
    auth_tag_b64u = '9hH0vgRfYgPnAHOd8stkvw'
    jwe_token = ''.join([
        "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.",
        "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm",
        "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc",
        "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF",
        "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8",
        "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv",
        "-B3oWh2TbqmScqXMR4gp_A.",
        "AxY8DCtDaGlsbGljb3RoZQ.",
        "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.",
        "9hH0vgRfYgPnAHOd8stkvw",
    ])


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
        jwe3 = Jwe.merge(jwe1, jwe2)

        self.assertEqual(jwe3.alg, KeyEncEnum.RSA1_5)
        self.assertEqual(jwe3.zip, ZipEnum.DEF)
        self.assertIsNone(jwe1.zip)
        self.assertIsNone(jwe2.alg)

    def test_jwa_appendix_a4(self):
        import os
        json_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'jwe_appendix_a4.json')

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

    def test_jwe_appendix2(self):

        jwemsg = Message.from_token(A2.jwe_token, None, None)

        self.assertEqual(jwemsg.protected, A2.jwe_header_b64u)
        self.assertEqual(jwemsg.tag, A2.auth_tag_b64u)
        self.assertEqual(jwemsg.ciphertext, A2.ciphert_b64u)
        self.assertEqual(jwemsg.iv, A2.iv_b64u)

        self.assertEqual(len(jwemsg.recipients), 1)
        self.assertEqual(jwemsg.recipients[0].encrypted_key,
                         A2.jwe_enc_key_b64u)
        self.assertEqual(jwemsg.recipients[0].header.alg,
                         KeyEncEnum.RSA1_5)
        self.assertEqual(jwemsg.recipients[0].header.enc,
                         EncEnum.A128CBC_HS256)

        jwk = Jwk(**A2.jwk_dict)
        plaint = jwemsg.get_plaintext(jwk=jwk)

        self.assertEqual(jwemsg.plaintext, A2.plaint)
        self.assertEqual(jwemsg.cek, A2.cek)

        print plaint, jwemsg.to_json()


class TestJweMessage(unittest.TestCase):

    def test_message(self):
        jwe = Jwe(alg=KeyEncEnum.A128KW)
        jwe2 = Jwe.from_json(jwe.to_json(indent=2))
        self.assertEqual(jwe2.alg, jwe.alg)
        jwe3 = Jwe.from_b64u(jwe.to_b64u())
        self.assertEqual(jwe3.alg, jwe.alg)

        msg = Message(
            protected=Jwe(enc=EncEnum.A128CBC_HS256),
            unprotected=Jwe(zip='DEF'),
        )
        rec = Recipient(header=Jwe(alg=KeyEncEnum.A192KW))
        msg.recipients.append(rec)

        msg2 = Message.from_json(msg.to_json(indent=2))
        self.assertEqual(len(msg2.recipients), 1)
        self.assertEqual(msg2.recipients[0].header.alg, KeyEncEnum.A192KW)
        self.assertEqual(msg2.unprotected.zip, ZipEnum.DEF)

        header2 = msg2.header()
        self.assertEqual(header2.enc, EncEnum.A128CBC_HS256)
        self.assertEqual(header2.zip, ZipEnum.DEF)
        self.assertIsNone(header2.alg)

        header3 = msg2.header(0)
        self.assertEqual(header3.enc, EncEnum.A128CBC_HS256)
        self.assertEqual(header3.zip, ZipEnum.DEF)
        self.assertEqual(header3.alg, KeyEncEnum.A192KW)

    def _alg_enc_test(self, alg, enc, receiver, jku, plaintext):
        print "==============="
        print " TESST for", alg, enc
        print "==============="
        #: Message
        message = Message(
            protected=Jwe(enc=enc, zip="DEF",),
            unprotected=Jwe(typ="text"),
            plaintext=_BE(plaintext)
        )

        recipient = Recipient(
            header=Jwe(alg=alg, jku=jku),
            recipient=receiver
        )
        message.add_recipient(recipient)

        texts = [
            message.serialize_json(indent=2),
            message.serialize_compact(),
        ]

        for t in texts:
            print "--------------------------\n", t
            m = Message.from_token(
                t, sender=None, receiver=receiver)
            self.assertEqual(
                len(message.recipients), len(m.recipients))
            self.assertEqual(_BD(m.plaintext), plaintext)

        return message

    def _create_jwk(self, owner, jku, alg):
        jwk = Jwk.get_or_create_from(
            owner, jku, alg.key_type, kid=None)
        return jwk

    def test_message_rsakw(self):
        receiver = "http://test.rsa.com"
        plaintext = "Everybody wants to rule the world."
        jku = receiver + '/jwkset'

        for alg in [KeyEncEnum.RSA1_5, KeyEncEnum.RSA_OAEP]:
            self.assertEqual(
                self._create_jwk(receiver, jku, alg).kty,
                KeyTypeEnum.RSA)

            for enc in EncEnum.all():
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_aeskw(self):
        receiver = "http://test.aes.com"
        plaintext = "Everybody wants to rule the world."
        jku = receiver + '/jwkset'

        for alg in [KeyEncEnum.A128KW, KeyEncEnum.A192KW, KeyEncEnum.A256KW]:
            for enc in EncEnum.all():
                jwk = self._create_jwk(receiver, jku, alg)
                self.assertEqual(jwk.kty, KeyTypeEnum.OCT)
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_gcmkw(self):
        receiver = "http://test.gcm.com"
        plaintext = "Everybody wants to rule the world."
        jku = receiver + '/jwkset'

        for alg in [
            KeyEncEnum.GCMA128KW,
            KeyEncEnum.GCMA192KW,
            KeyEncEnum.GCMA256KW
        ]:
            for enc in EncEnum.all():
                jwk = self._create_jwk(receiver, jku, alg)
                self.assertEqual(jwk.kty, KeyTypeEnum.OCT)
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_pbes2kw(self):
        receiver = "http://test.pbes2.com"
        plaintext = "Everybody wants to rule the world."
        jku = receiver + '/jwkset'

        for alg in [
            KeyEncEnum.PBES2_HS256_A128KW,
            KeyEncEnum.PBES2_HS384_A192KW,
            KeyEncEnum.PBES2_HS512_A256KW,
        ]:
            for enc in EncEnum.all():
                jwk = self._create_jwk(receiver, jku, alg)
                self.assertEqual(jwk.kty, KeyTypeEnum.OCT)
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_ecdhkw(self):
        receiver = "http://test.ecdh.com"
        plaintext = "Everybody wants to rule the world."
        jku = receiver + '/jwkset'

        for alg in [
            KeyEncEnum.ECDH_ES_A128KW,
            KeyEncEnum.ECDH_ES_A192KW,
            KeyEncEnum.ECDH_ES_A256KW,
        ]:
            for enc in EncEnum.all():
                jwk = self._create_jwk(receiver, jku, alg)
                self.assertEqual(jwk.kty, KeyTypeEnum.EC)
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_ecdhdir(self):
        receiver = "http://test.ecdh.com"
        plaintext = "Everybody wants to rule the world."
        jku = receiver + '/jwkset'

        for alg in [
            KeyEncEnum.ECDH_ES,
        ]:
            for enc in EncEnum.all():
                jwk = self._create_jwk(receiver, jku, alg)
                self.assertEqual(jwk.kty, KeyTypeEnum.EC)
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_dir(self):
        receiver = "http://test.dir.com"
        plaintext = "Everybody wants to rule the world."
        jku = receiver + '/jwkset'

        for alg in [
            KeyEncEnum.DIR,
        ]:
            for enc in EncEnum.all():
                jwk = self._create_jwk(receiver, jku, alg)
                self.assertEqual(jwk.kty, KeyTypeEnum.OCT)
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_multi(self):

        payload = "Everybody wants to rule the world."

        enc = EncEnum.all()[0]

        for enc in EncEnum.all():
            message = Message(
                protected=Jwe(enc=enc, zip="DEF",),
                unprotected=Jwe(typ="text"),
                plaintext=_BE(payload)
            )

            receivers = []
            for alg in KeyEncEnum.all():
                if alg.single:
                    continue
                receiver = 'https://%s.com/' % alg.name.lower()
                receivers.append(receiver)
                jku = receiver + 'jwkset'
                Jwk.get_or_create_from(
                    receiver, jku, alg.key_type, kid=None,)

                recipient = Recipient(
                    header=Jwe(alg=alg, jku=jku,),
                    recipient=receiver
                )
                message.add_recipient(recipient)

            json_message = message.serialize_json(indent=2)

            for me in receivers:
                message2 = Message.from_token(
                    json_message, sender=None, receiver=me)

                self.assertEqual(
                    len(message.recipients), len(message2.recipients))
                try:
                    print _BD(message2.plaintext), enc, me
                except:
                    print traceback.format_exc()

if __name__ == '__main__':
    unittest.main()
