# -*- coding: utf-8 -*-

import unittest

from jose.jwk import Jwk, JwkSet
from jose.jwe import Jwe, ZipEnum, Message, Recipient
from jose.jwa.encs import KeyEncEnum, EncEnum
from jose.jwa.keys import KeyTypeEnum
from jose.utils import base64
import traceback
from jose.tests import (
    JWE_A2, JWE_A3, JWE_B,
)
from jose.crypto import KeyOwner

_S = lambda o: ''.join([chr(i) for i in o])
_BE = lambda s: base64.base64url_encode(s)
_BD = lambda s: base64.base64url_decode(s)


class TestEntity(KeyOwner):
    def __init__(self, identifier, jku, jwkset=None):
        self.identifier = identifier 
        self.jku = jku
        self.jwkset = JwkSet(
            keys=[
                Jwk.generate(KeyTypeEnum.RSA),
                Jwk.generate(KeyTypeEnum.EC),
                Jwk.generate(KeyTypeEnum.OCT),
            ]   
        )  

    def get_key(self, crypto, *args, **kwargs):
        assert len(self.jwkset.keys) > 0, "TestEntity has some Jwks."
        return self.jwkset.get_key(
            crypto.key_type, kid=crypto.kid
        ) 

class TestJwe(unittest.TestCase):

    def test_simple(self):
        '''
        nose2 jose.tests.test_jwe.TestJwe.test_simple
        '''
        data = '{ "alg": "RSA1_5",  "zip": "DEF" }'
        jwe1 = Jwe.from_json(data)
        print dir(jwe1)
        self.assertEqual(jwe1.alg, KeyEncEnum.RSA1_5)

    def test_merge(self):
        ''' Jwe specs 3 jwe objects(2 in Message, 1 on Signature)
        nose2 jose.tests.test_jwe.TestJwe.test_merge
        '''
        jwe1 = Jwe.from_json('{ "alg": "RSA1_5"}')
        jwe2 = Jwe.from_json('{ "zip": "DEF"}')
        jwe3 = Jwe.merge(jwe1, jwe2)

        self.assertEqual(jwe3.alg, KeyEncEnum.RSA1_5)
        self.assertEqual(jwe3.zip, ZipEnum.DEF)
        self.assertIsNone(jwe1.zip)
        self.assertIsNone(jwe2.alg)

    def test_jwa_appendix_a4(self):
        '''
        nose2 jose.tests.test_jwe.TestJwe.test_jwa_appendix_a4
        '''
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
        self.assertEqual(msg.iv, JWE_A3.iv_b64)
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
        msg.cek = JWE_B.cek
        self.assertEqual(msg.plaintext, JWE_A3.plaint)

        #:
        print msg.to_json(indent=2)

    def test_jwe_appendix2(self):
        '''
        nose2 jose.tests.test_jwe.TestJwe.test_jwe_appendix2
        '''

        jwemsg = Message.from_token(JWE_A2.jwe_token, None, None)

        self.assertEqual(jwemsg.protected, JWE_A2.jwe_header_b64u)
        self.assertEqual(jwemsg.tag, JWE_A2.auth_tag_b64u)
        self.assertEqual(jwemsg.ciphertext, JWE_A2.ciphert_b64u)
        self.assertEqual(jwemsg.iv, JWE_A2.iv_b64u)

        self.assertEqual(len(jwemsg.recipients), 1)
        self.assertEqual(jwemsg.recipients[0].encrypted_key,
                         JWE_A2.jwe_enc_key_b64u)
        self.assertEqual(jwemsg.recipients[0].header.alg,
                         KeyEncEnum.RSA1_5)
        self.assertEqual(jwemsg.recipients[0].header.enc,
                         EncEnum.A128CBC_HS256)

        jwk = Jwk(**JWE_A2.jwk_dict)
        print "Jwk", jwk.kty, jwk.length
        plaint = jwemsg.get_plaintext(jwk=jwk)

        self.assertEqual(jwemsg.plaintext, JWE_A2.plaint)
        self.assertEqual(jwemsg.cek, JWE_A2.cek)

        print plaint, jwemsg.to_json()


class TestJweMessage(unittest.TestCase):

    def test_message(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_message
        '''
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
        print "============================================================"
        print " TEST for", alg, enc
        print "============================================================"
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
            m = Message.from_token(t, sender=None, receiver=receiver)
            m.get_plaintext()

            self.assertEqual(
                len(message.recipients), len(m.recipients))
            self.assertEqual(_BD(m.plaintext), plaintext)

        return message

    def _create_jwk(self, owner, jku, alg):
        #        jwk = Jwk.get_or_create_from(
        #         owner, jku, alg.key_type, kid=None)
        jwk = Jwk.generate(alg.key_type)
        return jwk

    def test_message_rsakw(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_message_rsakw
        '''
        
        plaintext = "Everybody wants to rule the world."
        jku= "http://test.rsa.com/jwkset",
        receiver =  TestEntity(
            identifier="http://test.rsa.com",
            jku=jku, 
            jwkset=JwkSet()
        )

        for alg in [KeyEncEnum.RSA1_5, KeyEncEnum.RSA_OAEP]:
            for enc in EncEnum.all():
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_aeskw(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_message_aeskw
        '''
        plaintext = "Everybody wants to rule the world."

        jku= "http://test.rsa.com/jwkset",
        receiver =  TestEntity(
            identifier="http://test.rsa.com",
            jku=jku, 
            jwkset=JwkSet()
        )

        for alg in [KeyEncEnum.A128KW, KeyEncEnum.A192KW, KeyEncEnum.A256KW]:
            for enc in EncEnum.all():
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_gcmkw(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_message_gcmkw
        '''
        plaintext = "Everybody wants to rule the world."
        jku= "http://test.rsa.com/jwkset",
        receiver =  TestEntity(
            identifier="http://test.rsa.com",
            jku=jku, 
            jwkset=JwkSet()
        )

        for alg in [
            KeyEncEnum.GCMA128KW,
            KeyEncEnum.GCMA192KW,
            KeyEncEnum.GCMA256KW
        ]:
            for enc in EncEnum.all():
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_pbes2kw(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_message_pbes2kw
        '''
        plaintext = "Everybody wants to rule the world."

        jku= "http://test.pebs2.com/jwkset",
        receiver =  TestEntity(
            identifier="http://test.rsa.com",
            jku=jku, 
            jwkset=JwkSet()
        )

        for alg in [
            KeyEncEnum.PBES2_HS256_A128KW,
            KeyEncEnum.PBES2_HS384_A192KW,
            KeyEncEnum.PBES2_HS512_A256KW,
        ]:
            for enc in EncEnum.all():
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_ecdhkw(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_message_ecdhkw
        '''
        plaintext = "Everybody wants to rule the world."

        jku= "http://test.ecdhkw.com/jwkset",
        receiver =  TestEntity(
            identifier="http://test.ecdhkw.com",
            jku=jku, 
            jwkset=JwkSet()
        )

        for alg in [
            KeyEncEnum.ECDH_ES_A128KW,
            KeyEncEnum.ECDH_ES_A192KW,
            KeyEncEnum.ECDH_ES_A256KW,
        ]:
            for enc in EncEnum.all():
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_ecdhdir(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_message_ecdhdir
        '''
        plaintext = "Everybody wants to rule the world."

        jku= "http://test.ecdhdir.com/jwkset",
        receiver =  TestEntity(
            identifier="http://test.ecdhdir.com", jku=jku, 
        )

        for alg in [
            KeyEncEnum.ECDH_ES,
        ]:
            for enc in EncEnum.all():
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_message_dir(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_message_dir
        '''
        plaintext = "Everybody wants to rule the world."
        
        jku= "http://test.dir.com/jwkset",
        receiver =  TestEntity(
            identifier="http://test.dir.com", jku=jku, 
        )

        for alg in [
            KeyEncEnum.DIR,
        ]:
            for enc in EncEnum.all():
                self._alg_enc_test(alg, enc, receiver, jku, plaintext)

    def test_multi(self):
        '''
        nose2 jose.tests.test_jwe.TestJweMessage.test_multi
        '''

        payload = "All you need is love."

        jku= "http://test.multi.com/jwkset",
        receiver =  TestEntity(
            identifier="http://test.multi.com", jku=jku, 
        )
        fake =  TestEntity(
            identifier="http://test.fake.com", jku=jku, 
        )

        enc = EncEnum.all()[0]

        for enc in EncEnum.all():
            message = Message(
                protected=Jwe(enc=enc, zip="DEF",),
                unprotected=Jwe(typ="text"),
                plaintext=_BE(payload)
            )

            for alg in KeyEncEnum.all():
                if alg.single:
                    continue

                recipient = Recipient(
                    header=Jwe(alg=alg, jku=jku,),
                    recipient=receiver
                )
                message.add_recipient(recipient)

            json_message = message.serialize_json(indent=2)

            receivers = [fake, receiver]
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
