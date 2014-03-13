# -*- coding: utf-8 -*-

import unittest
from jose.utils import base64
from jose.jwe import Jwe
from jose.jwa.encs import EncEnum,  KeyEncEnum
from jose.jwa.keys import KeyTypeEnum
from jose.jwk import Jwk


class TestPbes2(unittest.TestCase):
    def test_pbes2(self):
        # PBES2-HS256+A128KW

        from pbkdf2 import PBKDF2
        from Crypto import Random

        klen = 16                           # key length

        # Sender ----
        cek = Random.get_random_bytes(klen) # CEK
        key = Random.get_random_bytes(klen) # shared key
        p2s = Random.get_random_bytes(32)   # salt
        p2c = 4096                          # iter count

        from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
        # Derive shared key to KEK by Alice
        kek_alice  = PBKDF2(key, p2s, p2c,
                            digestmodule=SHA256,
                            macmodule=HMAC).read(klen)
        self.assertEqual(len(kek_alice), klen)

        # Wrap CEK to CEKCI with AES
        from jose.jwa.aes import aes_key_wrap
        cekci = aes_key_wrap(kek_alice, cek)

        # Recepient ----
        # 'key' has been shared before a session.
        # 'p2s', 'p2c', and 'cekci' are delivered on a session

        # Derive shared key to KEY by Bob
        kek_bob = PBKDF2(key, p2s, p2c,
                         digestmodule=SHA256,
                         macmodule=HMAC).read(klen)
        self.assertEqual(kek_alice, kek_bob)

        # UnWrap CEKCI to CEK with AES
        from jose.jwa.aes import aes_key_unwrap
        cek_agreed = aes_key_unwrap(kek_bob, cekci)

        self.assertEqual(cek, cek_agreed)

if __name__ == '__main__':
    unittest.main()
