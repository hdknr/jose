# -*- coding: utf-8 -*-

import unittest
from jose.jwk import Jwk
#from jose.jwa.sigs import SigEnum
#from jose.jwa.keys import KeyTypeEnum
from jose.utils import base64
from jose.jwa.hmac import HS256, HS384, HS512


class TestHmac(unittest.TestCase):

    def test_hmac(self):
        jwk = Jwk(
            kty="oct",
            k=''.join([
                'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75'
                'aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'])
        )
        self.assertEqual(jwk.k, base64.base64url_encode(jwk.key.material))

        msg = "Best of my life."
        for mac in [HS256, HS384, HS512]:
            sig = mac().sign(jwk, msg)
            self.assertTrue(mac().verify(jwk, msg, sig))


if __name__ == '__main__':
    unittest.main()
