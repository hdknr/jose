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

if __name__ == '__main__':
    unittest.main()
