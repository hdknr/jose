# -*- coding: utf-8 -*-

import unittest
from jose.store import FileStore
from jose.jwk import Jwk


class TestStore(unittest.TestCase):

    def test_save_and_load(self):
        fs = FileStore()
        jwk = Jwk()
        fs.save(jwk)


if __name__ == '__main__':
    unittest.main()
