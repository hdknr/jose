# -*- coding: utf-8 -*-

import unittest
from jose.store import FileStore
from jose.jwk import Jwk


class TestStore(unittest.TestCase):

    def test_save_and_load(self):
        fs = FileStore(None)
        jwk = Jwk()
        fs.save(jwk)

    def test_conf(self):
        from jose import conf
        jwk = Jwk()
        conf.store.save(jwk)


if __name__ == '__main__':
    unittest.main()
