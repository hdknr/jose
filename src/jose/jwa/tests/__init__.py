# -*- coding: utf-8 -*-


if __name__ == '__main__':
    import unittest
    import importlib

    for name in ['jwa', 'rsa', 'ec', ]:
        mod = importlib.import_module("test_{:s}".format(name))
        for attr in dir(mod):
            if not attr.startswith('Test'):
                continue
            globals()[attr] = getattr(mod, attr)

    unittest.main()
