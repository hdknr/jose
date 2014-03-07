Jose
====================================

Cryptography Depencencies
------------------------------------

Most of them
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    $ pip instal pycrypto


ECDSA, ECDH-ES
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- https://github.com/niccokunzmann/ecc

.. code-block:: bash

    $ pip install ecc

PKCS#5 v2.0 PBKDF2 Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

    $ pip install -e git+https://github.com/dlitz/python-pbkdf2.git#egg=pbkdf2

128 bit AES GCM
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- https://github.com/bozhu/AES-GCM-Python

For convenience, there is a setup.py in hdknr fork :

.. code-block:: bash

    $ pip install -e git+https://github.com/hdknr/AES-GCM-Python#egg=aes_gcm
