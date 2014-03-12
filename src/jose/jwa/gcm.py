from Crypto.Util.number import long_to_bytes, bytes_to_long
from aes_gcm import AES_GCM, InvalidTagException
from jose import BaseContentEncryptor

# Key Encryption


class GcmKeyEncryptor(object):
    pass


class GCMA128KW(GcmKeyEncryptor):
    pass


class GCMA192KW(GcmKeyEncryptor):
    pass


class GCMA256KW(GcmKeyEncryptor):
    pass


# Content Encryption

class GcmContentEncryptor(BaseContentEncryptor):
    _IV_LEN = 12    # octs -> 96bits
    _TAG_LEN = 16   # octs -> 128bits

    def encrypt(self, cek, plaint, iv, aad, *args, **kwargs):
        assert cek and len(cek) == self._KEY_LEN
        assert iv and len(iv) == self._IV_LEN

        ci = AES_GCM(bytes_to_long(cek))
        ciphert, tag = ci.encrypt(bytes_to_long(iv), plaint,  aad)

        return ciphert, long_to_bytes(tag)

    def decrypt(self, cek, ciphert, iv, aad, tag, *args,  **kwargs):
        print "@@@@@", type(self), len(cek), len(iv), len(tag)
        assert cek and len(cek) == self._KEY_LEN
        assert iv and len(iv) == self._IV_LEN
        assert tag and len(tag) == self._TAG_LEN

        ci = AES_GCM(bytes_to_long(cek))
        try:
            plaint = ci.decrypt(bytes_to_long(iv), ciphert,
                                bytes_to_long(tag), aad)
            return plaint, True
        except InvalidTagException:
            return (None, False)


class GCMA128(GcmContentEncryptor):
    _KEY_LEN = 16   # octs -> 128bits


class GCMA192(GcmContentEncryptor):
    _KEY_LEN = 24   # octs -> 192bits


class GCMA256(GcmContentEncryptor):
    _KEY_LEN = 32   # octs -> 256bits


if __name__ == '__main__':

    from jose.utils import base64
    for enc in [GCMA128, GCMA192, GCMA256]:
        cek, iv = enc.create_key_iv()
        assert len(cek) == enc._KEY_LEN
        assert len(iv) == enc._IV_LEN
        print enc.__name__
        print "CEK =", base64.urlsafe_b64encode(cek)
        print "IV=", base64.urlsafe_b64encode(iv)
