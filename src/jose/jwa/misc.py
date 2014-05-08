from jose.base import BaseKeyEncryptor


class NONE(object):

    @classmethod
    def sign(cls, jwk, data):
        return ''

    @classmethod
    def verify(cls, jwk, data, signature=None):
        return True


class DIR(BaseKeyEncryptor):
    @classmethod
    def provide(cls, enc, jwk, jwe, cek=None, iv=None, *args, **kwargs):
        ''' cek == None
        '''
        cek_ci, kek = None, None
        cek, iv = enc.encryptor.create_key_iv()
        cek = jwk.key.shared_key[:enc.encryptor.key_length()]
        return cek, iv, cek_ci, kek

    @classmethod
    def agree(cls, enc, jwk, jwe, cek_ci, *args, **kwargs):
        ''' cek_ci = None
        '''
        return jwk.key.shared_key[:enc.encryptor.key_length()]
