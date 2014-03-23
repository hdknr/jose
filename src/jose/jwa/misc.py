class NONE(object):

    @classmethod
    def sign(cls, jwk, data):
        return ''

    @classmethod
    def verify(cls, jwk, data, signature=None):
        return True


class DIR(object):
    pass
