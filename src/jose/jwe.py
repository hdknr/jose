from crypto import Crypto
from jose.jwa.encs import EncEnum, KeyEncEnum
from jose import BaseEnum, BaseObject
from jose.utils import merged
import re
import traceback
import zlib

# http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-23#section-7.1
_component = [
    r'^(?P<header>[^\.]+)',
    r'(?P<encrypted_key>[^\.]*)',   #: blank for shared key.
    r'(?P<iv>[^\.]+)',
    r'(?P<ciphertext>[^\.]+)',
    r'(?P<tag>[^\.]+)$',
]

_compact = re.compile('\.'.join(_component))


class ZipEnum(BaseEnum):
    DEF = 'DEF'

    def compress(self, data):
        if self.value == 'DEF':
            return zlib.compress(data)
        return data

    def uncompress(self, data):
        if self.value == 'DEF':
            return zlib.decompress(data)
        return data


BASE_FIELD = dict(
    enc=None,   #: EncEnum Algorithm
    zip=None,   #: ZipEnum Compression Algorithm
)

GCM_FIELD = dict(
    iv=None,    #: IV for Key Wrap
    tag=None,   #: Auth Tag for Key Wrap
)

ECDH_FIELD = dict(
    epk=None,   #: Ephemeral Public Key
    apu=None,   #: Agreement ParytUInfo
    apv=None,   #: Agreement PartyVInf
)

PBES_FIELD = dict(
    p2s=None,    #: Salt for PBKDF2
    p2c=None,    #: Loop counts for PBKDF2
)


class Jwe(Crypto):
    _fields = merged([
        Crypto._fields, BASE_FIELD,
        GCM_FIELD, ECDH_FIELD, PBES_FIELD
    ])

    def __init__(self, **kwargs):
        super(Jwe, self).__init__(**kwargs)
        if isinstance(self.alg, basestring):
            self.alg = KeyEncEnum.create(self.alg)
        if isinstance(self.zip, basestring):
            self.zip = ZipEnum.create(self.zip)
        if isinstance(self.enc, basestring):
            self.enc = EncEnum.create(self.enc)

    @classmethod
    def from_json(cls, json_str, base=None):
        obj = BaseObject.from_json(json_str, cls)
        obj.enc = EncEnum.create(obj.enc)
        obj.zip = ZipEnum.create(obj.zip)
        return obj

    @classmethod
    def from_token(cls, token):
        m = re.search(_compact)

        return m and cls()

    def to_token(self):
        return ''

    def provide_key(self, jwk):
        return self.alg.encryptor.provide(jwk, self)

    def agree_key(self, jwk, cek_ci):
        return self.alg.encryptor.agree(jwk, self, cek_ci)


class Recipient(BaseObject):
    _fields = dict(
        header=None,            # JWE Per-Recipient Unprotected Header
        encrypted_key=None,     # BASE64URL(JWE Encrypted Key)
    )

    def __init__(self, **kwargs):
        super(Recipient, self).__init__(**kwargs)

        # Jwe
        if isinstance(self.header, basestring):
            self.header = Jwe.from_base64(self.header)

        self._cek, self._iv = None, None

    def provide_key(self, jwk, cek=None, iv=None):
        assert jwk.is_public, "providing jwk must be public."
        (self._cek, self._iv, self.encrypted_key
         ) = self.jwe.alg.encryptor.provide(self.header, jwk, cek, iv)
        return self._cek, self._iv

    def agree_key(self, jwk):
        assert jwk.is_private, "Agreement jwk must be private."
        self._cek = self.header.alg.encryptor.agree(
            self.header, self.encrypted_key, jwk)
        return self._cek

    def load_key(self, receiver):
        return self.header.load_key(receiver)


class Message(BaseObject):
    _fields = dict(
        protected=None,     # BASE64URL(UTF8(JWE Protected Header))
        unprotected=None,   # JWE Shared Unprotected Header (Json)
        iv='',              # BASE64URL(JWE Initialization Vector)
        aad='',             # BASE64URL(JWE AAD))
                            # (only used for Json Serialization)
        ciphertext='',      # BASE64(JWE Ciphertext)
        tag='',             # BASE64URL(JWE Authentication Tag)
        recipients=[],      # array of Recipient
    )

    def __init__(self, *args, **kwargs):
        self._plaintext = None
        self._cek = None
        super(Message, self).__init__(*args, **kwargs)
        if isinstance(self.recipients, list):
            self.recipients = map(lambda i: Recipient(**i),
                                  self.recipients)
        if isinstance(self.protected, basestring):
            self.protected = Jwe.from_json(self.protected)

    def create_ciphertext(self, recipient, plaint, receiver):
        ''' before call, recipient has to be provided _iv and _cek
        '''
        jwk = recipient.load_key(receiver).public_jwk
        (self._cek, self.iv) = recipient.provide_key(jwk)

        self.recipients = []      # reset recipient

        #: Two Jwe headered are merged.
        header = self.protected.merge(self.unprotected)
        if header.zip:
            plaint = header.zip.compress(plaint)

        (self.ciphertext,
         self.tag) = header.enc.encryptor.encrypt(
            recipient._cek, plaint, self.iv, self.aad)

        self.recipients.append(recipient)

    def add_recipient(self, recipient, receiver):
        ''' before call, recipient has to be provided with
            messsage's CEK and IV
        '''
        # use existent cek and iv
        recipient.provide(receiver, self.cek, self.iv)
        self.recipients.append(recipient)

    @property
    def plaintext(self):
        if self._plaint:
            # already decrypted and cached
            return self._plaint

        #: Two Jwe headered are merged.
        header = self.protected.merge(self.unprotected)

        for recipient in self.recipients:
            jwk = recipient.load_key(self.receiver).private_jwk
            #: key agreement fails if receiver is not me.
            recipient.agree_key(jwk)
            if recipient._cek:
                # only recipient has receiver's private key can agree
                self._plaint = header.enc.encryptor.decrypt(
                    recipient._cek, self.ciphertext,
                    self.iv, self.aad, self.tag)
                if header.zip:
                    self._plaint = header.zip.uncompress(self._plaint)

        return self._plaint

    @property
    def cek(self):
        return self._cek

    @cek.setter
    def cek(self, value):
        self._cek = value

    @classmethod
    def from_token(cls, token, sender, receiver):
        '''
            :param token: Serialized Jws (JSON or Compact)
            :param str sender: Message sender identifier
        '''

        try:
            message = cls.from_json(token)
            message.sender = sender
            message.receiver = receiver
            return message

        except ValueError:
            #: fall to  compact serialization
            pass
        except Exception, e:
            print ">>>>>>", type(e)
            print traceback.format_exc()

        try:
            m = _compact.search(token).groupdict()
            message = cls(recepients=[Recipient(**m)], **m)
            message.sender = sender
            message.receiver = receiver
            return message
        except Exception, e:
            print ">>>>>>", type(e)
            print traceback.format_exc()

        return None
