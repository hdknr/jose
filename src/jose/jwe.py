from crypto import Crypto, CryptoMessage
from jose.jwa.encs import EncEnum, KeyEncEnum
from jose import BaseEnum, BaseObject
from jose.jwk import Jwk
from jose.utils import merged, _BD, _BE
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
        if data and self.value == 'DEF':
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
        if isinstance(self.epk, dict):
            self.epk = Jwk(**self.epk)
        if isinstance(self.apu, unicode):
            self.apu = self.apu.encode('utf8')
        if isinstance(self.apv, unicode):
            self.apv = self.apv.encode('utf8')

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
        return self.alg.encryptor.provide(self.enc, jwk, self)

    def agree_key(self, jwk, cek_ci):
        return self.alg.encryptor.agree(self.enc, jwk, self, cek_ci)


class Recipient(BaseObject):
    ''' Per Receiver CEK Management
    '''
    _fields = dict(
        header=None,            # JWE Per-Recipient Unprotected Header
        encrypted_key=None,     # BASE64URL(JWE Encrypted Key)
    )
    _excludes = [
        'recipient', 'cek', 'iv', ]

    def __init__(self, recipient=None, iv=None, cek=None, **kwargs):
        super(Recipient, self).__init__(**kwargs)

        # Jwe
        if isinstance(self.header, basestring):
            self.header = Jwe.from_b64u(self.header)
        elif isinstance(self.header, dict):
            self.header = Jwe(**self.header)

        self.recipient = recipient
        self.cek = cek
        self.iv = iv

    def provide_key(self, jwk, cek=None, iv=None, jwe=None):
        jwe = Jwe.merge(self.header, jwe)

        assert jwk and isinstance(jwk, Jwk), "Recipient's Jwk must specifile"
        assert jwe
        assert jwe.enc
        assert jwe.alg

        if jwk.kid and not self.header.kid:
            self.header.kid = jwk.kid

        (self.cek, self.iv, self.encrypted_key, kek
         ) = jwe.alg.encryptor.provide(jwe.enc, jwk, self.header, cek, iv)

        self.encrypted_key = _BE(self.encrypted_key)

        return self.cek, self.iv

    def agree_key(self, jwk, jwe=None):
        jwe = Jwe.merge(self.header, jwe)
        assert jwk.is_private, "Agreement jwk must be private."

        self.cek = jwe.alg.encryptor.agree(
            jwe.enc, jwk, self.header,
            _BD(self.encrypted_key))
        return self.cek


class Message(CryptoMessage):
    '''  Encryptoed Message Container
    '''
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

    _excludes = ['cek', ]

    def __init__(self, plaintext=None, *args, **kwargs):
        self._protected = Jwe()  # `protected` cache as Jwe object
        self._plaintext = plaintext
        self.cek = None

        super(Message, self).__init__(*args, **kwargs)

        self._convert_recipients(self.recipients)

        if isinstance(self.protected, basestring):
            self._protected = Jwe.from_b64u(self.protected)
            if isinstance(self.protected, unicode):
                self.protected = self.protected.encode('utf8')

        elif isinstance(self.protected, Jwe):
            self._protected = self.protected
            self.protected = self._protected.to_b64u()

        if isinstance(self.unprotected, dict):
            self.unprotected = Jwe(**self.unprotected)

    def _convert_recipients(self, src):
        if not isinstance(src, list):
            return

        new = []
        for r in src:
            if isinstance(r, Recipient):
                new.append(r)
            elif isinstance(r, dict):
                new.append(Recipient(**r))
        self.recipients = new

    def header(self, index=-1, jwe=None):
        return Jwe.merge(
            self._protected,
            self.unprotected,
            self.recipients[index].header if index >= 0 else None,
            jwe,
        )

    @property
    def auth_data(self):
        if self.aad:
            # self.aad is exclusively for JSON Serializatio
            # Jwe 5.1
            return self.protected + "." + self.aad
        return self.protected

    def zip(self, src, unzip=False):
        ''' if "protected" has "zip", compress src
            <Spec Jwe 4.1.3>
        '''
        if self._protected and self._protected.zip:
            if unzip:
                return self._protected.zip.uncompress(src)
            else:
                return self._protected.zip.compress(src)
        return src

    def encrypt(self, header=None, auth_data=None):
        auth_data = auth_data or self.auth_data
        header = header or self.header()
        assert self.cek
        assert self.iv
        assert self.auth_data

        plaint = self.zip(self.plaintext)   # 'zip' compression
        ciphert, tag = header.enc.encryptor.encrypt(
            self.cek, plaint, _BD(self.iv), auth_data)
        return (ciphert, tag)

    def add_recipient(self, recipient):
        ''' before call, recipient has to be provided with
            messsage's CEK and IV
        '''
        header = self.header(jwe=recipient.header)
        key = header.load_key(recipient.recipient)

        if len(self.recipients) < 1:
            #: Provide CEK & IV
            (self.cek, self.iv) = recipient.provide_key(
                key, jwe=header)
            self.iv = _BE(self.iv)
        else:
            # use existent cek and iv
            assert self.cek
            assert self.iv
            recipient.provide_key(key, self.cek, self.iv, jwe=header)

        self.recipients.append(recipient)

    def find_cek(self, jwk=None):
        ''' force to use jwk '''
        header = self.header()
        for recipient in self.recipients:
            jwk = jwk or recipient.header.load_key(recipient.recipient)
            if jwk:
                #: key agreement fails if receiver is not me.
                self.cek = recipient.agree_key(jwk, jwe=header)
                return self.cek
            else:
                #:TODO log
                pass

        return None

    def decrypt(self, jwk=None):
        if not self.cek:
            self.find_cek(jwk)

        header = self.header()           # Two Jwe headered are merged.
        assert self.cek
        assert self.ciphertext
        assert self.iv
        assert self.tag

        plaint, is_valid = header.enc.encryptor.decrypt(
            self.cek,
            _BD(self.ciphertext),
            _BD(self.iv),
            self.auth_data,
            _BD(self.tag))

        # TODO: is_valid == False, raise execption

        return self.zip(plaint, unzip=True)

    def get_plaintext(self, jwk=None):
        #: If CEK has not been found

        if not self.cek:
            self.find_cek(jwk)

        self._plaintext = self.decrypt()
        return self._plaintext

    @property
    def plaintext(self):
        if self._plaintext:
            # already decrypted and cached
            return self._plaintext

        return self.decrypt()

    @plaintext.setter
    def plaintext(self, value):
        # CEK is not serizalied.
        self._plaintext = value

    def text(self):
        return self.plaintext

    @classmethod
    def from_token(cls, token, sender, receiver):
        '''
            :param token: Serialized Jws (JSON or Compact)
            :param str sender: Message sender identifier
        '''

        try:
            message = cls.from_json(token)
            for rec in message.recipients:
                rec.recipient = receiver
            return message

        except ValueError:
            #: fall to  compact serialization
            pass

        except Exception, e:
            print ">>>>>>", type(e)
            print traceback.format_exc()

        return cls.parse_token(token, sender, receiver)

    @classmethod
    def parse_token(cls, token, sender, recipient):
        '''
            :param token: Compact Serialization
            :param str sender: Message sender identifier
        '''

        try:
            m = _compact.search(token).groupdict()
            header = Jwe.from_b64u(m.get('header', None))
            recipient = dict(
                recipient=recipient,
                header=header,
                encrypted_key=m.get('encrypted_key', None),
            )
            message = Message(
                protected=m.get('header', None),
                iv=m.get('iv', None),
                tag=m.get('tag', None),
                ciphertext=m.get('ciphertext', None),
                recipients=[recipient]
            )
            assert len(message.recipients) == 1
            return message

        except Exception, e:
            print ">>>>>>", type(e)
            print traceback.format_exc()

        return None

    def serialize_json(self, **kwargs):
        assert self.iv
        assert self.cek

        #: Content encryption
        (self.ciphertext,
         self.tag) = self.encrypt()

        self.ciphertext = _BE(self.ciphertext)
        self.tag = _BE(self.tag)

        return self.to_json(**kwargs)

    def serialize_compact(self, index=0):
        if len(self.recipients) < 1:
            return None

        header = self.header(index)      # all header togher
        header_b64u = header.to_b64u()   # auth_data = _BE(header)
        #: encrypt with same CEK+IV, but with new auth_data
        ciphertext, tag = self.encrypt(header, header_b64u)

        #: Tokenize
        return ".".join([
            header_b64u,
            self.recipients[0].encrypted_key or '',
            self.iv,
            _BE(ciphertext),
            _BE(tag)])
