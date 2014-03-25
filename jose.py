import logging
logger = logging.getLogger(__name__)

try:
    from cjson import encode as json_encode, decode as json_decode
except ImportError:  # pragma: nocover
    logger.warn('cjson not found, falling back to stdlib json')
    from json import loads as json_decode, dumps as json_encode

import zlib

from base64 import urlsafe_b64encode, urlsafe_b64decode
from collections import namedtuple
from time import time

from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_SIG


__all__ = ['encrypt', 'decrypt', 'sign', 'verify']


# XXX: The attribute order is IMPORTANT in the following namedtuple
# definitions. DO NOT change them, unless you really know what you're doing.

JWE = namedtuple('JWE',
    'header '
    'cek '
    'iv '
    'ciphertext '
    'tag ')

JWS = namedtuple('JWS',
        'header '
        'payload '
        'signature ')

JWT = namedtuple('JWT',
        'header '
        'claims ')


def serialize_compact(jwt):
    """ Compact serialization of a :class:`~jose.JWE` or :class:`~jose.JWS`

    :rtype: str
    :returns: A string, representing the compact serialization of a
              :class:`~jose.JWE` or :class:`~jose.JWS`.
    """
    return '.'.join(jwt)


def deserialize_compact(jwt):
    """ Deserialization of a compact representation of a :class:`~jwt.JWE`

    :param jwt: The serialized JWT to deserialize.
    :rtype: :class:`~jose.JWT`.
    """
    parts = jwt.split('.')

    # http://tools.ietf.org/html/
    # draft-ietf-jose-json-web-encryption-23#section-9
    if len(parts) == 3:
        token_type = JWS
    elif len(parts) == 5:
        token_type = JWE
    else:
        raise ValueError('Malformed JWT')

    return token_type(*parts)


def encrypt(claims, jwk, adata='', add_header=None, alg='RSA-OAEP',
        enc='A128CBC-HS256', rng=get_random_bytes, compression=None):
    """ Encrypts the given claims and produces a :class:`~jose.JWE`

    :param claims: A `dict` representing the claims for this
                   :class:`~jose.JWE`.
    :param jwk: A `dict` representing the JWK to be used for encryption of
                the CEK. This parameter is algorithm-specific.
    :param adata: Arbitrary string data to add to the authentication
                  (i.e. HMAC). The same data must be provided during
                  decryption.
    :param add_header: Additional items to be added to the header. Additional
                       headers *will* be authenticated.
    :param alg: The algorithm to use for CEK encryption
    :param enc: The algorithm to use for claims encryption
    :param rng: Random number generator. A string of random bytes is expected
                as output.
    :param compression: The compression algorithm to use. Currently supports
                `'DEF'`.
    :rtype: :class:`~jose.JWE`
    """

    header = dict((add_header or {}).items() + [
        ('enc', enc), ('alg', alg)])

    plaintext = json_encode(claims)

    # compress (if required)
    if compression is not None:
        header['zip'] = compression
        try:
            (compress, _) = COMPRESSION[compression]
        except KeyError:
            raise ValueError(
                'Unsupported compression algorithm: {}'.format(compression))
        plaintext = compress(plaintext)

    # body encryption/hash
    ((cipher, _), key_size), ((hash_fn, _), hash_mod) = JWA[enc]
    iv = rng(AES.block_size)
    encryption_key = rng((key_size // 8) + hash_mod.digest_size)

    ciphertext = cipher(plaintext, encryption_key[:-hash_mod.digest_size], iv)
    hash = hash_fn(_jwe_hash_str(plaintext, iv, adata),
            encryption_key[-hash_mod.digest_size:], hash_mod)

    # cek encryption
    (cipher, _), _ = JWA[alg]
    encryption_key_ciphertext = cipher(encryption_key, jwk)

    return JWE(*map(b64encode_url,
            (json_encode(header),
            encryption_key_ciphertext,
            iv,
            ciphertext,
            auth_tag(hash))))


def decrypt(jwe, jwk, adata=''):
    """ Decrypts a deserialized :class:`~jose.JWE`

    :param jwe: An instance of :class:`~jose.JWE`
    :param jwk: A `dict` representing the JWK required to decrypt the content
                of the :class:`~jose.JWE`.
    :param adata: Arbitrary string data used during encryption for additional
                  authentication.
    :rtype: :class:`~jose.JWT`
    """
    header, encryption_key_ciphertext, iv, ciphertext, tag = map(
        b64decode_url, jwe)
    header = json_decode(header)

    # decrypt cek
    (_, decipher), _ = JWA[header['alg']]
    encryption_key = decipher(encryption_key_ciphertext, jwk)

    # decrypt body
    ((_, decipher), _), ((hash_fn, _), mod) = JWA[header['enc']]

    plaintext = decipher(ciphertext, encryption_key[:-mod.digest_size], iv)
    hash = hash_fn(_jwe_hash_str(plaintext, iv, adata),
            encryption_key[-mod.digest_size:], mod=mod)

    if not const_compare(auth_tag(hash), tag):
        raise ValueError('Mismatched authentication tags')

    if 'zip' in header:
        try:
            (_, decompress) = COMPRESSION[header['zip']]
        except KeyError:
            raise ValueError('Unsupported compression algorithm: {}'.format(
                header['zip']))

        plaintext = decompress(plaintext)

    claims = json_decode(plaintext)
    _validate(claims)

    return JWT(header, claims)


def sign(claims, jwk, add_header=None, alg='HS256'):
    """ Signs the given claims and produces a :class:`~jose.JWS`

    :param claims: A `dict` representing the claims for this
                   :class:`~jose.JWS`.
    :param jwk: A `dict` representing the JWK to be used for signing of the
                :class:`~jose.JWS`. This parameter is algorithm-specific.
    :parameter add_header: Additional items to be added to the header.
                           Additional headers *will* be authenticated.
    :parameter alg: The algorithm to use to produce the signature.
    """
    (hash_fn, _), mod = JWA[alg]

    header = dict((add_header or {}).items() + [('alg', alg)])
    header, payload = map(b64encode_url, map(json_encode, (header, claims)))

    sig = b64encode_url(hash_fn(_jws_hash_str(header, payload), jwk['k'],
        mod=mod))

    return JWS(header, payload, sig)


def verify(jws, jwk):
    """ Verifies the given :class:`~jose.JWS`

    :param jws: The :class:`~jose.JWS` to be verified.
    :param jwk: A `dict` representing the JWK to use for verification. This
                parameter is algorithm-specific.
    """
    header, payload, sig = map(b64decode_url, jws)
    header = json_decode(header)
    (_, verify_fn), mod = JWA[header['alg']]

    if not verify_fn(_jws_hash_str(jws.header, jws.payload),
            jwk['k'], sig, mod=mod):
        raise ValueError('Mismatched signatures')

    claims = json_decode(b64decode_url(jws.payload))
    _validate(claims)

    return JWT(header, claims)


def b64decode_url(istr):
    """ JWT Tokens may be truncated without the usual trailing padding '='
        symbols. Compensate by padding to the nearest 4 bytes.
    """
    istr = encode_safe(istr)
    return urlsafe_b64decode(istr + '=' * (4 - (len(istr) % 4)))


def b64encode_url(istr):
    """ JWT Tokens may be truncated without the usual trailing padding '='
        symbols. Compensate by padding to the nearest 4 bytes.
    """
    return urlsafe_b64encode(encode_safe(istr)).rstrip('=')


def encode_safe(istr, encoding='utf8'):
    try:
        return istr.encode(encoding)
    except UnicodeDecodeError:
        # this will fail if istr is already encoded
        pass
    return istr


def auth_tag(hmac):
    # http://tools.ietf.org/html/
    # draft-ietf-oauth-json-web-token-19#section-4.1.4
    return hmac[:len(hmac) // 2]


def pad_pkcs7(s):
    sz = AES.block_size - (len(s) % AES.block_size)
    return s + (chr(sz) * sz)


def unpad_pkcs7(s):
    return s[:-ord(s[-1])]


def encrypt_oaep(plaintext, jwk):
    return PKCS1_OAEP.new(RSA.importKey(jwk['k'])).encrypt(plaintext)


def decrypt_oaep(ciphertext, jwk):
    return PKCS1_OAEP.new(RSA.importKey(jwk['k'])).decrypt(ciphertext)


def hmac_sign(s, key, mod=SHA256):
    hmac = HMAC.new(key, digestmod=mod)
    hmac.update(s)
    return hmac.digest()


def hmac_verify(s, key, sig, mod=SHA256):
    hmac = HMAC.new(key, digestmod=mod)
    hmac.update(s)

    if not const_compare(hmac.digest(), sig):
        return False

    return True


def rsa_sign(s, key, mod=SHA256):
    key = RSA.importKey(key)
    hash = mod.new(s)
    return PKCS1_v1_5_SIG.new(key).sign(hash)


def rsa_verify(s, key, sig, mod=SHA256):
    key = RSA.importKey(key)
    hash = mod.new(s)
    return PKCS1_v1_5_SIG.new(key).verify(hash, sig)


def encrypt_aescbc(plaintext, key, iv):
    plaintext = pad_pkcs7(plaintext)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)


def decrypt_aescbc(ciphertext, key, iv):
    return unpad_pkcs7(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext))


def const_compare(stra, strb):
    if len(stra) != len(strb):
        return False

    res = 0
    for a, b in zip(stra, strb):
        res |= ord(a) ^ ord(b)
    return res == 0


class _JWA(object):
    """ Represents the implemented algorithms

    A big TODO list can be found here:
    http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-24
    """
    _impl = {
        'HS256': ((hmac_sign, hmac_verify), SHA256),
        'HS384': ((hmac_sign, hmac_verify), SHA384),
        'HS512': ((hmac_sign, hmac_verify), SHA512),
        'RS256': ((rsa_sign, rsa_verify), SHA256),
        'RS384': ((rsa_sign, rsa_verify), SHA384),
        'RS512': ((rsa_sign, rsa_verify), SHA512),
        'RSA-OAEP': ((encrypt_oaep, decrypt_oaep), 2048),

        'A128CBC': ((encrypt_aescbc, decrypt_aescbc), 128),
        'A192CBC': ((encrypt_aescbc, decrypt_aescbc), 192),
        'A256CBC': ((encrypt_aescbc, decrypt_aescbc), 256),
    }

    def __getitem__(self, key):
        """ Derive implementation(s) from key
        """
        if key in self._impl:
            return self._impl[key]

        enc, hash = self._compound_from_key(key)
        return self._impl[enc], self._impl[hash]

    def _compound_from_key(self, key):
        try:
            enc, hash = key.split('+')
            return enc, hash
        except ValueError:
            pass

        try:
            enc, hash = key.split('-')
            return enc, hash
        except ValueError:
            pass

        raise KeyError('Unsupported algorithm: {}'.format(key))


JWA = _JWA()


COMPRESSION = {
    'DEF': (zlib.compress, zlib.decompress),
}


def _validate(claims):
    now = time()

    # TODO: allow for clock skew?
    if claims.get('exp', now) < now:
        raise ValueError('Token has expired')
    elif claims.get('nbf', now) > now:
        raise ValueError('Token is not valid yet')


def _jwe_hash_str(plaintext, iv, adata=''):
    # http://tools.ietf.org/html/
    # draft-ietf-jose-json-web-algorithms-24#section-5.2.2.1
    return '.'.join((adata, iv, plaintext, str(len(adata))))


def _jws_hash_str(header, claims):
    return '.'.join((header, claims))
