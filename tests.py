import json
import unittest

from base64 import b64encode
from copy import copy, deepcopy
from itertools import product
from time import time

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import jose

rsa_key = RSA.generate(2048)

rsa_priv_key = {
    'k': rsa_key.exportKey('PEM'),
}
rsa_pub_key = {
    'k': rsa_key.publickey().exportKey('PEM'),
}

claims = {'john': 'cleese'}


def legacy_encrypt(claims, jwk, adata='', add_header=None, alg='RSA-OAEP',
        enc='A128CBC-HS256', rng=get_random_bytes, compression=None, version=None):
    # see https://github.com/Demonware/jose/pull/3/files

    header = dict((add_header or {}).items() + [
        ('enc', enc), ('alg', alg)])

    if version == 1:
        claims = deepcopy(claims)
        assert jose._TEMP_VER_KEY not in claims
        claims[jose._TEMP_VER_KEY] = version

        # promote the temp key to the header
        assert jose._TEMP_VER_KEY not in header
        header[jose._TEMP_VER_KEY] = version

    plaintext = jose.json_encode(claims)

    # compress (if required)
    if compression is not None:
        header['zip'] = compression
        try:
            (compress, _) = jose.COMPRESSION[compression]
        except KeyError:
            raise jose.Error(
                'Unsupported compression algorithm: {}'.format(compression))
        plaintext = compress(plaintext)

    # body encryption/hash
    ((cipher, _), key_size), ((hash_fn, _), hash_mod) = jose.JWA[enc]
    iv = rng(AES.block_size)
    if version == 1:
        encryption_key = rng(hash_mod.digest_size)
        cipher_key = encryption_key[-hash_mod.digest_size/2:]
        mac_key = encryption_key[:-hash_mod.digest_size/2]
    else:
        encryption_key = rng((key_size // 8) + hash_mod.digest_size)
        cipher_key = encryption_key[:-hash_mod.digest_size]
        mac_key = encryption_key[-hash_mod.digest_size:]

    ciphertext = cipher(plaintext, cipher_key, iv)
    hash = hash_fn(jose._jwe_hash_str(ciphertext, iv, adata, version), mac_key, hash_mod)

    # cek encryption
    (cipher, _), _ = jose.JWA[alg]
    encryption_key_ciphertext = cipher(encryption_key, jwk)

    return jose.JWE(*map(jose.b64encode_url,
            (jose.json_encode(header),
            encryption_key_ciphertext,
            iv,
            ciphertext,
            jose.auth_tag(hash))))


class TestLegacyDecrypt(unittest.TestCase):
    def test_jwe(self):
        bad_key = {'k': RSA.generate(2048).exportKey('PEM')}

        jwe = legacy_encrypt(claims, rsa_pub_key)
        token = jose.serialize_compact(jwe)

        jwt = jose.decrypt(jose.deserialize_compact(token), rsa_priv_key)

        self.assertEqual(jwt.claims, claims)
        self.assertNotIn(jose._TEMP_VER_KEY, claims)

        # invalid key
        try:
            jose.decrypt(jose.deserialize_compact(token), bad_key)
            self.fail()
        except jose.Error as e:
            self.assertEqual(e.message, 'Incorrect decryption.')

    def test_version1(self):
        bad_key = {'k': RSA.generate(2048).exportKey('PEM')}

        jwe = legacy_encrypt(claims, rsa_pub_key, version=1)
        token = jose.serialize_compact(jwe)

        jwt = jose.decrypt(jose.deserialize_compact(token), rsa_priv_key)

        self.assertEqual(jwt.claims, claims)
        self.assertEqual(jwt.header.get(jose._TEMP_VER_KEY), 1)


class TestSerializeDeserialize(unittest.TestCase):
    def test_serialize(self):
        try:
            jose.deserialize_compact('1.2.3.4')
            self.fail()
        except jose.Error as e:
            self.assertEqual(e.message, 'Malformed JWT')


class TestJWE(unittest.TestCase):
    encs = ('A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512')
    algs = (('RSA-OAEP', rsa_key),)

    def test_jwe(self):
        bad_key = {'k': RSA.generate(2048).exportKey('PEM')}

        for (alg, jwk), enc in product(self.algs, self.encs):
            jwe = jose.encrypt(claims, rsa_pub_key, enc=enc, alg=alg)

            # make sure the body can't be loaded as json (should be encrypted)
            try:
                json.loads(jose.b64decode_url(jwe.ciphertext))
                self.fail()
            except ValueError:
                pass

            token = jose.serialize_compact(jwe)

            jwt = jose.decrypt(jose.deserialize_compact(token), rsa_priv_key)
            self.assertNotIn(jose._TEMP_VER_KEY, claims)

            self.assertEqual(jwt.claims, claims)

            # invalid key
            try:
                jose.decrypt(jose.deserialize_compact(token), bad_key)
                self.fail()
            except jose.Error as e:
                self.assertEqual(e.message, 'Incorrect decryption.')

    def test_jwe_add_header(self):
        add_header = {'foo': 'bar'}

        for (alg, jwk), enc in product(self.algs, self.encs):
            et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key,
                add_header=add_header))
            jwt = jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)

            self.assertEqual(jwt.header['foo'], add_header['foo'])

    def test_jwe_adata(self):
        adata = '42'
        for (alg, jwk), enc in product(self.algs, self.encs):
            et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key,
                adata=adata))
            jwt = jose.decrypt(jose.deserialize_compact(et), rsa_priv_key,
                    adata=adata)

            # make sure signaures don't match when adata isn't passed in
            try:
                hdr, dt = jose.decrypt(jose.deserialize_compact(et),
                    rsa_priv_key)
                self.fail()
            except jose.Error as e:
                self.assertEqual(e.message, 'Mismatched authentication tags')

            self.assertEqual(jwt.claims, claims)

    def test_jwe_invalid_base64(self):
        try:
            jose.decrypt('aaa', rsa_priv_key)
            self.fail()  # expecting error due to invalid base64
        except jose.Error as e:
            pass

        self.assertEquals(
            e.args[0],
            'Unable to decode base64: Incorrect padding'
        )

    def test_jwe_no_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) + 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_expired_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)
            self.fail()  # expecting expired token
        except jose.Expired as e:
            pass

        self.assertEquals(
            e.args[0],
            'Token expired at {}'.format(
                jose._format_timestamp(claims[jose.CLAIM_EXPIRATION_TIME])
            )
        )

    def test_jwe_no_error_with_iat_claim(self):
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key,
            expiry_seconds=20)

    def test_jwe_expired_error_with_iat_claim(self):
        expiry_seconds = 10
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.decrypt(jose.deserialize_compact(et), rsa_priv_key,
                expiry_seconds=expiry_seconds)
            self.fail()  # expecting expired token
        except jose.Expired as e:
            pass

        expiration_time = claims[jose.CLAIM_ISSUED_AT] + expiry_seconds
        self.assertEquals(
            e.args[0],
            'Token expired at {}'.format(
                jose._format_timestamp(expiration_time)
            )
        )

    def test_jwe_no_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_not_yet_valid_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) + 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)
            self.fail()  # expecting not valid yet
        except jose.NotYetValid as e:
            pass

        self.assertEquals(
            e.args[0],
            'Token not valid until {}'.format(
                jose._format_timestamp(claims[jose.CLAIM_NOT_BEFORE])
            )
        )

    def test_jwe_ignores_expired_token_if_validate_claims_is_false(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key,
            validate_claims=False)

    def test_format_timestamp(self):
        self.assertEquals(
            jose._format_timestamp(1403054056),
            '2014-06-18T01:14:16Z'
        )

    def test_jwe_compression(self):
        local_claims = copy(claims)

        for v in xrange(1000):
            local_claims['dummy_' + str(v)] = '0' * 100

        jwe = jose.serialize_compact(jose.encrypt(local_claims, rsa_pub_key))
        _, _, _, uncompressed_ciphertext, _ = jwe.split('.')

        jwe = jose.serialize_compact(jose.encrypt(local_claims, rsa_pub_key,
            compression='DEF'))
        _, _, _, compressed_ciphertext, _ = jwe.split('.')

        self.assertTrue(len(compressed_ciphertext) <
                len(uncompressed_ciphertext))

        jwt = jose.decrypt(jose.deserialize_compact(jwe), rsa_priv_key)
        self.assertEqual(jwt.claims, local_claims)

    def test_encrypt_invalid_compression_error(self):
        try:
            jose.encrypt(claims, rsa_pub_key, compression='BAD')
            self.fail()
        except jose.Error:
            pass

    def test_decrypt_invalid_compression_error(self):
        jwe = jose.encrypt(claims, rsa_pub_key, compression='DEF')
        header = jose.b64encode_url(
            jose.json_encode(
                {"alg": "RSA-OAEP", "enc": "A128CBC-HS256",
                 jose._TEMP_VER_KEY: jose._TEMP_VER, "zip": "BAD"}
            )
        )

        try:
            jose.decrypt(jose.JWE(*((header,) + (jwe[1:]))), rsa_priv_key)
            self.fail()
        except jose.Error as e:
            self.assertEqual(
                e.message, 'Unsupported compression algorithm: BAD')


class TestJWS(unittest.TestCase):

    def test_jws_sym(self):
        algs = ('HS256', 'HS384', 'HS512',)
        jwk = {'k': 'password'}

        for alg in algs:
            st = jose.serialize_compact(jose.sign(claims, jwk, alg=alg))
            jwt = jose.verify(jose.deserialize_compact(st), jwk, alg)

            self.assertEqual(jwt.claims, claims)

    def test_jws_asym(self):
        algs = ('RS256', 'RS384', 'RS512')

        for alg in algs:
            st = jose.serialize_compact(jose.sign(claims, rsa_priv_key,
                alg=alg))
            jwt = jose.verify(jose.deserialize_compact(st), rsa_pub_key, alg)
            self.assertEqual(jwt.claims, claims)

    def test_jws_signature_mismatch_error(self):
        alg = 'HS256'
        jwk = {'k': 'password'}
        jws = jose.sign(claims, jwk, alg=alg)
        try:
            jose.verify(jose.JWS(jws.header, jws.payload, 'asd'), jwk, alg)
        except jose.Error as e:
            self.assertEqual(e.message, 'Mismatched signatures')

    def test_jws_invalid_algorithm_error(self):
        sign_alg = 'HS256'
        verify_alg = 'RS256'
        jwk = {'k': 'password'}
        jws = jose.sign(claims, jwk, alg=sign_alg)
        try:
            jose.verify(jose.JWS(jws.header, jws.payload, 'asd'), jwk,
                        verify_alg)
        except jose.Error as e:
            self.assertEqual(e.message, 'Invalid algorithm')


class TestUtils(unittest.TestCase):
    def test_b64encode_url_utf8(self):
        istr = 'eric idle'.encode('utf8')
        encoded = jose.b64encode_url(istr)
        self.assertEqual(jose.b64decode_url(encoded), istr)

    def test_b64encode_url_ascii(self):
        istr = 'eric idle'
        encoded = jose.b64encode_url(istr)
        self.assertEqual(jose.b64decode_url(encoded), istr)

    def test_b64encode_url(self):
        istr = '{"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}'

        # sanity check
        self.assertEqual(b64encode(istr)[-1], '=')

        # actual test
        self.assertNotEqual(jose.b64encode_url(istr), '=')


class TestJWA(unittest.TestCase):
    def test_lookup(self):
        impl = jose._JWA._impl
        jose._JWA._impl = dict((k, k) for k in (
            'HS256', 'RSA-OAEP', 'A128CBC', 'A128CBC'))

        self.assertEqual(jose.JWA['HS256'], 'HS256')
        self.assertEqual(jose.JWA['RSA-OAEP'], 'RSA-OAEP')
        self.assertEqual(jose.JWA['A128CBC-HS256'],
                ('A128CBC', 'HS256'))
        self.assertEqual(jose.JWA['A128CBC+HS256'],
                ('A128CBC', 'HS256'))

        jose._JWA._impl = impl

    def test_invalid_error(self):
        try:
            jose.JWA['bad']
            self.fail()
        except jose.Error as e:
            self.assertTrue(e.message.startswith('Unsupported'))


if __name__ == '__main__':
    unittest.main()
