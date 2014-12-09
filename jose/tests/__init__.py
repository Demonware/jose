import json
import unittest

from base64 import b64encode
from copy import copy
from itertools import product
from time import time

from Crypto.PublicKey import RSA

import jose

rsa_key = RSA.generate(2048)

rsa_priv_key = {
    'k': rsa_key.exportKey('PEM'),
}
rsa_pub_key = {
    'k': rsa_key.publickey().exportKey('PEM'),
}

claims = {'john': 'cleese'}


class TestSerializeDeserialize(unittest.TestCase):
    def test_serialize(self):
        try:
            jose.deserialize_compact('1.2.3.4')
            self.fail()
        except jose.Error as e:
            self.assertEqual(str(e), 'Malformed JWT')


class TestJWE(unittest.TestCase):
    encs = ('A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512')
    algs = (('RSA-OAEP', rsa_key),)

    def test_jwe(self):
        bad_key = {'k': RSA.generate(2048).exportKey('PEM')}

        for (alg, jwk), enc in product(self.algs, self.encs):
            jwe = jose.encrypt(claims, rsa_pub_key, enc=enc, alg=alg)

            # make sure the body can't be loaded as json (should be encrypted)
            try:
                json.loads(jose.b64decode_url(jwe.ciphertext).decode('utf-8'))
                self.fail()
            except ValueError:
                pass

            token = jose.serialize_compact(jwe)

            jwt = jose.decrypt(jose.deserialize_compact(token), rsa_priv_key)

            self.assertEqual(jwt.claims, claims)

            # invalid key
            try:
                jose.decrypt(jose.deserialize_compact(token), bad_key)
                self.fail()
            except jose.Error as e:
                self.assertEqual(str(e), 'Incorrect decryption.')

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
                self.assertEqual(str(e), 'Mismatched authentication tags')

            self.assertEqual(jwt.claims, claims)

    def test_jwe_invalid_base64(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        bad = '\x00' + et

        try:
            jose.decrypt(jose.deserialize_compact(bad), rsa_priv_key)
        except jose.Error as e:
            self.assertEquals(
                e.args[0],
                'Unable to decode base64: Incorrect padding'
            )
        else:
            self.fail()  # expecting error due to invalid base64

    def test_jwe_no_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) + 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_expired_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)
        except jose.Expired as e:
            self.assertEquals(
                e.args[0],
                'Token expired at {}'.format(
                    jose._format_timestamp(claims[jose.CLAIM_EXPIRATION_TIME])
                )
            )
        else:
            self.fail()  # expecting expired token

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
        except jose.Expired as e:
            expiration_time = claims[jose.CLAIM_ISSUED_AT] + expiry_seconds
            self.assertEquals(
                e.args[0],
                'Token expired at {}'.format(
                    jose._format_timestamp(expiration_time)
                )
            )
        else:
            self.fail()  # expecting expired token

    def test_jwe_no_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_not_yet_valid_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) + 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.decrypt(jose.deserialize_compact(et), rsa_priv_key)
        except jose.NotYetValid as e:
            self.assertEquals(
                e.args[0],
                'Token not valid until {}'.format(
                    jose._format_timestamp(claims[jose.CLAIM_NOT_BEFORE])
                )
            )
        else:
            self.fail()  # expecting not valid yet

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

        for v in range(1000):
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
        except jose.Error:
            pass
        else:
            self.fail()

    def test_decrypt_invalid_compression_error(self):
        jwe = jose.encrypt(claims, rsa_pub_key, compression='DEF')
        header = jose.b64encode_url(b'{"alg": "RSA-OAEP", '
            b'"enc": "A128CBC-HS256", "zip": "BAD"}')

        try:
            jose.decrypt(jose.JWE(*((header,) + (jwe[1:]))), rsa_priv_key)
        except jose.Error as e:
            self.assertEqual(str(e),
                    'Unsupported compression algorithm: BAD')
        else:
            self.fail()


class TestJWS(unittest.TestCase):

    def test_jws_sym(self):
        algs = ('HS256', 'HS384', 'HS512',)
        jwk = {'k': 'password'}

        for alg in algs:
            st = jose.serialize_compact(jose.sign(claims, jwk, alg=alg))
            jwt = jose.verify(jose.deserialize_compact(st), jwk)

            self.assertEqual(jwt.claims, claims)

    def test_jws_asym(self):
        algs = ('RS256', 'RS384', 'RS512')

        for alg in algs:
            st = jose.serialize_compact(jose.sign(claims, rsa_priv_key,
                alg=alg))
            jwt = jose.verify(jose.deserialize_compact(st), rsa_pub_key)
            self.assertEqual(jwt.claims, claims)

    def test_jws_signature_mismatch_error(self):
        jwk = {'k': 'password'}
        jws = jose.sign(claims, jwk)
        try:
            jose.verify(jose.JWS(jws.header, jws.payload, 'asd'), jwk)
        except jose.Error as e:
            self.assertEqual(str(e), 'Mismatched signatures')


class TestUtils(unittest.TestCase):
    def test_b64encode_url_utf8(self):
        istr = 'eric idle'.encode('utf8')
        encoded = jose.b64encode_url(istr)
        self.assertEqual(jose.b64decode_url(encoded), istr)

    def test_b64encode_url_ascii(self):
        istr = b'eric idle'
        encoded = jose.b64encode_url(istr)
        self.assertEqual(jose.b64decode_url(encoded), istr)

    def test_b64encode_url(self):
        istr = b'{"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}'

        # sanity check
        self.assertTrue(b64encode(istr).endswith(b'='))

        # actual test
        self.assertFalse(jose.b64encode_url(istr).endswith('='))


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
            self.assertTrue(str(e).startswith('Unsupported'))


loader = unittest.TestLoader()
suite = unittest.TestSuite((
    loader.loadTestsFromTestCase(TestSerializeDeserialize),
    loader.loadTestsFromTestCase(TestJWE),
    loader.loadTestsFromTestCase(TestJWS),
    loader.loadTestsFromTestCase(TestUtils),
    loader.loadTestsFromTestCase(TestJWA),
))
