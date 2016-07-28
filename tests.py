import json
import mock
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

            jwt = jose.legacy_decrypt(jose.deserialize_compact(token), rsa_priv_key)
            self.assertNotIn(jose._TEMP_VER_KEY, claims)

            self.assertEqual(jwt.claims, claims)

            # invalid key
            try:
                jose.legacy_decrypt(jose.deserialize_compact(token), bad_key)
                self.fail()
            except jose.Error as e:
                self.assertEqual(e.message, 'Incorrect decryption.')

    def test_jwe_add_header(self):
        add_header = {'foo': 'bar'}

        for (alg, jwk), enc in product(self.algs, self.encs):
            et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key,
                add_header=add_header))
            jwt = jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key)

            self.assertEqual(jwt.header['foo'], add_header['foo'])

    def test_jwe_adata(self):
        adata = '42'
        for (alg, jwk), enc in product(self.algs, self.encs):
            et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key,
                adata=adata))
            jwt = jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key,
                    adata=adata)

            # make sure signaures don't match when adata isn't passed in
            try:
                hdr, dt = jose.legacy_decrypt(jose.deserialize_compact(et),
                    rsa_priv_key)
                self.fail()
            except jose.Error as e:
                self.assertEqual(e.message, 'Mismatched authentication tags')

            self.assertEqual(jwt.claims, claims)

    def test_jwe_invalid_base64(self):
        try:
            jose.legacy_decrypt('aaa', rsa_priv_key)
            self.fail()  # expecting error due to invalid base64
        except jose.Error as e:
            pass

        self.assertEqual(
            e.args[0],
            'Unable to decode base64: Incorrect padding'
        )

    def test_jwe_no_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) + 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_expired_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key)
            self.fail()  # expecting expired token
        except jose.Expired as e:
            pass

        self.assertEqual(
            e.args[0],
            'Token expired at {}'.format(
                jose._format_timestamp(claims[jose.CLAIM_EXPIRATION_TIME])
            )
        )

    def test_jwe_no_error_with_iat_claim(self):
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key,
            expiry_seconds=20)

    def test_jwe_expired_error_with_iat_claim(self):
        expiry_seconds = 10
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key,
                expiry_seconds=expiry_seconds)
            self.fail()  # expecting expired token
        except jose.Expired as e:
            pass

        expiration_time = claims[jose.CLAIM_ISSUED_AT] + expiry_seconds
        self.assertEqual(
            e.args[0],
            'Token expired at {}'.format(
                jose._format_timestamp(expiration_time)
            )
        )

    def test_jwe_no_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_not_yet_valid_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) + 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))

        try:
            jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key)
            self.fail()  # expecting not valid yet
        except jose.NotYetValid as e:
            pass

        self.assertEqual(
            e.args[0],
            'Token not valid until {}'.format(
                jose._format_timestamp(claims[jose.CLAIM_NOT_BEFORE])
            )
        )

    def test_jwe_ignores_expired_token_if_validate_claims_is_false(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.encrypt(claims, rsa_pub_key))
        jose.legacy_decrypt(jose.deserialize_compact(et), rsa_priv_key,
            validate_claims=False)

    def test_format_timestamp(self):
        self.assertEqual(
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

        jwt = jose.legacy_decrypt(jose.deserialize_compact(jwe), rsa_priv_key)
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
            jose.legacy_decrypt(jose.JWE(*((header,) + (jwe[1:]))),
                                rsa_priv_key)
            self.fail()
        except jose.Error as e:
            self.assertEqual(
                e.message, 'Unsupported compression algorithm: BAD')


class TestSpecCompliantJWE(unittest.TestCase):
    encs = ('A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512')
    algs = (('RSA-OAEP', rsa_key),)

    def test_jwe(self):
        bad_key = {'k': RSA.generate(2048).exportKey('PEM')}

        for (alg, jwk), enc in product(self.algs, self.encs):
            jwe = jose.spec_compliant_encrypt(claims, rsa_pub_key, enc=enc, alg=alg)

            # make sure the body can't be loaded as json (should be encrypted)
            try:
                json.loads(jose.b64decode_url(jwe.ciphertext))
                self.fail()
            except ValueError:
                pass

            token = jose.serialize_compact(jwe)

            jwt = jose.spec_compliant_decrypt(jose.deserialize_compact(token), rsa_priv_key)
            self.assertNotIn(jose._TEMP_VER_KEY, claims)

            self.assertEqual(jwt.claims, claims)

            # invalid key
            try:
                jose.spec_compliant_decrypt(jose.deserialize_compact(token), bad_key)
                self.fail()
            except jose.Error as e:
                self.assertEqual(e.message, 'Incorrect decryption.')

    def test_jwe_add_header(self):
        add_header = {'foo': 'bar'}

        for (alg, jwk), enc in product(self.algs, self.encs):
            et = jose.serialize_compact(jose.spec_compliant_encrypt(claims, rsa_pub_key,
                add_header=add_header))
            jwt = jose.spec_compliant_decrypt(jose.deserialize_compact(et), rsa_priv_key)

            self.assertEqual(jwt.header['foo'], add_header['foo'])

    def test_jwe_invalid_base64(self):
        try:
            jose.spec_compliant_decrypt('aaa', rsa_priv_key)
            self.fail()  # expecting error due to invalid base64
        except jose.Error as e:
            pass

        self.assertEqual(
            e.args[0],
            'Unable to decode base64: Incorrect padding'
        )

    def test_jwe_no_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) + 5}
        et = jose.serialize_compact(jose.spec_compliant_encrypt(claims, rsa_pub_key))
        jose.spec_compliant_decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_expired_error_with_exp_claim(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.spec_compliant_encrypt(claims, rsa_pub_key))

        try:
            jose.spec_compliant_decrypt(jose.deserialize_compact(et), rsa_priv_key)
            self.fail()  # expecting expired token
        except jose.Expired as e:
            pass

        self.assertEqual(
            e.args[0],
            'Token expired at {}'.format(
                jose._format_timestamp(claims[jose.CLAIM_EXPIRATION_TIME])
            )
        )

    def test_jwe_no_error_with_iat_claim(self):
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}
        et = jose.serialize_compact(jose.spec_compliant_encrypt(claims, rsa_pub_key))

        jose.spec_compliant_decrypt(jose.deserialize_compact(et), rsa_priv_key,
            expiry_seconds=20)

    def test_jwe_expired_error_with_iat_claim(self):
        expiry_seconds = 10
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}
        et = jose.serialize_compact(jose.spec_compliant_encrypt(claims, rsa_pub_key))

        try:
            jose.spec_compliant_decrypt(jose.deserialize_compact(et), rsa_priv_key,
                expiry_seconds=expiry_seconds)
            self.fail()  # expecting expired token
        except jose.Expired as e:
            pass

        expiration_time = claims[jose.CLAIM_ISSUED_AT] + expiry_seconds
        self.assertEqual(
            e.args[0],
            'Token expired at {}'.format(
                jose._format_timestamp(expiration_time)
            )
        )

    def test_jwe_no_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) - 5}
        et = jose.serialize_compact(jose.spec_compliant_encrypt(claims, rsa_pub_key))
        jose.spec_compliant_decrypt(jose.deserialize_compact(et), rsa_priv_key)

    def test_jwe_not_yet_valid_error_with_nbf_claim(self):
        claims = {jose.CLAIM_NOT_BEFORE: int(time()) + 5}
        et = jose.serialize_compact(jose.spec_compliant_encrypt(claims, rsa_pub_key))

        try:
            jose.spec_compliant_decrypt(jose.deserialize_compact(et), rsa_priv_key)
            self.fail()  # expecting not valid yet
        except jose.NotYetValid as e:
            pass

        self.assertEqual(
            e.args[0],
            'Token not valid until {}'.format(
                jose._format_timestamp(claims[jose.CLAIM_NOT_BEFORE])
            )
        )

    def test_jwe_ignores_expired_token_if_validate_claims_is_false(self):
        claims = {jose.CLAIM_EXPIRATION_TIME: int(time()) - 5}
        et = jose.serialize_compact(jose.spec_compliant_encrypt(claims, rsa_pub_key))
        jose.spec_compliant_decrypt(jose.deserialize_compact(et), rsa_priv_key,
            validate_claims=False)

    def test_format_timestamp(self):
        self.assertEqual(
            jose._format_timestamp(1403054056),
            '2014-06-18T01:14:16Z'
        )

    def test_jwe_compression(self):
        local_claims = copy(claims)

        for v in xrange(1000):
            local_claims['dummy_' + str(v)] = '0' * 100

        jwe = jose.serialize_compact(
            jose.spec_compliant_encrypt(local_claims, rsa_pub_key)
        )
        _, _, _, uncompressed_ciphertext, _ = jwe.split('.')

        jwe = jose.serialize_compact(
            jose.spec_compliant_encrypt(local_claims, rsa_pub_key,
                                        add_header={'zip': 'DEF'})
        )
        _, _, _, compressed_ciphertext, _ = jwe.split('.')

        self.assertTrue(len(compressed_ciphertext) <
                len(uncompressed_ciphertext))

        jwt = jose.spec_compliant_decrypt(jose.deserialize_compact(jwe),
                                          rsa_priv_key)
        self.assertEqual(jwt.claims, local_claims)

    def test_encrypt_invalid_compression_error(self):
        try:
            jose.spec_compliant_encrypt(claims, rsa_pub_key,
                                        add_header={'zip':'BAD'})
            self.fail()
        except jose.Error:
            pass

    def test_decrypt_invalid_compression_error(self):
        with mock.patch.dict(jose.COMPRESSION,
                             {'BAD': jose.COMPRESSION['DEF']}):
            jwe = jose.spec_compliant_encrypt(claims, rsa_pub_key,
                                              add_header={'zip': 'BAD'})

        try:
            jose.spec_compliant_decrypt(jwe, rsa_priv_key)
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


PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEApqgUUxKXW4gVCHffi+u2nWqlYK6WBCPCNyhJzsauFbsilw0G
dU6BKUMIzrsKvm8wUxJVVSVH42dCZhLiT3yC85Eb6rrrYpdXzMkim9oPR1pG1lyg
3pJGcg4eFxd8S7xGeBELcANTmvLT0D1ka9Rs4iWImQDyQieXdglQWesIOYNSymaz
SzWrj3LZ5ihns6uFzx4ykisRVfK7TgOGGBl/53b0J8DxvjbHDFKNt4DgTF8eKP59
O4rKsEAv5LlsbN/MirvF6D1ZoKOXDCAvmC7MMXw8nYE9qwfgCXSH9VKnUtnVmDXL
za0loS4RIpkz1cVbHKOJlp7HH66rg5yOZek/mQIDAQABAoIBAAEQHWESQ0jgK1Is
gY6A6F9EqN1e/7HzEHANn7rj5YRZ9zSDbsEcyRIcTVgUNVNVnjdJbKXoYPcAV5oT
EMJ1BtjK2iS7IHk2gebaeZAI6gQIfV8spBIHWM+ta1+2VKKfBswJP8ttGgFo/xTa
72MIrdEbcC2ZpfHqErs7//ky2JCVVTLv4GuSr5U4dYCG/swkC92lOtf7aowlMwL7
/kFPOIpJ84SjRvcB08kIyRSf6Kcw1Tw4TUTaL345d2btlpcZN1U+h67PY9+oeQzg
WeypOCYtOm2tu3yxbvsysPLlkt3Mo4FzJkxZyXXPqggCby0aH/KI8Cv8LXdX6eeR
RwZ1DekCgYEAveO0Fb4wkHxbikzLyPoxNuoKK3z+8S+s27aa14AFtFyaic7qR6Nv
Rv6rhhYK5YBBkyW30aQbV/ZRCPlkD5TLA71eBdCUPn1Yh9gUAfNjZ/cJTPr8p8V/
jNC5bUkOHen+riflg1yeIJm+F643n3mbDK3Ruhkc4L+rHlD0JWPgMbcCgYEA4K2x
yMI8vgp9wiI+aVvevow3P+jq4fL7rAi1FyLPSzrxW0mnIzGRHsKVz6XBI8UUtT0h
AxN7fEY1Mu0tPJObQciM8/EIOlfANsxMm0NUFPsi8sEKm8KsC8qxNxj2ShmKvNHn
GPoxbp1ouLxdLcEIl4WMyMzpIDzfRAXWl7dE2S8CgYEAsC3E1uuH2XZX5EAOTuC6
qq2IVAL78sB+C7gnf8v6/vVwOG3u9hqP0vnUIGrxHy/ZJ3I2U16ENB+H3eCtUruF
hGm9A34bHMNlUVxMa+bqkvoj+fVgVzSpe/foIppGa8C/l8vSaQeUesDKGuR8HQ1R
qvjWfmhwX6HVXSJU8x/wUY8CgYEA3n6jxG+1v2ycRResPqHf30rzm7KIh+EcIa0t
yA+MwK9KPGCfx1Zao9+Gg+9daJLOgvxaKLWuX88W96uwVIDIC0kTbK+QulYT3zBJ
3Ke8KFrarRNF8iHCRpsfC7UIkTDiF0K2XCHHugbfobHHhHvYilSSqndhla8yWiZ9
8BhpcbkCgYAXEZ1ErSZv9m3na2/PAhk/u7sHEi/O5wyvuGe1Q1SW8ESdYhI3vlap
o87ipFLz5YPW5Cbqz7pBvowbx91vI7imrilvSEBwl8BY/u5Q4EWiL4QlAe+xCYhJ
B60eK9sJADyJFXjFUIryuAsrxPFvDHs3iU709Cs+EH9nxWLBqpRl5Q==
-----END RSA PRIVATE KEY-----"""

SPEC_COMPLIANT_TOKEN = (
    "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkExMjhDQkMtSFMyNTYifQ."
    "Ha3w8AO7Jq25p3KqLhXaV1N1vbwSNQ5hjeh0nxWRJTHW-E7c3paxN38eNSJ"
    "4vXWO2vhNgkAS81I35GZXy0JTAA2oswx8yzaF_UHTQ7ajTBgmvwBxgpW-Pf"
    "8YL2IhGycNDrtx-ZqYwl9WDEQlZnm0_eX3bg31LGqtnz-MFWCOa7-tPZ93Z"
    "i4IhdKLygjrjQssUUQGJxFVkWLhVuI9sNcxdjDCR1jN2CopHCsnuSlGjKxd"
    "YLeCC50IyVlWPY3Zf3TBmtvfrLEqipQsETbxZ-ihOVSToALZ7q8QZfHPM4R"
    "d7_vBGt6dY3BIqqRl88p56j1MQ-ekTZvduiuMZYNZcmdmPg.4doDewLiO-q"
    "nOqAweE-Zlw.3mWP86WP6P4cCALdV8yU1LwIPKQO9MUGQSUDl6jbYSY.Kb8"
    "OqWxyLhr4R0-Kzz4nMQ"
)

# This key is generated by jose 1.0.0 (from master)
LEGACY_V1_TOKEN = (
    "eyJhbGciOiAiUlNBLU9BRVAiLCAiZW5jIjogIkExMjhDQkMtSFMyNTYiLCA"
    "iX192IjogMX0.FN3aVDp2EGD34zyD3HmEyeBld9eUKToiBknlegJ06ViFuS"
    "Tt_aZ0VTh72ySm0Q5l9u-7xlw3amZiSUm9ZOyaT05bu4CVjPJunqepvXkAF"
    "aIEcSvKjifaweEd6HBdvOgvgBEbzt4LOysunt2N_sbaDOkzSZEUbgp8_Rh7"
    "7-r5A3x3VCSBcA-ThluWG6XuaUVY2NrjJQ4bc-wF0qfEaEt1C_zV2hxJeZ_"
    "3nIzGNy3M-bHnMaBIvZqP-jmRPTnvgTibDntymMmE7-c71Q1e0-HK0YpAfK"
    "4RzdKfvjyKoVmpPk4Ris3W2Lr9jdToTYwocKyF0mV2uxE19cNAWoQqyS_Pc"
    "g.QHgwlB0dCHXx1c-dnn7c0g.F04cKdz-M1_VSb25_kPwiAGBbVGE-Mh4OE"
    "vrOsilQGc.vsO_UAlFRGIWlkFis5Xnng"
)


class TestDecryptCompatibility(unittest.TestCase):
    def test_jwe_decrypt_compliant(self):
        jwk = {'k': PRIVATE_KEY}
        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            jwt = jose.decrypt(
                jose.deserialize_compact(SPEC_COMPLIANT_TOKEN), jwk
            )

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 1)
        self.assertEqual(jwt.claims, claims)
        expected_header = {
            'alg': 'RSA-OAEP',
            'enc': 'A128CBC-HS256'
        }
        self.assertEqual(jwt.header, expected_header)

    def test_jwe_decrypt_compliant_incorrect_jwk(self):
        jwk_for_decrypt = {'k': RSA.generate(2048).exportKey('PEM')}

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.Error) as decryption_error:
                jose.decrypt(
                    jose.deserialize_compact(SPEC_COMPLIANT_TOKEN),
                    jwk_for_decrypt)

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 1)
        self.assertEqual(decryption_error.exception.message,
                          "Incorrect decryption.")

    def test_jwe_decrypt_compliant_expiry(self):
        expiry_seconds = 10
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}

        jwe = jose.spec_compliant_encrypt(claims, rsa_pub_key)

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.Expired) as expiry_error:
                jose.decrypt(jwe, rsa_priv_key, expiry_seconds=expiry_seconds)

        expiration_time = claims[jose.CLAIM_ISSUED_AT] + expiry_seconds

        # when the error is expiry, we should not fall back to legacy.
        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 1)
        self.assertEqual(
            expiry_error.exception.message,
            'Token expired at {}'.format(
                jose._format_timestamp(expiration_time)
            )
        )

    def test_jwe_decrypt_compliant_not_before(self):
        # not valid for another hour.
        claim_not_before = int(time()) + 3600
        claims = {jose.CLAIM_NOT_BEFORE: claim_not_before}

        jwe = jose.spec_compliant_encrypt(claims, rsa_pub_key)

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.NotYetValid) as not_valid_error:
                jose.decrypt(jwe, rsa_priv_key)

        # when the error is expiry, we should not fall back to legacy.
        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 1)
        self.assertEqual(
            not_valid_error.exception.message,
            'Token not valid until {}'.format(
                jose._format_timestamp(claim_not_before)
            )
        )

    def test_jwe_decrypt_legacy_v1(self):
        jwk = {'k': PRIVATE_KEY}
        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            jwt = jose.decrypt(jose.deserialize_compact(LEGACY_V1_TOKEN), jwk)

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 0)
        self.assertEqual(jwt.claims, claims)
        expected_header = {
            'alg': 'RSA-OAEP',
            'enc': 'A128CBC-HS256',
            '__v': 1
        }
        self.assertEqual(jwt.header, expected_header)

    def test_jwe_decrypt_legacy_v1_expiry(self):
        expiry_seconds = 10
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}

        jwe = jose.encrypt(claims, rsa_pub_key)

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.Expired) as expiry_error:
                jose.decrypt(jwe, rsa_priv_key, expiry_seconds=expiry_seconds)

        expiration_time = claims[jose.CLAIM_ISSUED_AT] + expiry_seconds

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 0)

        self.assertEqual(
            expiry_error.exception.message,
            'Token expired at {}'.format(
                jose._format_timestamp(expiration_time)
            )
        )

    def test_jwe_decrypt_legacy_v1_not_yet_valid(self):
        # not valid for another hour.
        claim_not_before = int(time()) + 3600
        claims = {jose.CLAIM_NOT_BEFORE: claim_not_before}

        jwe = jose.encrypt(claims, rsa_pub_key)

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.NotYetValid) as not_valid_error:
                jose.decrypt(jwe, rsa_priv_key)

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 0)

        self.assertEqual(
            not_valid_error.exception.message,
            'Token not valid until {}'.format(
                jose._format_timestamp(claim_not_before)
            )
        )

    def test_jwe_decrypt_legacy_v1_incorrect_jwk(self):
        jwk_for_decrypt = {'k': RSA.generate(2048).exportKey('PEM')}

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.Error) as decryption_error:
                jose.decrypt(
                    jose.deserialize_compact(LEGACY_V1_TOKEN),
                    jwk_for_decrypt)

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 1)

        self.assertEqual(decryption_error.exception.message,
                          "Incorrect decryption.")

    def test_jwe_decrypt_legacy_v1_without_temp_ver(self):
        jwk = {'k': PRIVATE_KEY}

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )

        legacy_legacy_temp_ver = jose.serialize_compact(
            legacy_encrypt(claims, jwk)
        )

        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            jwt = jose.decrypt(
                jose.deserialize_compact(legacy_legacy_temp_ver), jwk)

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 0)
        self.assertEqual(jwt.claims, claims)
        expected_header = {
            'alg': 'RSA-OAEP',
            'enc': 'A128CBC-HS256',
        }
        self.assertEqual(jwt.header, expected_header)
        self.assertNotIn('__v', jwt.header)

    def test_jwe_decrypt_legacy_v1_without_temp_ver_incorrect_jwk(self):
        jwk_for_encrypt = {'k': PRIVATE_KEY}

        legacy_legacy_temp_ver = jose.serialize_compact(
            legacy_encrypt(claims, jwk_for_encrypt)
        )

        jwk_for_decrypt = {'k': RSA.generate(2048).exportKey('PEM')}

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.Error) as decryption_error:
                jose.decrypt(
                    jose.deserialize_compact(legacy_legacy_temp_ver),
                    jwk_for_decrypt)

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 1)

        self.assertEqual(decryption_error.exception.message,
                          "Incorrect decryption.")

    def test_jwe_decrypt_legacy_v1_without_temp_var_expiry(self):
        expiry_seconds = 10
        claims = {jose.CLAIM_ISSUED_AT: int(time()) - 15}

        jwe = legacy_encrypt(claims, rsa_pub_key)

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.Expired) as expiry_error:
                jose.decrypt(jwe, rsa_priv_key, expiry_seconds=expiry_seconds)

        expiration_time = claims[jose.CLAIM_ISSUED_AT] + expiry_seconds

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 0)

        self.assertEqual(
            expiry_error.exception.message,
            'Token expired at {}'.format(
                jose._format_timestamp(expiration_time)
            )
        )

    def test_jwe_decrypt_legacy_v1_without_temp_ver_not_yet_valid(self):
        # not valid for another hour.
        claim_not_before = int(time()) + 3600
        claims = {jose.CLAIM_NOT_BEFORE: claim_not_before}

        jwe = legacy_encrypt(claims, rsa_pub_key)

        legacy_patch = mock.patch.object(
            jose, 'legacy_decrypt', wraps=jose.legacy_decrypt
        )
        spec_patch = mock.patch.object(
            jose, 'spec_compliant_decrypt', wraps=jose.spec_compliant_decrypt
        )
        with legacy_patch as legacy_mock, spec_patch as spec_mock:
            with self.assertRaises(jose.NotYetValid) as not_valid_error:
                jose.decrypt(jwe, rsa_priv_key)

        self.assertEqual(legacy_mock.call_count, 1)
        self.assertEqual(spec_mock.call_count, 0)

        self.assertEqual(
            not_valid_error.exception.message,
            'Token not valid until {}'.format(
                jose._format_timestamp(claim_not_before)
            )
        )


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
