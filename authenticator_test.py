"""Unit test for the AncientAuth authenticator class."""

from ancientsolutions.crypttools import x509
from datetime import datetime, timedelta
from Crypto.PublicKey.RSA import importKey

import authenticator
import calendar
import token_cookie
import token_pb2
import unittest


_TEST_KEY = """-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMgTwGPXIBLojKVq
sJRUecNhOfPPuKEwM/z6h2qnAvxZpTystm4JO/NWJbJ8DBPXlAMkk49FJqk8D7xb
liY6uwMgZtLPg8vtMAxpLt9oKddYHC/xpYFeE0nsM1CO1IeA+/2c7KvVwp5wmtpK
nOCDJWxjJXLy4XbjjF9LQWv1kBRjAgMBAAECgYBG9hpqTsZlbm1Tzf9K3JtDHJy9
SJMnOD14IDMfNJTug60DVA5wAH5u08MTBsQR1Yf9hV+AlPodU9wQ5jre3D2vQabn
SP35fV2xaJzZdoXjel/fWMKSJGEsFg4E99eGEevygjxXZWKs1cqWrMKnt/0vQURX
krwR1gnULdmEBwwqoQJBAOSCfqN9W35Vhn3DJYIENFTn2pTFx//5USRlP0dD3djG
WbeHXQMxR2+/KfM5im+xcEDpsYIY8mW8vto9fMNy/hcCQQDgJZtot9zm9HDKy7Kj
DzDopZQLko2Lh3EZ/LtaXvLFe8UiEj9XJgsBIPsyaWkUD1Q3KeeDgqQZajBqKxP5
lveVAkEAo9IKCBtu5HtcF/03fqaU/enagp3obFLJIVaUrvqwqSBKYZDh1dAWbr6V
zJGL9dc3qtHfOG26GcXe7Yb3Uwe1sQJBAJFttQRfbtLmPBxHx3JmU8xOSdysTGwA
B5Dd2k0LF6ar5D5z6mbHxxIHbRPLMqMSQwi7hntcEs5uiFUJ+B7TJXUCQD0cmQEn
onuBkmfkSL5GC74M1MvjnwHwoIOA9HsfVnaGjtUgmwWoYRA3KWQoB1u3BhBT6bFC
5/dZFrKYHgp1+pQ=
-----END PRIVATE KEY-----
"""

_TEST_CERT = """-----BEGIN CERTIFICATE-----
MIICIDCCAYmgAwIBAgIBADANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdUZXN0
IENBMCAXDTE0MDEyMDA1MTUzNloYDzIxMTMxMjI3MDUxNTM2WjAbMRkwFwYDVQQD
DBBUZXN0IENlcnRpZmljYXRlMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDI
E8Bj1yAS6IylarCUVHnDYTnzz7ihMDP8+odqpwL8WaU8rLZuCTvzViWyfAwT15QD
JJOPRSapPA+8W5YmOrsDIGbSz4PL7TAMaS7faCnXWBwv8aWBXhNJ7DNQjtSHgPv9
nOyr1cKecJraSpzggyVsYyVy8uF244xfS0Fr9ZAUYwIDAQABo3sweTAJBgNVHRME
AjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0
ZTAdBgNVHQ4EFgQUt3K0lx1RbBOzBTsd4axqVwXryB8wHwYDVR0jBBgwFoAUkkmw
1vM/7BfNZfVyAYdtWNIOUSUwDQYJKoZIhvcNAQELBQADgYEAE9mEQC4o9ARUuDZD
rHUiL24AFhiZaWyRswsWEuDS9y4KGk0FxeswGLhPRr8UhHppWu/zG36IzlpAIihv
kZiJrldQGN58P4vW/2x5gaqEtv/GMgnK58KntHI/JNczRgTfpScJo2Yy/iImB7xR
kTOQLEMHLOKdUomfTE3bslbH9u8=
-----END CERTIFICATE-----
"""

_TEST_CA = """-----BEGIN CERTIFICATE-----
MIIB9DCCAV2gAwIBAgIJAKHxW+D7fp9HMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
BAMMB1Rlc3QgQ0EwIBcNMTQwMTIwMDUwOTE3WhgPMjExMzEyMjcwNTA5MTdaMBIx
EDAOBgNVBAMMB1Rlc3QgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJ4S
4rS375IHRkXRxFITRE7DVZEXhnrQRMOzgr1gwhyhWBUGEugLYo7uVoO9E2npdL1N
MZkJV60AahuacVxmqjB4ippm2QVBPNJocAJLbfEr/luUEZkYRWFVyNbQL5K0WH71
NFocMP59dDs+Ib888o1NGpwwv95upbGjDJapiiILAgMBAAGjUDBOMB0GA1UdDgQW
BBSSSbDW8z/sF81l9XIBh21Y0g5RJTAfBgNVHSMEGDAWgBSSSbDW8z/sF81l9XIB
h21Y0g5RJTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAG7Iaknm91s7
94Bv+9gt/2OekdxHNsdyyoVUoZl7r2fOMklwduiPCeKsjwluGo01gu4mZGPKF7F/
j/CO1MYpyCm2YnwMc6eQzCUtJpxPcQi3AQzL2G80QCIBgFmG+wCBrYKRtIEFlKn6
MAtouJXWLkCCY3IH5UoY7ObrIK639szY
-----END CERTIFICATE-----
"""

class AuthenticatorTest(unittest.TestCase):
	"""Test the different methods of the AncientAuth authenticator."""

	def test_authenticated_user(self):
		"""Test if we can extract the user from a TokenCookie."""

		key = importKey(_TEST_KEY)

		token = token_pb2.TokenCookie()
		token.basic_creds.user_name = 'testosteronius'
		token.basic_creds.scope.append('users')
		token.basic_creds.expires = calendar.timegm(
			datetime.utcnow().timetuple()) + 30

		codec = token_cookie.TokenCookieCodec(token, privkey=key)
		cookie = codec.encode()

		auth = authenticator.Authenticator("Unit Test", cert=_TEST_CERT)
		self.assertEquals(auth.get_authenticated_user(cookie),
			'testosteronius')

	def test_authenticated_scopes(self):
		"""Test if we can extract the scopes from a TokenCookie."""

		key = importKey(_TEST_KEY)
		token = token_pb2.TokenCookie()
		token.basic_creds.user_name = 'testosteronius'
		token.basic_creds.scope.append('users')
		token.basic_creds.scope.append('lusers')
		token.basic_creds.expires = calendar.timegm(
			datetime.utcnow().timetuple()) + 30

		codec = token_cookie.TokenCookieCodec(token, privkey=key)
		cookie = codec.encode()

		auth = authenticator.Authenticator("Unit Test", cert=_TEST_CERT)
		self.assertEqual(auth.get_authenticated_scopes(cookie),
			['users', 'lusers'])
		self.assertTrue(auth.is_authenticated_scope(cookie, 'users'))
		self.assertTrue(auth.is_authenticated_scope(cookie, 'lusers'))
		self.assertFalse(auth.is_authenticated_scope(cookie, 'fusers'))

	def test_request_authorization(self):
		"""Test if we can request authorization correctly."""

		cert = x509.parse_certificate(_TEST_CERT)

		auth = authenticator.Authenticator("Unit Test", cert=_TEST_CERT,
			key=_TEST_KEY)
		dest = authenticator.urlparse(auth.request_authorization(
			'http://bazquux.foo/asdf/bsdf?q=x&r=x#asd'))

		self.assertEqual("https", dest.scheme)
		self.assertEqual("login.ancient-solutions.com", dest.hostname)
		self.assertEqual("/", dest.path)

		query = authenticator.parse_qs(dest.query)
		self.assertEqual(["token"], query["response_type"])
		self.assertEqual(["http://bazquux.foo/asdf/bsdf?q=x&r=x#asd"],
			query["redirect_uri"])
		self.assertIn("client_id", query)

		atr = token_pb2.AuthTokenRequest()
		cdc = token_cookie.AuthTokenRequestCodec(atr,
			pubkey=cert.get_pub_key())
		try:
			cdc.decode(query["client_id"][0])
		except token_cookie.SignatureException as e:
			self.fail("Cannot validate signature on auth token request")

		self.assertEqual("Unit Test", atr.app_name)
		self.assertEqual("http://bazquux.foo/asdf/bsdf?q=x&r=x#asd",
			atr.original_uri)
		self.assertEqual("http://bazquux.foo/login", atr.return_uri)

	def test_login_handler(self):
		"""Check whether an authentication token response is handled
		and decoded correctly by the authenticator implementation."""

		now = datetime.now()
		expires = now + timedelta(0, 300)
		pkey = importKey(_TEST_KEY)

		auth = authenticator.Authenticator("Unit Test", cert=_TEST_CERT,
			key=_TEST_KEY, ca_bundle=_TEST_CA)
		atres = token_pb2.AuthTokenResponse()
		atres.basic_creds.user_name = 'testosteronius'
		atres.basic_creds.scope.extend(['one', 'two'])
		atres.basic_creds.expires = calendar.timegm(expires.utctimetuple())

		atres.app_name = 'Unit Test'
		atres.original_uri = 'http://lolcathost:8080/foo/bar'
		atres.certificate = _TEST_CERT
		atres.granted = calendar.timegm(now.utctimetuple())

		# FIXME(caoimhe): this should go away.
		atres.random = 'A' * 64

		atrc = token_cookie.AuthTokenResponseCodec(atres, privkey=pkey)
		response = atrc.encode()

		data = auth.login_handler(response)
		self.assertEquals(2, len(data))
		cookiedata = data[0]
		nexturl = data[1]

		self.assertEquals('http://lolcathost:8080/foo/bar', nexturl)


if __name__ == '__main__':
	unittest.main()
