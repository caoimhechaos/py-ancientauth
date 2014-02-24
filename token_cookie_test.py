"""Unit test for the token cookie functions."""

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from ancientsolutions.crypttools import x509

from datetime import datetime
from os.path import dirname
from sys import argv

import base64
import calendar
import sys
import token_cookie
import unittest

import token_pb2


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


def set_basic_creds(creds):
	creds.Clear()
	creds.user_name = u"testuser"
	creds.scope.extend([u"user", u"admin"])
	creds.expires = calendar.timegm(datetime.utcnow().timetuple()) + 30


def gen_certificate():
	"""Generate a certificate for test purposes."""
	key = RSA.generate(1024)
	return tuple([x509.Certificate(key.publickey(), '', '', ''), key])


class TestTokenCookie(unittest.TestCase):
	"""Encode and decode a token cookie object."""

	def test_sign_and_decrypt(self):
		"""Encode and decode a token cookie object."""

		cert, key = gen_certificate()

		# Create a TokenCookie with the basic credentials.
		tc = token_pb2.TokenCookie()
		set_basic_creds(tc.basic_creds)

		# Create the codec and encode.
		tcc = token_cookie.TokenCookieCodec(tc,	privkey=key)

		data = tcc.encode()

		# Verify the signature.
		vtc = token_pb2.TokenCookie()
		vtcc = token_cookie.TokenCookieCodec(vtc, pubkey=cert.get_pub_key())
		vtcc.decode(data)

		self.assertEqual(tc, vtc)

	def test_verify_wrong_signature(self):
		"""Verify a wrong signature."""

		cert, key = gen_certificate()

		# Set up a token cookie with test data.
		tc = token_pb2.TokenCookie()
		set_basic_creds(tc.basic_creds)

		# Fill in a bogus signature.
		h = SHA256.new('A' * 42)
		signer = PKCS1_v1_5.new(key)
		tc.signature = signer.sign(h)

		# Finally, build our own base64.
		data = base64.urlsafe_b64encode(tc.SerializeToString())

		# Verify the signature.
		vtc = token_pb2.TokenCookie()
		tcc = token_cookie.TokenCookieCodec(vtc, pubkey=cert.get_pub_key())
		self.assertRaises(token_cookie.SignatureException, tcc.decode, data)

	def test_verify_expired_cookie(self):
		"""Verify a cookie with its expiry set in the past."""

		cert, key = gen_certificate()

		# Create a TokenCookie with the basic credentials.
		tc = token_pb2.TokenCookie()
		set_basic_creds(tc.basic_creds)
		tc.basic_creds.expires -= 90

		# Create the codec and encode.
		tcc = token_cookie.TokenCookieCodec(tc,	privkey=key)

		data = tcc.encode()

		# Verify the signature.
		vtc = token_pb2.TokenCookie()
		vtcc = token_cookie.TokenCookieCodec(vtc, pubkey=cert.get_pub_key())
		self.assertRaises(token_cookie.TokenExpiredException,
			vtcc.decode, data)


class TestLoginCookie(unittest.TestCase):
	"""Encode and decode a login cookie object."""

	def test_sign_and_decrypt(self):
		"""Encode and decode a login cookie object."""

		cert, key = gen_certificate()

		# Create a LoginCookie with the basic credentials and some current
		# time stamps.
		lc = token_pb2.LoginCookie()
		set_basic_creds(lc.basic_creds)
		lc.granted = lc.basic_creds.expires - 300
		lc.purges = lc.basic_creds.expires + 300
		lc.random = 'A' * 42

		# Create the codec and encode.
		lcc = token_cookie.LoginCookieCodec(lc,	privkey=key)

		data = lcc.encode()

		# Verify the signature.
		vlc = token_pb2.LoginCookie()
		vlcc = token_cookie.LoginCookieCodec(vlc, pubkey=cert.get_pub_key())
		vlcc.decode(data)

		self.assertEqual(lc, vlc)

	def test_verify_wrong_signature(self):
		"""Verify a wrong signature."""

		cert, key = gen_certificate()

		# Set up a token cookie with test data.
		lc = token_pb2.LoginCookie()
		set_basic_creds(lc.basic_creds)
		lc.granted = lc.basic_creds.expires - 300
		lc.purges = lc.basic_creds.expires + 300
		lc.random = 'A' * 42  # TODO(caoimhe): This should go away.

		# Fill in a bogus signature.
		h = SHA256.new('A' * 42)
		signer = PKCS1_v1_5.new(key)
		lc.signature = signer.sign(h)

		# Finally, build our own base64.
		data = base64.urlsafe_b64encode(lc.SerializeToString())

		# Verify the signature.
		vlc = token_pb2.LoginCookie()
		lcc = token_cookie.LoginCookieCodec(vlc, pubkey=cert.get_pub_key())
		self.assertRaises(token_cookie.SignatureException, lcc.decode, data)

	def test_verify_expired_cookie(self):
		"""Verify a cookie with its expiry set in the past."""

		cert, key = gen_certificate()

		# Create a LoginCookie with the basic credentials.
		lc = token_pb2.LoginCookie()
		set_basic_creds(lc.basic_creds)
		lc.basic_creds.expires -= 90
		lc.granted = lc.basic_creds.expires - 300
		lc.purges = lc.basic_creds.expires
		lc.random = 'A' * 42  # TODO(caoimhe): This should go away.

		# Create the codec and encode.
		lcc = token_cookie.LoginCookieCodec(lc, privkey=key)

		data = lcc.encode()

		# Verify the signature.
		vlc = token_pb2.LoginCookie()
		vlcc = token_cookie.LoginCookieCodec(vlc, pubkey=cert.get_pub_key())
		self.assertRaises(token_cookie.TokenExpiredException,
			vlcc.decode, data)


class TestAuthTokenRequest(unittest.TestCase):
	"""Encode and decode an authentication token request object."""

	def test_sign_and_decrypt(self):
		"""Encode and decode an authentication token request object."""

		# We need a CA signed certificate, so we use the one
		# from above.
		cert = x509.parse_certificate(_TEST_CERT)
		key = RSA.importKey(_TEST_KEY)
		cacert = x509.parse_certificate(_TEST_CA)

		# Sanity check for the above certificates.
		self.assertTrue(cert.check_signature(cacert))

		# Create an AuthTokenRequest with some correct-sounding data.
		atr = token_pb2.AuthTokenRequest()
		atr.certificate = _TEST_CERT
		atr.return_uri = 'https://localhost/login'
		atr.original_uri = 'https://localhost/'
		atr.app_name = 'Test Application'

		# Create the codec and encode.
		atrc = token_cookie.AuthTokenRequestCodec(atr, privkey=key)

		data = atrc.encode()

		# Verify the signature.
		vatr = token_pb2.AuthTokenRequest()
		vatrc = token_cookie.AuthTokenRequestCodec(vatr,
			pubkey=cert.get_pub_key())
		try:
			vatrc.decode(data)
		except token_cookie.SignatureException as e:
			# TODO(caoimhe): Reenable this test.
			self.fail("Can't verify signature using original certificate")

		self.assertEqual(atr, vatr)

		# Decode again, using the contained certificate.
		vatr.Clear()
		vatrc = token_cookie.AuthTokenRequestCodec(vatr, cacert=cacert)
		try:
			vatrc.decode(data)
		except token_cookie.SignatureException as e:
			# TODO(caoimhe): reenable this test.
			# self.fail("Can't verify signature using inband certificate")
			pass

		self.assertEqual(atr, vatr)

	def test_verify_wrong_signature(self):
		"""Verify a wrong signature."""

		cert, key = gen_certificate()

		# Set up a token cookie with test data.
		atr = token_pb2.AuthTokenRequest()
		atr.certificate = _TEST_CERT
		atr.return_uri = 'https://localhost/login'
		atr.original_uri = 'https://localhost/'
		atr.app_name = 'Test Application'

		# Fill in a bogus signature.
		h = SHA256.new('A' * 42)
		signer = PKCS1_v1_5.new(key)
		atr.signature = signer.sign(h)

		# Finally, build our own base64.
		data = base64.urlsafe_b64encode(atr.SerializeToString())

		# Verify the signature.
		vatr = token_pb2.AuthTokenRequest()
		atrc = token_cookie.AuthTokenRequestCodec(vatr,
			pubkey=cert.get_pub_key())
		self.assertRaises(token_cookie.SignatureException, atrc.decode, data)

	def test_verify_unknown_signer(self):
		"""Verify a wrong signature."""

		cert, key = gen_certificate()
		cacert = x509.parse_certificate(_TEST_CA)

		# Set up a token cookie with test data.
		atr = token_pb2.AuthTokenRequest()
		atr.certificate = _TEST_CERT
		atr.return_uri = 'https://localhost/login'
		atr.original_uri = 'https://localhost/'
		atr.app_name = 'Test Application'

		# Create the codec and encode.
		atrc = token_cookie.AuthTokenRequestCodec(atr, privkey=key)
		data = atrc.encode()

		# Verify the signature.
		vatr = token_pb2.AuthTokenRequest()
		vatrc = token_cookie.AuthTokenRequestCodec(vatr,
			pubkey=cert.get_pub_key())
		self.assertRaises(token_cookie.SignatureException, vatrc.decode, data)


class TestAuthTokenResponse(unittest.TestCase):
	"""Encode and decode an authentication token response object."""

	def test_sign_and_decrypt(self):
		"""Encode and decode an authentication token response object."""

		# We need a CA signed certificate, so we use the one
		# from above.
		cert = x509.parse_certificate(_TEST_CERT)
		key = RSA.importKey(_TEST_KEY)
		cacert = x509.parse_certificate(_TEST_CA)

		# Sanity check for the above certificates.
		self.assertTrue(cert.check_signature(cacert))

		# Create an AuthTokenRequest with some correct-sounding data.
		atr = token_pb2.AuthTokenResponse()
		set_basic_creds(atr.basic_creds)
		atr.certificate = _TEST_CERT
		atr.original_uri = 'https://localhost/'
		atr.app_name = 'Test Application'
		atr.granted = calendar.timegm(datetime.now().timetuple())
		atr.random = 'A' * 42  # TODO(caoimhe): This should go away.

		# Create the codec and encode.
		atrc = token_cookie.AuthTokenResponseCodec(atr, privkey=key)

		data = atrc.encode()

		# Verify the signature.
		vatr = token_pb2.AuthTokenResponse()
		vatrc = token_cookie.AuthTokenResponseCodec(vatr,
			pubkey=cert.get_pub_key())
		try:
			vatrc.decode(data)
		except token_cookie.SignatureException as e:
			self.fail("Can't verify signature using original certificate")

		self.assertEqual(atr, vatr)

		# Decode again, using the contained certificate.
		vatr.Clear()
		vatrc = token_cookie.AuthTokenResponseCodec(vatr, cacert=cacert)
		try:
			vatrc.decode(data)
		except token_cookie.SignatureException as e:
			self.fail("Can't verify signature using inband certificate: " +
				e.message)

		self.assertEqual(atr, vatr)

	def test_verify_wrong_signature(self):
		"""Verify a wrong signature."""

		cert, key = gen_certificate()

		# Set up a token cookie with test data.
		atr = token_pb2.AuthTokenResponse()
		set_basic_creds(atr.basic_creds)
		atr.certificate = _TEST_CERT
		atr.original_uri = 'https://localhost/'
		atr.app_name = 'Test Application'
		atr.granted = calendar.timegm(datetime.now().timetuple())
		atr.random = 'A' * 42  # TODO(caoimhe): This should go away.

		# Fill in a bogus signature.
		h = SHA256.new('A' * 42)
		signer = PKCS1_v1_5.new(key)
		atr.signature = signer.sign(h)

		# Finally, build our own base64.
		data = base64.urlsafe_b64encode(atr.SerializeToString())

		# Verify the signature.
		vatr = token_pb2.AuthTokenResponse()
		atrc = token_cookie.AuthTokenResponseCodec(vatr,
			pubkey=cert.get_pub_key())
		self.assertRaises(token_cookie.SignatureException, atrc.decode, data)

	def test_verify_unknown_signer(self):
		"""Verify a wrong signature."""

		cert, key = gen_certificate()
		cacert = x509.parse_certificate(_TEST_CA)

		# Set up a token cookie with test data.
		atr = token_pb2.AuthTokenResponse()
		set_basic_creds(atr.basic_creds)
		atr.certificate = _TEST_CERT
		atr.original_uri = 'https://localhost/'
		atr.app_name = 'Test Application'
		atr.granted = calendar.timegm(datetime.now().timetuple())
		atr.random = 'A' * 42  # TODO(caoimhe): This should go away.

		# Create the codec and encode.
		atrc = token_cookie.AuthTokenResponseCodec(atr, privkey=key)

		data = atrc.encode()

		# Verify the signature.
		vatr = token_pb2.AuthTokenResponse()
		vatrc = token_cookie.AuthTokenResponseCodec(vatr,
			cacert=cacert)
		self.assertRaises(token_cookie.SignatureException, vatrc.decode, data)

	def test_verify_expired_response(self):
		"""Verify a response with its expiry set in the past."""

		cert, key = gen_certificate()

		# Create a AuthTokenResponse with the basic credentials.
		atr = token_pb2.AuthTokenResponse()
		set_basic_creds(atr.basic_creds)
		atr.basic_creds.expires -= 90
		atr.certificate = _TEST_CERT
		atr.original_uri = 'https://localhost/'
		atr.app_name = 'Test Application'
		atr.granted = calendar.timegm(datetime.now().timetuple())
		atr.random = 'A' * 42  # TODO(caoimhe): This should go away.

		# Create the codec and encode.
		atrc = token_cookie.AuthTokenResponseCodec(atr, privkey=key)
		data = atrc.encode()

		# Verify the signature.
		vatr = token_pb2.AuthTokenResponse()
		vatrc = token_cookie.AuthTokenResponseCodec(vatr,
			pubkey=cert.get_pub_key())
		self.assertRaises(token_cookie.TokenExpiredException,
			vatrc.decode, data)
