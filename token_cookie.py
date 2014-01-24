"""Helpers for encoding, decoding and verification of various objects.

This file contains methods for encoding (packing and signing) as well
as decoding (verifying signatures and unpacking) of token cookies,
login cookies, authentication token requests and responses.
"""

from ancientsolutions.crypttools import x509
import base64

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from datetime import datetime

import token_pb2


class SignatureException(Exception):
    """The signature on a cookie was not valid."""


class TokenExpiredException(Exception):
    """The token which was supposed to be decoded has expired."""


class NoKeyException(Exception):
    """Signature creation or verification was requested without a key.

    This indicates that the user of the codec has requested an operation
    which requires a key which was not configured for the codec.
    """


class UnsupportedKeyTypeException(Exception):
    """Indicates that the key type was not known or supported."""


class DataTypeException(Exception):
    """Indicates that data passed in was not of the expected type."""


class TokenCookieCodec(object):
    """Extension for the protocol buffer class TokenCookie.

    This class provides extensions for the TokenCookie class to
    generate an RSA signature or to verify it. It doesn't override any
    of the other fields of the TokenCookie class.
    """

    def __init__(self, tc, privkey=None, pubkey=None):
        """Creates an encoder/decoder for TokenCookie objects.

        The codec can encode a token cookie to signed, base64 encoded
        format and read such tokens, verifying their signature.

        Args:
        tc: a TokenCookie object to be used for reading/writing the
        structured data. Will be used as a data source for encode()
        and as a destination for data in decode().
        privkey: Crypto.PublicKey.RSA key to use for signing the cookie.
        pubkey: RSA public key to use for verifying the signature.
        """
        if isinstance(tc, token_pb2.TokenCookie):
            self._tc = tc
        else:
            raise DataTypeException()

        if privkey is None or isinstance(privkey, RSA._RSAobj):
            self._priv = privkey
        else:
            raise UnsupportedKeyTypeException()

        if pubkey is None or isinstance(pubkey, RSA._RSAobj):
            self._pub = pubkey
        else:
            raise UnsupportedKeyTypeException()

    def set_privkey(self, key):
        """Change the configured private key.

        Args:
        key: the new private key to be used for generating signatures.
        """

        if not isinstance(key, RSA._RSAobj):
            raise UnsupportedKeyTypeException()

        self._priv = key

    def set_pubkey(self, key):
        """Change the configured private key.

        Args:
        key: the new private key to be used for generating signatures.
        """

        if not isinstance(key, RSA._RSAobj):
            raise UnsupportedKeyTypeException()

        self._pub = key

    def encode(self):
        """Encodes the given token cookie with the given RSA key.

        Encode the structure and return it as bytes. Sign with the
        private key.

        Return:
        Base64 encoded version of the PKCS#1v1.5 signed token cookie.
        """
        if not self._priv:
            raise NoKeyException()

        self._tc.ClearField("signature")
        h = SHA256.new(self._tc.SerializeToString())

        signer = PKCS1_v1_5.new(self._priv)
        self._tc.signature = signer.sign(h)

        return base64.urlsafe_b64encode(self._tc.SerializeToString())

    def decode(self, src):
        """Verify the signature and decode the token cookie.

        Decode the structure. Verifies the signature with the
        public key configured with the codec.

        Args:
        src: string containing the base64 encoded cookie.

        Return:
        Integer value indicating the length of the data which was
        read; this is so it can be skipped if multiple records are
        returned. This length is after base64 decoding, so a
        multiplier must be applied.
        """
        if self._pub is None:
            raise NoKeyException()

        data = base64.urlsafe_b64decode(src)
        self._tc.ParseFromString(data)

        if (datetime.utcfromtimestamp(self._tc.basic_creds.expires) <
            datetime.utcnow()):
            raise TokenExpiredException()

        # We'll need a copy of the data so we can verify it by
        # setting the signature to None.
        pb = token_pb2.TokenCookie()
        pb.ParseFromString(data)
        pb.ClearField("signature")

        h = SHA256.new(pb.SerializeToString())
        verifier = PKCS1_v1_5.new(self._pub)
        if verifier.verify(h, self._tc.signature):
            return len(data)
        else:
            raise SignatureException()


class LoginCookieCodec(object):
    """Extension for the protocol buffer class LoginCookie.

    This class provides extensions for the LoginCookie class to
    generate an RSA signature or to verify it. It doesn't override any
    of the other fields of the LoginCookie class.
    """

    def __init__(self, lc, privkey=None, pubkey=None):
        """Creates an encoder/decoder for LoginCookie objects.

        The codec can encode a login cookie to signed, base64 encoded
        format and read such tokens, verifying their signature.

        Args:
        lc: a LoginCookie object to be used for reading/writing the
        structured data. Will be used as a data source for encode()
        and as a destination for data in decode().
        privkey: Crypto.PublicKey.RSA key to use for signing the cookie.
        pubkey: RSA public key to use for verifying the signature.
        """
        if isinstance(lc, token_pb2.LoginCookie):
            self._lc = lc
        else:
            raise DataTypeException()

        if privkey is None or isinstance(privkey, RSA._RSAobj):
            self._priv = privkey
        else:
            raise UnsupportedKeyTypeException()

        if pubkey is None or isinstance(pubkey, RSA._RSAobj):
            self._pub = pubkey
        else:
            raise UnsupportedKeyTypeException()

    def set_privkey(self, key):
        """Change the configured private key.

        Args:
        key: the new private key to be used for generating signatures.
        """

        if not isinstance(key, RSA._RSAobj):
            raise UnsupportedKeyTypeException()

        self._priv = key

    def set_pubkey(self, key):
        """Change the configured private key.

        Args:
        key: the new private key to be used for generating signatures.
        """

        if not isinstance(key, RSA._RSAobj):
            raise UnsupportedKeyTypeException()

        self._pub = key

    def encode(self):
        """Encode and sign the structure and return it as bytes.

        Return:
        Base64 encoded version of the PKCS#1v1.5 signed token cookie.
        """
        if not self._priv:
            raise NoKeyException()

        # TODO(caoimhe): Fill the random field.

        self._lc.ClearField("signature")
        h = SHA256.new(self._lc.SerializeToString())

        signer = PKCS1_v1_5.new(self._priv)
        self._lc.signature = signer.sign(h)

        return base64.urlsafe_b64encode(self._lc.SerializeToString())

    def decode(self, src):
        """Verify the signature and decode the login cookie.

        Decode the structure. Verifies the signature with the
        public key configured for the codec.

        Args:
        src: string containing the base64 encoded cookie.

        Return:
        Integer value indicating the length of the data which was
        read; this is so it can be skipped if multiple records are
        returned. This length is after base64 decoding, so a
        multiplier must be applied.
        """
        if not self._pub:
            raise NoKeyException()

        data = base64.urlsafe_b64decode(src)
        self._lc.ParseFromString(data)

        if (datetime.utcfromtimestamp(self._lc.basic_creds.expires) <
            datetime.utcnow()):
            raise TokenExpiredException()

        if (datetime.utcfromtimestamp(self._lc.granted) >
            datetime.utcnow()):
            raise TokenExpiredException()

        if (datetime.utcfromtimestamp(self._lc.purges) <
            datetime.utcnow()):
            raise TokenExpiredException()

        # We'll need a copy of the data so we can verify it by
        # setting the signature to None.
        pb = token_pb2.LoginCookie()
        pb.ParseFromString(data)
        pb.ClearField("signature")

        h = SHA256.new(pb.SerializeToString())
        verifier = PKCS1_v1_5.new(self._pub)
        if verifier.verify(h, self._lc.signature):
            return len(data)
        else:
            raise SignatureException()


class AuthTokenRequestCodec(object):
    """Extension for the protocol buffer class AuthTokenRequest.

    This class provides extensions for the AuthTokenRequest class to
    generate an RSA signature or to verify it. It doesn't override any
    of the other fields of the AuthTokenRequest class.
    """

    def __init__(self, atr, privkey=None, pubkey=None, cacert=None):
        """Creates an encoder/decoder for AuthTokenRequest objects.

        The codec can encode an authentication token request to signed,
        base64 encoded format and read such tokens, verifying their
        signature.

        Args:
        lc: an AuthTokenRequest object to be used for reading/writing the
        structured data. Will be used as a data source for encode() and
        as a destination for data in decode().
        privkey: Crypto.PublicKey.RSA key to use for signing the cookie.
        pubkey: RSA public key to use for verifying the signature.
        cacert: path or x509.Certificate object of a CA certificate which
        should be used to verify certificates used in the
        AuthTokenRequests.
        """
        if isinstance(atr, token_pb2.AuthTokenRequest):
            self._atr = atr
        else:
            raise DataTypeException()

        if privkey is None or isinstance(privkey, RSA._RSAobj):
            self._priv = privkey
        else:
            raise UnsupportedKeyTypeException()

        if pubkey is None or isinstance(pubkey, RSA._RSAobj):
            self._pub = pubkey
        else:
            raise UnsupportedKeyTypeException()

        if cacert is None or isinstance(cacert, x509.Certificate):
            self._ca = cacert
        else:
            self._ca = x509.parse_certificate_file(cacert)

    def set_privkey(self, key):
        """Change the configured private key.

        Args:
        key: the new private key to be used for generating signatures.
        """

        if not isinstance(key, RSA._RSAobj):
            raise UnsupportedKeyTypeException()

        self._priv = key

    def set_pubkey(self, key):
        """Change the configured private key.

        Args:
        key: the new private key to be used for generating signatures.
        """

        if not isinstance(key, RSA._RSAobj):
            raise UnsupportedKeyTypeException()

        self._pub = key

    def set_cacert(self, cert):
        """Define a CA certificate to verify request certificates with.

        AuthTokenRequests may contain certificates which were used for
        signing the request. The CA certificate defined using this
        method will be used to verify any certificates specified in
        the AuthTokenRequests passed in.

        Args:
        cert: x509.Certificate object or path to an X509 certificate file.
        """

        if not isinstance(cert, x509.Certificate):
            cert = x509.parse_certificate_file(cert)

        self._ca = cert

    def encode(self):
        """Encode and sign the structure and return it as bytes.

        Args:
        key: Crypto.PublicKey.RSA key to use for signing the request.

        Return:
        Base64 encoded version of the PKCS#1v1.5 signed authentication
        token request.
        """
        if not self._priv:
            raise NoKeyException()

        self._atr.ClearField("signature")
        h = SHA256.new(self._atr.SerializeToString())

        signer = PKCS1_v1_5.new(self._priv)
        self.signature = signer.sign(h)

        return base64.urlsafe_b64encode(self._atr.SerializeToString())


    def decode(self, src):
        """Verify the signature and decode the request.

        Decode the structure. Verifies the signature with the given
        public key, or with the key contained inside the message if
        None is passed.

        Args:
        src: string containing the base64 encoded cookie.

        Return:
        Integer value indicating the length of the data which was
        read; this is so it can be skipped if multiple records are
        returned. This length is after base64 decoding, so a
        multiplier must be applied.
        """
        data = base64.urlsafe_b64decode(src)
        self._atr.ParseFromString(data)

        # We'll need a copy of the data so we can verify it by
        # setting the signature to None.
        pb = token_pb2.AuthTokenRequest()
        pb.ParseFromString(data)
        pb.ClearField("signature")

        h = SHA256.new(pb.SerializeToString())

        if self._pub:
            verifier = PKCS1_v1_5.new(self._pub)
        else:
            # Attempt to extract the certificate from the request.
            cert = x509.parse_certificate(self._atr.certificate)

            if not self._ca:
                raise NoKeyException()
            if not self._ca.check_signature(cert):
                raise SignatureException()

            verifier = PKCS1_v1_5.new(cert.get_pubkey())

        if verifier.verify(h, self._atr.signature):
            return len(data)
        else:
            raise SignatureException()


class AuthTokenResponseCodec(object):
    """Extension for the protocol buffer class AuthTokenResponse.

    This class provides extensions for the AuthTokenResponse class to
    generate an RSA signature or to verify it. It doesn't override any
    of the other fields of the AuthTokenResponse class.
    """

    def __init__(self, atr, privkey=None, pubkey=None, cacert=None):
        """Creates an encoder/decoder for AuthTokenResponse objects.

        The codec can encode an authentication token response to signed,
        base64 encoded format and read such tokens, verifying their
        signature.

        Args:
        lc: an AuthTokenResponse object to be used for reading/writing the
        structured data. Will be used as a data source for encode() and
        as a destination for data in decode().
        privkey: Crypto.PublicKey.RSA key to use for signing the cookie.
        pubkey: RSA public key to use for verifying the signature.
        cacert: path or x509.Certificate object of a CA certificate which
        should be used to verify certificates used in the
        AuthTokenResponse.
        """
        if isinstance(atr, token_pb2.AuthTokenResponse):
            self._atr = atr
        else:
            raise DataTypeException()

        if privkey is None or isinstance(privkey, RSA._RSAobj):
            self._priv = privkey
        else:
            raise UnsupportedKeyTypeException()

        if pubkey is None or isinstance(pubkey, RSA._RSAobj):
            self._pub = pubkey
        else:
            raise UnsupportedKeyTypeException()

        if cacert is None or isinstance(cacert, x509.Certificate):
            self._ca = cacert
        else:
            self._ca = x509.parse_certificate_file(cacert)

    def set_privkey(self, key):
        """Change the configured private key.

        Args:
        key: the new private key to be used for generating signatures.
        """

        if not isinstance(key, RSA._RSAobj):
            raise UnsupportedKeyTypeException()

        self._priv = key

    def set_pubkey(self, key):
        """Change the configured private key.

        Args:
        key: the new private key to be used for generating signatures.
        """

        if not isinstance(key, RSA._RSAobj):
            raise UnsupportedKeyTypeException()

        self._pub = key

    def set_cacert(self, cert):
        """Define a CA certificate to verify request certificates with.

        AuthTokenRequests may contain certificates which were used for
        signing the request. The CA certificate defined using this
        method will be used to verify any certificates specified in
        the AuthTokenRequests passed in.

        Args:
        cert: x509.Certificate object or path to an X509 certificate file.
        """

        if not isinstance(cert, x509.Certificate):
            cert = x509.parse_certificate_file(cert)

        self._ca = cert

    def encode(self):
        """Encode and sign the structure and return it as bytes.

        Return:
        Base64 encoded version of the PKCS#1v1.5 signed authentication
        token response.
        """
        if not self._priv:
            raise NoKeyException()

        # TODO(caoimhe): Fill the random field.

        self._atr.ClearField("signature")
        h = SHA256.new(self._atr.SerializeToString())

        signer = PKCS1_v1_5.new(self._priv)
        self._atr.signature = signer.sign(h)

        return base64.urlsafe_b64encode(self._atr.SerializeToString())

    def decode(self, src):
        """Verify the signature and decode the response.

        Decode the structure. Verifies the signature with the given
        public key, or with the key contained inside the message if
        None is passed.

        Args:
        src: string containing the base64 encoded cookie.

        Return:
        Integer value indicating the length of the data which was
        read; this is so it can be skipped if multiple records are
        returned. This length is after base64 decoding, so a
        multiplier must be applied.
        """
        data = base64.urlsafe_b64decode(src)
        self._atr.ParseFromString(data)

        if (datetime.utcfromtimestamp(self._atr.basic_creds.expires) <
            datetime.utcnow()):
            raise TokenExpiredException()

       # We'll need a copy of the data so we can verify it by
        # setting the signature to None.
        pb = token_pb2.AuthTokenResponse()
        pb.ParseFromString(data)
        pb.ClearField("signature")

        h = SHA256.new(pb.SerializeToString())
        if self._pub:
            verifier = PKCS1_v1_5.new(self._pub)
        else:
            # Attempt to extract the certificate from the request.
            cert = x509.parse_certificate(self._atr.certificate)

            if not self._ca:
                raise NoKeyException()
            if not self._ca.check_signature(cert):
                raise SignatureException()

            verifier = PKCS1_v1_5.new(cert.get_pubkey())

        if verifier.verify(h, self._atr.signature):
            return len(data)
        else:
            raise SignatureException()
