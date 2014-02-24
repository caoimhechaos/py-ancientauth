"""Classes related to the ancient-auth authenticator module."""

from ancientsolutions.crypttools import rsa, x509
from Crypto.PublicKey.RSA import importKey

from os.path import exists
try:
    from urlparse import urlparse, urljoin, parse_qs
except Exception as e:
    from urllib.parse import urlparse, urljoin, parse_qs

try:
    from urllib import urlencode
except Exception as e:
    from urllib.parse import urlencode

import token_cookie
import token_pb2

import logging

class Authenticator(object):
    """Authentification client for the Ancient Login Service."""

    def __init__(self, app_name, cert=None, key=None, ca_bundle=None,
                 authserver="login.ancient-solutions.com"):
        """Set up the authentication client so it can be used lateron.

        Args:
        app_name: The name the login server shall display to the user.
        cert: Path to the certificate to use for signing the
        requests, or the contents of the certificate.
        key: Path to the private key to use for signing the
        requests, or the contents of the key.
        ca_bundle: path to a CA bundle file to use for authenticating
        the server.
        """

        if key is not None and exists(key):
            self._rsa_key = rsa.UnwrapRSAKey(key)
        elif key is not None:
            self._rsa_key = importKey(key)
        else:
            self._rsa_key = None

        if cert is not None and exists(cert):
            self._cert = x509.parse_certificate_file(cert)
            f = open(cert)
            self._plain_cert = f.read()
            f.close()
        elif cert is not None:
            self._cert = x509.parse_certificate(cert)
            self._plain_cert = cert
        else:
            self._cert = None
            self._plain_cert = None

        if ca_bundle is not None and exists(ca_bundle):
            self._ca = x509.parse_certificate_file(ca_bundle)
        elif ca_bundle is not None:
            self._ca = x509.parse_certificate(ca_bundle)
        else:
            self._ca = None

        self._app_name = app_name
        self._authserver = authserver

    def get_authenticated_user(self, auth_cookie):
        """Determine the name of the currently logged-in user, if any.

        Parses the authentication cookie passsed in as a string, verifies
        the signatures and, if all checks succeed, returns the name of
        the authenticated user.

        Args:
        auth_cookie: value of the cookie used for authentication.

        Returns:
        Name of the authenticated user, or an empty string if the user
        authentication cannot be verified or is empty.
        """

        if len(auth_cookie) == 0:
            return ""

        tc = token_pb2.TokenCookie()
        tcc = token_cookie.TokenCookieCodec(tc,
            pubkey=self._cert.get_pub_key())
        try:
            tcc.decode(auth_cookie)
        except token_cookie.SignatureException as e:
            return ""
        except token_cookie.TokenExpiredException as e:
            return ""

        return tc.basic_creds.user_name

    def get_authenticated_scopes(self, auth_cookie):
        """Determines the scopes the authenticated user belongs to.

        Returns a list of the names of all scopes the user is in. If no user
        is authenticated, an empty list is returned.

        Args:
        auth_cookie: value of the cookie used for authentication.

        Returns:
        List of all scopes the user is authorized for.
        """

        tc = token_pb2.TokenCookie()
        tcc = token_cookie.TokenCookieCodec(tc,
            pubkey=self._cert.get_pub_key())
        tcc.decode(auth_cookie)

        return tc.basic_creds.scope

    def is_authenticated_scope(self, auth_cookie, scope):
        """Determines if the currently authenticated user is a member of the
        given "scope". Returns true if an user is authenticated and is a
        member of the scope.

        Please note that if this is False but get_authenticated_user returns
        a nonempty string, running request_authorization() won't help since
        the user is already authenticated but doesn't have the requested
        authorization.

        Args:
        auth_cookie: value of the cookie used for authentication.
        scope: name of the scope we are interested in.

        Returns:
        True if the user is a member of the scope, False otherwise.
        """
        scopes = self.get_authenticated_scopes(auth_cookie)
        return scope in scopes

    def request_authorization(self, destination_url):
        """Generates an authentication request URL for the destination_url.

        Generates an URL which the web user needs to go to in order to log in
        and/or provide their authorization token to the current web
        application. After authentication has succeeded (if at all), the
        user will eventually be sent back to destination_url.

        Args:
        destination_url: URL which we would like to return to after a
        authenticating the user successfully.

        Returns: URL the user should be redirected to in order to commence
        authentication.
        """
        atr = token_pb2.AuthTokenRequest()
        returnuri = urlparse(urljoin(destination_url, '/login'))

        atr.app_name = self._app_name
        atr.certificate = self._plain_cert
        atr.return_uri = returnuri.geturl()
        atr.original_uri = destination_url

        if not self._rsa_key:
            raise token_cookie.NoKeyException()

        atrc = token_cookie.AuthTokenRequestCodec(atr,
            privkey=self._rsa_key, pubkey=self._cert.get_pub_key())
        atrdata = atrc.encode()

        params = {
            "client_id": atrdata,
            "redirect_uri": destination_url,
            "response_type": "token",
            "debug": str(atr),
        }
        newurl = ("https://" + self._authserver +
            "/?" + urlencode(params))
        return newurl
