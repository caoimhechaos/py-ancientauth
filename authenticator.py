"""Classes related to the ancient-auth authenticator module."""

from ancientsolutions.crypttools import rsa, x509
from Crypto.PublicKey.RSA import importKey

from os.path import exists

import token_cookie
import token_pb2

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

        if cert is not None and exists(cert):
            self._cert = x509.parse_certificate_file(cert)
        elif cert is not None:
            self._cert = x509.parse_certificate(cert)

        if ca_bundle is not None and exists(ca_bundle):
            self._ca = x509.parse_certificate_file(ca_bundle)
        elif ca_bundle is not None:
            self._ca = x509.parse_certificate(ca_bundle)

        self._app_name = app_name
        self._authserver = authserver

    def get_authenticated_user(self, auth_cookie):
        """Determine the name of the currently logged-in user, if any.

        Parses the authentication cookie passsed in as a string, verifies
        the signatures and, if all checks succeed, returns the name of
        the authenticated user.
        """

        tc = token_pb2.TokenCookie()
        tcc = token_cookie.TokenCookieCodec(tc,
            pubkey=self._cert.get_pub_key())
        tcc.decode(auth_cookie)

        return tc.basic_creds.user_name

    def get_authenticated_scopes(self, auth_cookie):
        """Determines the scopes the authenticated user belongs to.

        Returns a list of the names of all scopes the user is in. If no user
        is authenticated, an empty list is returned.
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
        """
        scopes = self.get_authenticated_scopes(auth_cookie)
        return scope in scopes
