"""Classes related to the ancient-auth authenticator module."""

from ancientsolutions.crypttools import rsa, x509

class Authenticator:
    """Authentification client for the Ancient Login Service."""

    def __init__(self, app_name, cert_file="cert.crt",
                 key_file="key.key", ca_bundle="ca-bundle.crt",
                 authserver="login.ancient-solutions.com"):
        """Set up the authentication client so it can be used lateron.

        Args:
        app_name: The name the login server shall display to the user.
        cert_file: Path to the certificate to use for signing the
        requests.
        key_file: Path to the private key to use for signing the
        requests.
        ca_bundle: path to a CA bundle file to use for authenticating
        the server.
        """
        
        self._rsa_key = rsa.UnwrapRSAKey(key_file)
