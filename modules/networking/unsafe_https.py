"""Provide a custom HTTP session with a relaxed SSL context.

Disable certificate verification and allow insecure ciphers for compatibility with legacy systems.
"""
import ssl
from ssl import SSLContext

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
from urllib3.poolmanager import PoolManager
from urllib3.util import create_urllib3_context

# Workaround unsecure request warnings
urllib3.disable_warnings(InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0",
}


# Allow custom ssl context for adapters
class CustomSSLContextHTTPAdapter(HTTPAdapter):
    def __init__(self, ssl_context: SSLContext | None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs):  # noqa: ARG002, FBT001, FBT002
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=self.ssl_context,
        )


def create_unsafe_https_session(headers: dict[str, str] | None = None):
    context = create_urllib3_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Work around unsecure ciphers being rejected
    context.set_ciphers("DEFAULT@SECLEVEL=0")
    # Work around legacy renegotiation being disabled
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT

    session = requests.session()
    session.mount("https://", CustomSSLContextHTTPAdapter(context))
    if headers:
        session.headers.update(headers)
    session.verify = False

    return session


s = create_unsafe_https_session(HEADERS)
