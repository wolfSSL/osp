"""
SSL/TLS support via the wolfSSL embedded SSL/TLS library.

You can install the wolfSSL python wrapper using the following command:

    pip install wolfssl

To activate wolfSSL support, call
:func:`~urllib3.contrib.wolfssl.inject_into_urllib3` from your Python code
before you begin making HTTP requests. This can be done in a ``sitecustomize``
module, or at any other time before your application begins using ``urllib3``,
like this::

    try:
        import urllib3.contrib.wolfssl
        urllib3.contrib.wolfssl.inject_into_urllib3()
    except ImportError:
        pass

If you want to configure the default list of supported cipher suites, you can
set the ``urllib3.contrib.wolfssl.DEFAULT_SSL_CIPHER_LIST`` variable.
"""
from __future__ import absolute_import

import wolfssl

from socket import timeout, error as SocketError
from io import BytesIO

try:  # Platform-specific: Python 2
    from socket import _fileobject
except ImportError:  # Platform-specific: Python 3
    _fileobject = None
    from ..packages.backports.makefile import backport_makefile

import logging
import ssl
from ..packages import six
import sys

from .. import util

__all__ = ['inject_into_urllib3', 'extract_from_urllib3']

# wolfssl-py is configured to have SNI always compiled in
HAS_SNI = True

# Map from urllib3 to wolfSSL compatible parameter-values.
_wolfssl_versions = {
    ssl.PROTOCOL_SSLv23: wolfssl.PROTOCOL_SSLv23,
    ssl.PROTOCOL_TLSv1: wolfssl.PROTOCOL_TLSv1,
}

# add SSL 3.0, TLS 1.1 and TLS 1.2 support, if available
if hasattr(ssl, 'PROTOCOL_TLSv1_1') and hasattr(wolfssl, 'PROTOCOL_TLSv1_1'):
    _wolfssl_versions[ssl.PROTOCOL_TLSv1_1] = wolfssl.PROTOCOL_TLSv1_1

if hasattr(ssl, 'PROTOCOL_TLSv1_2') and hasattr(wolfssl, 'PROTOCOL_TLSv1_2'):
    _wolfssl_versions[ssl.PROTOCOL_TLSv1_2] = wolfssl.PROTOCOL_TLSv1_2

try:
    _wolfssl_versions.update({ssl.PROTOCOL_SSLv3: wolfssl.PROTOCOL_SSLv3})
except AttributeError:
    pass

# wolfssl-py doesn't support CERT_OPTIONAL yet, map to CERT_REQUIRED
_stdlib_to_wolfssl_verify = {
    ssl.CERT_NONE: wolfssl.CERT_NONE,
    ssl.CERT_OPTIONAL: wolfssl.CERT_REQUIRED,
    ssl.CERT_REQUIRED: wolfssl.CERT_REQUIRED,
}
_wolfssl_to_stdlib_verify = dict(
    (v, k) for k, v in _stdlib_to_wolfssl_verify.items()
)

# store original util ssl settings, in case user wants to extract wolfssl-py
orig_util_HAS_SNI = util.HAS_SNI
orig_util_SSLContext = util.ssl_.SSLContext


log = logging.getLogger(__name__)


def inject_into_urllib3():
    'Monkey-patch urllib3 with wolfssl-backed SSL-support.'

    util.ssl_.SSLContext = wolfSSLContext
    util.HAS_SNI = HAS_SNI
    util.ssl_.HAS_SNI = HAS_SNI
    util.IS_WOLFSSL = True
    util.ssl_.IS_WOLFSSL = True


def extract_from_urllib3():
    'Undo monkey-patching by :func:`inject_into_urllib3`.'

    util.ssl_.SSLContext = orig_util_SSLContext
    util.HAS_SNI = orig_util_HAS_SNI
    util.ssl_.HAS_SNI = orig_util_HAS_SNI
    util.IS_WOLFSSL = False
    util.ssl_.IS_WOLFSSL = False


class WrappedSocket(object):
    '''API-compatibility wrapper for wolfSSL's SSLSocket class.

    Note: _makefile_refs, _drop() and _reuse() are needed for the garbage
    collector of pypy.
    '''

    def __init__(self, connection, socket, suppress_ragged_eofs=True):
        self.connection = connection
        self.socket = socket
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self._makefile_refs = 0
        self._closed = False

    def fileno(self):
        return self.socket.fileno()

    # Copy-pasted from Python 3.5 source code
    def _decref_socketios(self):
        if self._makefile_refs > 0:
            self._makefile_refs -= 1
        if self._closed:
            self.close()

    def recv(self, *args, **kwargs):
        try:
            data = self.connection.recv(*args, **kwargs)
        except wolfssl.SSLWantReadError:
            if not util.wait_for_read(self.socket, self.socket.gettimeout()):
                raise timeout('The read operation timed out')
            else:
                return self.recv(*args, **kwargs)
        else:
            return data

    def recv_into(self, *args, **kwargs):
        return self.connection.recv_into(*args, **kwargs)

    def settimeout(self, timeout):
        return self.socket.settimeout(timeout)

    def sendall(self, data):
        self.connection.sendall(data)

    def shutdown(self):
        self.connection.shutdown()

    def close(self):
        if self._makefile_refs < 1:
            self._closed = True
            return self.connection.close()
        else:
            self._makefile_refs -= 1

    def getpeercert(self, binary_form=False):
        return self.connection.getpeercert(binary_form=binary_form)

    def _reuse(self):
        self._makefile_refs += 1

    def _drop(self):
        if self._makefile_refs < 1:
            self.close()
        else:
            self._makefile_refs -= 1


if _fileobject:  # Platform-specific: Python 2
    def makefile(self, mode, bufsize=-1):
        self._makefile_refs += 1
        return _fileobject(self, mode, bufsize, close=True)
else:  # Platform-specific: Python 3
    makefile = backport_makefile

WrappedSocket.makefile = makefile


class wolfSSLContext(object):
    """
    Wrapper class for wolfssl-py ``Context`` object. Responsible for translating
    the interface of the standard library ``SSLContext`` object
    to calls into wolfSSL>
    """
    def __init__(self, protocol):
        self.protocol = _wolfssl_versions[protocol]
        self._ctx = wolfssl.SSLContext(self.protocol)
        self._options = 0
        self.check_hostname = False

    @property
    def options(self):
        return self._options

    @options.setter
    def options(self, value):
        self._options = value
        self._ctx.set_options(value)

    @property
    def verify_mode(self):
        return _wolfssl_to_stdlib_verify[self._ctx.verify_mode]

    @verify_mode.setter
    def verify_mode(self, value):
        self._ctx.verify_mode = _stdlib_to_wolfssl_verify[value]

    def set_default_verify_paths(self):
        return

    def set_ciphers(self, ciphers):
        if isinstance(ciphers, six.text_type):
            ciphers = ciphers.encode('utf-8')
        self._ctx.set_ciphers(ciphers)

    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        if cafile is not None:
            cafile = cafile.encode('utf-8')
        if capath is not None:
            capath = capath.encode('utf-8')
        self._ctx.load_verify_locations(cafile, capath=capath)
        if cadata is not None:
            self._ctx.load_verify_locations(BytesIO(cadata=cadata))

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        self._ctx.load_cert_chain(certfile, keyfile=keyfile, password=password)

    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True, suppress_ragged_eofs=True,
                    server_hostname=None):

        # turn off do_handshake_on_connect, so we can set SNI.
        # Manually do handshake below instead.
        cnx = self._ctx.wrap_socket(sock, server_side=server_side,
                                do_handshake_on_connect=False,
                                suppress_ragged_eofs=suppress_ragged_eofs)

        if isinstance(server_hostname, six.text_type):  # Platform-specific: Python 3
            server_hostname = server_hostname.encode('utf-8')

        # set SNI hostname
        if server_hostname is not None:
            cnx.use_sni(server_hostname)

        # do handshake
        while True:
            try:
                cnx.do_handshake()
            except wolfssl.SSLWantReadError:
                if not util.wait_for_read(sock, sock.gettimeout()):
                    raise timeout('select timed out')
                continue
            except wolfssl.SSLError as e:
                raise ssl.SSLError('bad handshake: %r' % e)
            break

        return WrappedSocket(cnx, sock)

