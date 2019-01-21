# -*- coding: utf-8 -*-
import os
import sys
import unittest

import mock
import pytest

def setup_module():
    try:
        from urllib3.contrib.wolfssl import inject_into_urllib3
        inject_into_urllib3()
    except ImportError as e:
        pytest.skip('Could not import wolfssl: %r' % e)


def teardown_module():
    try:
        from urllib3.contrib.wolfssl import extract_from_urllib3
        extract_from_urllib3()
    except ImportError:
        pass


from ..with_dummyserver.test_https import TestHTTPS, TestHTTPS_TLSv1  # noqa: F401
from ..with_dummyserver.test_socketlevel import (  # noqa: F401
    TestSNI, TestSocketClosing, TestClientCerts
)

