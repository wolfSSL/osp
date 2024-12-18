# Building pyOpenSSL with wolfSSL
+ It's recommended that you do the following steps using a Python virtual environment. Create it with `python -m venv /path/to/new/virtual/environment` and activate it with `source /path/to/new/virtual/environment/bin/activate`.
+ Clone wolfssl-py with `git clone git@github.com:wolfSSL/wolfssl-py.git`. `cd wolfssl-py`.
+ Build and install wolfssl-py with `pip install .`.
+ Download pyOpenSSL 19.0.0 with `curl -O https://files.pythonhosted.org/packages/40/d0/8efd61531f338a89b4efa48fcf1972d870d2b67a7aea9dcf70783c8464dc/pyOpenSSL-19.0.0.tar.gz`.
+ Extract the code with `tar xvf pyOpenSSL-19.0.0.tar.gz`. `cd pyOpenSSL-19.0.0`.
+ Apply the pyopenssl-19.0.0.patch file with `patch -p1 < pyopenssl-19.0.0.patch` (assuming the patch file is in the pyopenssl-19.0.0 directory; adjust the path according to your situation). This patch adds wolfSSl support.
+ Install pyOpenSSL with `pip install .`. At this time, only portions of pyOpenSSL have been ported to work with wolfSSL. Specifically, we've ported the parts used by the module ndg_httpsclient. The next section covers running the ndg_httpsclient unit tests.

# Testing
+ Download ndg_httpsclient 0.5.1 with `curl -O https://files.pythonhosted.org/packages/b9/f8/8f49278581cb848fb710a362bfc3028262a82044167684fb64ad068dbf92/ndg_httpsclient-0.5.1.tar.gz`.
+ Extract the code with `tar xvf ndg_httpsclient-0.5.1.tar.gz`. `cd ndg_httpsclient-0.5.1`.
+ Patch ndg_httpsclient to update the test certs and keys with `patch -p1 < ndg_httpsclient-0.5.1.patch` (assuming the patch file is in the ndg_httpsclient-0.5.1 directory; adjust the path according to your situation). This patch doesn't modify the core ndg_httpsclient code; it just makes the test assets usable.
+ Start the test server in the background using the provided script. First, `cd ndg/httpsclient/test/`. Then, `./scripts/openssl_https_server.sh > server.log 2>&1 &`
+ `cd ../../..` to get back to the root directory.
+ Run the tests (all should pass):
    + `python -m ndg.httpsclient.test.test_https`.
    + `python -m ndg.httpsclient.test.test_urllib2`.
    + `python -m ndg.httpsclient.test.test_utils`.
+ Make sure to kill the server that was launched in the background when done testing.
