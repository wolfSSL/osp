This patch is for Python version 3.8.5 which can be downloaded from Python's
webpage here
https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tar.xz

curl -O https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tar.xz

To build wolfSSL for use with Python 3.8.5, see the simple script
combine_wolfssl.sh used to pull together the correct wolfSSL sources, configure,
and compile the library. This script will not be used after the final port has
been complete, but is used for development/testing in the meantime.

combine_wolfssl.sh

1.  Clones wolfssl/master to directory wolfssl-master
2.  Adds current outstanding PR's
4.  Configures and compiles the library if all patches are successful,
    note that patches can fail and all code will still be applied. Often a fail
    case is just re-applying of code causing a non 0 return.

The script uses the below configuration for wolfSSL:

$ cd wolfssl-master
$ ./configure --enable-opensslall --enable-tls13 --enable-tlsx --enable-tlsv10 --enable-postauth --enable-certext --enable-certgen --enable-debug CFLAGS="-DHAVE_EX_DATA -DWOLFSSL_ERROR_CODE_OPENSSL -DHAVE_SECRET_CALLBACK -DWOLFSSL_PYTHON -DWOLFSSL_ALT_NAMES -DWOLFSSL_SIGNER_DER_CERT"
$ make check
$ sudo make install

To build Python-3.8.5 with wolfSSL enabled:

$ cd Python-3.8.5
$ ./configure --with-wolfssl=/usr/local
$ make

To run all Python-3.8.5 tests:

$ make test

Or, to run a specific test in verbose mode:

$ make test TESTOPTS="-v test_ssl"


Test Notes
-------------------------------------------------------------------------------

test_site:
    There is one skipped test:

    test_license_exists_at_url (test.test_site.ImportSideEffectTests) ... skipped 'system does not contain necessary certificates'

    This is skipped because wolfSSL does not automatically load system root
    CA certs like OpenSSL does when the following function is called:

    SSL_CTX_set_default_verify_paths()

    We may/may not need to implement this. Will need further research on how
    apps are calling Python SSL APIs, if they expect this default verify
    behavior to work.

test_ssl:

    - test_unwrap is skipped due to differences in read ahead behavior on
      shutdown

    - various error message differens accounted for in the tests. for example
      "ASN no signer error to confirm failure" in wolfSSL versus
      "certificate verify failed" in OpenSSL

    - wolfSSL does not support cipher suite rules i.e !NULL

