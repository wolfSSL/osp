This patch is for Python version 3.8.5 which can be downloaded from Python's
webpage here
https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tar.xz

curl -O https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tar.xz

To build wolfSSL for use with Python 3.8.5, see the simple script
build_wolfssl_master.sh which can be used to build wolfSSL sources, configure,
and compile the library using the current wolfssl master branch code.

build_wolfssl.sh

1.  Clones wolfssl/master to directory wolfssl-master
2.  Configures and compiles the library

The script uses the below configuration for wolfSSL:

$ cd wolfssl-master
$ ./configure --enable-opensslall --enable-tls13 --enable-tlsx --enable-tlsv10 --enable-postauth --enable-certext --enable-certgen --enable-scrypt --enable-debug CFLAGS="-DHAVE_EX_DATA -DWOLFSSL_ERROR_CODE_OPENSSL -DHAVE_SECRET_CALLBACK -DWOLFSSL_PYTHON -DWOLFSSL_ALT_NAMES -DWOLFSSL_SIGNER_DER_CERT"
$ make check

After compiling wolfSSL, install:

$ sudo make install

To build Python-3.8.5 with wolfSSL enabled:

$ tar xvf Python-3.8.5.tar.xz
$ cd Python-3.8.5
$ patch -p1 < wolfssl-python-3.8.5.patch
$ autoreconf -fi
$ ./configure --with-wolfssl=/usr/local
$ make

If you see an error similar to the following when running make:

*** WARNING: renaming "_ssl" since importing it failed: libwolfssl.so.30:
cannot open shared object file: No such file or directory

You may need to add your wolfSSL installation location to the library
search path and re-run make:

$ export LD_LIBRARY_PATH=/usr/local/lib
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

test_ssl:

    - test_unwrap is skipped due to differences in read ahead behavior on
      shutdown

    - various error message differences accounted for in the tests. for example
      "ASN no signer error to confirm failure" in wolfSSL versus
      "certificate verify failed" in OpenSSL

    - wolfSSL does not support cipher suite rules i.e !NULL

    - At the end of the test suite some dangling threads from tests are reported

test_nntplib:

    - The following two tests fail without wolfSSL, and as such also fail
      with wolfSSL:
          test_descriptions
          test_description

