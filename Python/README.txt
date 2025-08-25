# Python OSP Patches

# Known Limitations / Differences

- Can not load DER certificates with ctx.load_verify_locations, as seen in test test_load_verify_cadata
- set cipher lists does not handle AES256/AES128/AESGCM string types for a generic way to add all AES suites
- WOLFSSL_CTX session stats such as number of accept's or hits is not incremented and returns 0
- wolfSSL by default has TLS 1.1 and 1.0 off (seen with test test_options)

# 3.8.5 Patch

This patch is for Python version 3.8.5 which can be downloaded from Python's
webpage here
https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tar.xz

curl -O https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tar.xz

To build wolfSSL for use with Python 3.8.5, see the simple script
build_wolfssl.sh which can be used to build wolfSSL sources, configure,
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


# 3.8.14 Patch

This patch is for Python version 3.8.14. Follow these steps to download
and build python 3.8.14 with wolfssl enabled. This requires that wolfssl
has been built similarly as for the 3.8.5 patch instructions.

Note, you may need to update your LD_LIBRARY_PATH first:
$ export LD_LIBRARY_PATH=/usr/local/lib

$ wget https://www.python.org/ftp/python/3.8.14/Python-3.8.14.tar.xz
$ tar xvf Python-3.8.14.tar.xz
$ cd Python-3.8.14
$ patch -p1 < ../wolfssl-python-3.8.14.patch
$ ./configure --with-wolfssl=/usr/local
$ make

Run the ssl tests with:
$ make test TESTOPTS="-v test_ssl"

# 3.12 Patches

These patches are for the Python versions 3.12.6, 3.12.9 and 3.12.11, which can
be downloaded from

https://www.python.org/ftp/python/3.12.6/Python-3.12.6.tar.xz
https://www.python.org/ftp/python/3.12.9/Python-3.12.9.tar.xz
https://www.python.org/ftp/python/3.12.11/Python-3.12.11.tar.xz

To build wolfSSL for use with one of these versions, see the simple script
build_wolfssl_py312.sh which can be used to build wolfSSL sources, configure,
and compile the library using the current wolfssl master branch code.

build_wolfssl_py312.sh is identical to build_wolfssl.sh, aside from some
variations in the configuration options. In particular, it uses the following
configuration for wolfSSL:

$ cd wolfssl-master
$ ./configure --enable-opensslall --enable-tls13 --enable-tlsx --enable-tlsv10 --enable-postauth --enable-certext --enable-certgen --enable-scrypt --enable-sessioncerts --enable-crl CFLAGS="-DHAVE_EX_DATA -DWOLFSSL_ERROR_CODE_OPENSSL -DHAVE_SECRET_CALLBACK -DWOLFSSL_PYTHON -DWOLFSSL_ALT_NAMES -DWOLFSSL_SIGNER_DER_CERT -DNO_INT128"
$ make check

After compiling wolfSSL, install:

$ sudo make install

To build Python-3.12.6 with wolfSSL enabled:

$ tar xvf Python-3.12.6.tar.xz
$ cd Python-3.12.6
$ patch -p1 < wolfssl-python-3.12.6.patch
$ autoreconf -fi
$ ./configure --with-wolfssl=/usr/local
$ make

To build Python-3.12.9 with wolfSSL enabled:

$ tar xvf Python-3.12.9.tar.xz
$ cd Python-3.12.9
$ patch -p1 < wolfssl-python-3.12.9.patch
$ autoreconf -fi
$ ./configure --with-wolfssl=/usr/local
$ make

To build Python-3.12.11 with wolfSSL enabled:

$ tar xvf Python-3.12.11.tar.xz
$ cd Python-3.12.11
$ patch -p1 < wolfssl-python-3.12.11.patch
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

To run all Python tests:

$ make test

Or, to run a specific test in verbose mode:

$ make test TESTOPTS="-v test_ssl"
