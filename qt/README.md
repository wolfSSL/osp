# wolfSSL Support for Qt 5.15
## Building
Requirements:
* Linux environment - this version was tested on 20.04.2 LTS (GNU/Linux 5.4.0-67-generic x86_64)
* See https://wiki.qt.io/Building_Qt_5_from_Git for a full list of requirements for building Qt

### Building wolfSSL
1. Clone wolfSSL Library:
```
git clone https://github.com/wolfssl/wolfssl.git
```
2. Configure wolfSSL with Qt:
```
cd wolfssl
./autogen.sh
./configure --enable-qt --enable-qt-test --enable-alpn --enable-rc2 --prefix=/path/to/wolfssl-install\
 CFLAGS="-DWOLFSSL_ERROR_CODE_OPENSSL -DWOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS=0x1b"

Note :
WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS=0x1b is to be compliant with OpenSSL by Or'ed the following flags:
LOAD_FLAG_IGNORE_ERROR, LOAD_FLAG_DATE_ERR_OKAY, LOAD_FLAG_IGNORE_BAT_PATH_ERR and \
LOAD_FLAG_IGNORE_ZEROFILE
```
3. Build and install:
```
make
make install
```
4. Export wolfSSL library for linking:
```
export WOLFSSL_LIBS="-L/path/to/wolfssl-install/lib -lwolfssl"
```

5. Add wolfSSL install path to LD_LIBRARY_PATH
```
Depending on the environment, adding wolfSSL install path to LD_LIBRARY_PATH
LD_LIBRARY_PATH=/path/to/wolfssl\install/lib:$LD_LIBRARY_PATH
```

### Building Qt 5.15 with wolfSSL

1. Clone Qt library from base directory:
```
git clone git://code.qt.io/qt/qt5.git --branch v5.15.x
```

2. Checkout Qt version and init repository:
```
cd qt5
./init-repository --module-subset=qtbase
```

3. Apply patch to Qt5
```
wget https://raw.githubusercontent.com/wolfSSL/osp/master/qt/wolfssl-qt-515.patch
cd qtbase
git apply -v ../wolfssl-qt-515.patch
```
4. Add unit test program(Optional):

   4-1. Clone the OSP repository to get unit test program
   ```
   git clone https://github.com/wolfssl/osp.git /path/to/clone-osp-folder
   ```
   4-2. Download patch and get unit test program
   ```
   cd /path/to/qt5
   wget https://raw.githubusercontent.com/wolfSSL/osp/master/qt/wolfssl-qt-515-unit-test.patch
   ```
   4-3. Apply patch
   ```
   cd qtbase
   git apply -v ../wolfssl-qt-515_unit_test.patch
   ```
   4-4. Copy certs in wolfssl certs folder to qssl_wolf certs folder
   This step is needed to avoid certificate-expiration issues during unit testing.
   ```
   copy ca-cert.pem, client-cert.pem and server-cert.pem files from \
        /path/to/wolfssl/certs/ to /path/to/osp/qt/qssl_wolf/certs folder
   ```
   4-5. Copy unit test folder and certificate files
   ```
   copy /path/to/osp-repo/qt/qssl_wolf folder to /path/to/qt5/qtbase/tests/auto/network/ssl
   copy crt, key and pem files from /path/to/qt5/qtbase/tests/auto/network/ssl/qsslsocket/certs to \
        /path/to/qt5/qtbase/tests/auto/network/ssl/qssl_wolf/certs folder
   ```
5. Configure Qt5
```
cd ../../
mkdir build
cd ./build
../qt5/configure -opensource -wolfssl-linked -confirm-license -ccache -no-pch -developer-build \
-I/path/to/wolfssl-install/include/wolfssl -I/path/to/wolfssl-install/include
```

6. Build and install
```
make -j4
```

## Running tests

### To run all tests:
```
make check
```

### SSL unit tests

The Qt SSL unit tests can be found from the root qt5 directory:

`qt5/qtbase/tests/auto/network/ssl/`

To run a single SSL test (i.e. qsslcipher) from the test ssl directory:
```
./qsslcipher
```

#### wolfSSL unit test
When you set up wolfSSL unit test, please prepare the following step before it runs:
1. Prepare a PC to run OpenSSL command
2. Copy server-cert.pem and server-key.pem in qssl_wolf folder to the PC
3. Change target IP address in qssl_wolf/tst_wolfssl.cpp to the PC
```
QString tst_QSslWolfSSL::EXAMPLE_SERVER = "xxx.xxx.xxx.xxx";
Note:Please specify IP address except "127.0.0.1". The IP address causes test failures.
```
4. Launch OpenSSL on the PC with the following options:
```
$ openssl s_server -accept 11111 -key /path/to/server-key.pem -cert /path/to/server-cert.pem -WWW
```
5. Go to /path/to/qtbase/tests/auto/network/ssl/
```
make check -C qssl_wolf
```