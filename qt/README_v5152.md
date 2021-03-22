# wolfSSL Support for Qt 5.15.2
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
 CFLAGS="-DWOLFSSL_ERROR_CODE_OPENSSL"
```
3. Build and install:
```
make
make install
```
4. export wolfSSL library for linking:
```
export WOLFSSL_LIBS="-L/path/to/wolfssl-install/lib -lwolfssl"
```

### Building Qt 5.15 with wolfSSL

1. Clone Qt library from base directory:
```
git clone git://code.qt.io/qt/qt5.git --branch v5.15.2 
```

2. Checkout Qt version and init repository:
```
cd qt5
./init-repository --module-subset=qtbase
```

3. Apply patch:
```
wget https://raw.githubusercontent.com/wolfSSL/osp/master/qt/wolfssl-qt-5152.patch
cd qtbase
git apply -v ../wolfssl-qt-5152.patch
```

4. Configure:
```
cd ../../
mkdir build
cd ./build
../qt5/configure -commercial -wolfssl-linked -confirm-license -ccache -no-pch -developer-build \
-I/path/to/wolfssl-install/include/wolfssl -I/path/to/wolfssl-install/include
```

5. Build and install
```
make -j4
```

## Running tests

### To run all tests:
```
make check
```

### SSL unit tests

The Qt SSL unit tests can be found from the root qt5 directory: `qt5/qtbase/tests/auto/network/ssl/`

To run a single SSL test (i.e. qsslcipher) from the test ssl directory:
```
./qsslcipher
```
