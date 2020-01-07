# wolfSSL Supoort for Qt 5.12
## Building
Requirements:
* Linux environment - this version was tested on Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-62-generic x86\_64)
* See https://wiki.qt.io/Building\_Qt\_5\_from\_Git for a full list of requirements for building Qt

### Building wolfSSL
1. Clone wolfSSL Library:
```
git clone https://github.com/wolfssl/wolfssl.git
```
2. Configure wolfSSL with Qt:
```
cd wolfssl
./autogen.sh
./configure --enable-qt --enable-qt-test --prefix="/path/to/wolfssl-install"
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

###Building Qt 5.12 with wolfSSL

1. Clone Qt library from base directory:
```
git clone git://code.qt.io/qt/qt5.git
```

2. Checkout Qt version and init repository:
```
cd qt5
git checkout 5.13
perl init-repository
```

3. Apply patch:
```
cd qtbase
git apply -v ../../wolfssl-qt-513.patch
```

4. Configure:
```
./configure -wolfssl-linked -developer-build -opensource -confirm-license \
    -I/path/to/wolfssl-install/include/wolfssl -I/path/to/wolfssl-install/include
```

5. Build and install
```
make -j4
```


##Running tests

###To run all tests:
```
make check
```

###SSL unit tests

The Qt SSL unit tests can be found from the root qt5 directory: `qt5/qtbase/tests/auto/network/ssl/`

To run a single SSL test (i.e. qsslcipher) from the test ssl directory:
```
./qsslcipher
```
