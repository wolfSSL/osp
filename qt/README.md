# wolfSSL Support for Qt 5.15.18

## Building

Requirements:

* Linux environment - this version was tested on 22.04 LTS on WSL2
* See https://wiki.qt.io/Building_Qt_5_from_Git for a full list of requirements for building Qt

### Building wolfSSL

1. Clone wolfSSL Library:

```bash
git clone https://github.com/wolfssl/wolfssl.git
```

1. Configure wolfSSL with Qt:

```bash
cd wolfssl
./autogen.sh
./configure --enable-qt --enable-qt-test --enable-alpn --enable-rc2 --prefix=/path/to/wolfssl-install \
 CFLAGS="-DWOLFSSL_ERROR_CODE_OPENSSL -DWOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS=0x1b -DOPENSSL_COMPATIBLE_DEFAULTS -DWC_DISABLE_RADIX_ZERO_PAD -DALLOW_INVALID_CERTSIGN -DWOLFSSL_NO_ASN_STRICT"
```

Note:

* `WOLFSSL_LOAD_VERIFY_DEFAULT_FLAGS=0x1b` is to be compliant with OpenSSL by Or'ed the following flags:
  `LOAD_FLAG_IGNORE_ERROR`, `LOAD_FLAG_DATE_ERR_OKAY`, `LOAD_FLAG_IGNORE_BAT_PATH_ERR` and `LOAD_FLAG_IGNORE_ZEROFILE`
* **`-DWOLFSSL_NO_ASN_STRICT` is required to make `qsslcertificate` and `qssl_wolf` tests passed.**
  wolfSSL treats a certificate serial number of 0 as an error. There are some certificates with serial number 0 in the Qt repo.
* **`-DALLOW_INVALID_CERTSIGN` is required to make `qsslcertificate` tests passed.**
  wolfSSL v5.6.4+ enforces RFC 5280 section 4.2.1.9, which prohibits a certificate with `CA:FALSE` from having the `keyCertSign` bit set. Qt's test certificate `test-ocsp-good-cert.pem` violates this rule, so this flag is needed to bypass that check.
* **`-DWC_DISABLE_RADIX_ZERO_PAD` is required to match OpenSSL's hex string output format.**
  wolfSSL by default zero-pads big integer hex strings to an even number of digits (byte boundary alignment), whereas OpenSSL does not. This causes mismatches when Qt tests compare certificate serial numbers or key parameter values as hex strings. This flag disables the zero-padding to match OpenSSL's behavior.

1. Build and install:

```bash
make
make install
```

1. Export wolfSSL library for linking:

```bash
export WOLFSSL_LIBS="-L/path/to/wolfssl-install/lib -lwolfssl"
```

1. Add wolfSSL install path to LD_LIBRARY_PATH:

```bash
LD_LIBRARY_PATH=/path/to/wolfssl-install/lib:$LD_LIBRARY_PATH
```

### Building Qt 5.15.18 with wolfSSL

1. Clone Qt library from base directory:

```bash
git clone git://code.qt.io/qt/qt5.git --branch v5.15.18-lts-lgpl
```

1. Checkout Qt version and init repository:

```bash
cd qt5
./init-repository --module-subset=qtbase
```

1. Apply patch to Qt5:

```bash
wget https://raw.githubusercontent.com/wolfSSL/osp/master/qt/wolfssl-qt-51518-full.patch
cd qtbase
git apply -v ../wolfssl-qt-51518-full.patch
```

1. Add unit test program (Optional):

   4-1. Clone the OSP repository to get unit test program:

   ```bash
   git clone https://github.com/wolfssl/osp.git /path/to/clone-osp-folder
   ```

   4-2. Copy certs in wolfssl certs folder to qssl_wolf certs folder.
   This step is needed to avoid certificate-expiration issues during unit testing.

   ```bash
   cp /path/to/wolfssl/certs/{ca-cert.pem,client-cert.pem,server-cert.pem} \
      /path/to/osp/qt/qssl_wolf/certs/
   ```

   4-3. Copy unit test folder and certificate files:

   ```bash
   cp -r /path/to/osp-repo/qt/qssl_wolf /path/to/qt5/qtbase/tests/auto/network/ssl/
   cp /path/to/qt5/qtbase/tests/auto/network/ssl/qsslsocket/certs/*.{crt,key,pem} \
      /path/to/qt5/qtbase/tests/auto/network/ssl/qssl_wolf/certs/
   ```

1. Configure Qt5:

```bash
cd ../..
mkdir build
cd build
../qt5/configure -opensource -wolfssl-linked -confirm-license -ccache -no-pch -developer-build \
-I/path/to/wolfssl-install/include/wolfssl -I/path/to/wolfssl-install/include
```

1. Build and install:

```bash
make -j4
```

## Running tests

### To run all tests

```bash
make check
```

### SSL unit tests

The Qt SSL unit tests can be found from the root qt5 directory:

`qt5/qtbase/tests/auto/network/ssl/`

To run a single SSL test (i.e. qsslcipher) from the test ssl directory:

```bash
./qsslcipher
```

### wolfSSL unit test

When you set up wolfSSL unit test, please prepare the following steps before it runs:

1. Prepare a PC to run OpenSSL command.
1. Copy `server-cert.pem` and `server-key.pem` in `qssl_wolf` folder to the PC.
1. Change target IP address in `qssl_wolf/tst_wolfssl.cpp` to the PC:

```cpp
QString tst_QSslWolfSSL::EXAMPLE_SERVER = "xxx.xxx.xxx.xxx";
// Note: Please specify IP address except "127.0.0.1". That address causes test failures.
```

1. Launch OpenSSL on the PC with the following options:

```bash
openssl s_server -accept 11111 -key /path/to/server-key.pem -cert /path/to/server-cert.pem -WWW
```

1. Go to `/path/to/qtbase/tests/auto/network/ssl/` and run:

```bash
make check -C qssl_wolf
```
