## xmlsec 1.2.42

xmlsec1 1.2.42 (XML Security Library) with its OpenSSL backend
(`libxmlsec1-openssl` and the `xmlsec1` tool) on the wolfSSL OpenSSL
compatibility layer. All changes in `xmlsec1-1.2.42.patch` are under
`OPENSSL_IS_WOLFSSL`. Tested on Ubuntu 24.04 x86_64 (GCC 13, libxml2 2.9.14,
libxslt 1.1.39).

## Build Instructions

### Build wolfSSL
+ wolfSSL master does not have all the compatibility fixes xmlsec needs yet.
  Build wolfSSL from https://github.com/wolfSSL/wolfssl/pull/12041 (tested at
  commit 130c52a015).
+ Configure wolfSSL with `./configure --enable-all`. On x86_64 also add
  `--enable-aesni`. To run the xmlsec test suite, see Testing below.
+ Compile with `make`.
+ Install wolfSSL into /usr/local with `sudo make install`.

### Build xmlsec
+ Download xmlsec 1.2.42 with
  `curl -fLO https://github.com/lsh123/xmlsec/releases/download/xmlsec-1_2_42/xmlsec1-1.2.42.tar.gz`
  (sha256 `5359e3c19016ab164b505c1222ef5a2d87b34f50f85ff91d765f4aaa0df42db2`).
+ Unarchive it with `tar xf xmlsec1-1.2.42.tar.gz` and cd into xmlsec1-1.2.42.
+ Patch the source code with `patch -p1 < xmlsec1-1.2.42.patch`, adjusting the
  path to the patch file accordingly.
+ The patch changes `configure.ac`. Regenerate `configure` with
  `autoreconf -fi` (needs autoconf, automake, libtool and pkg-config).
+ Configure xmlsec with
  ```
  OPENSSL_CFLAGS="-I/usr/local/include -I/usr/local/include/wolfssl -DWOLFSSL_USE_OPTIONS_H" \
  OPENSSL_LIBS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib -lwolfssl" \
  ./configure --with-default-crypto=openssl --without-nss --without-gnutls \
      --without-gcrypt
  ```
  Configure prints `openssl version 'wolfSSL'` and `RIPEMD-160 support...
  disabled`: wolfSSL `EVP_ripemd160()` is a stub.
+ Compile with `make` and install with `sudo make install`.

## Testing
+ The test suite uses a 512-bit RSA CA, MD5-signed certificates and
  certificates with serial number 0, and it generates 1024-bit RSA keys. To run
  it, add
  `CFLAGS="-DWOLFSSL_MIN_RSA_BITS=512 -DRSA_MIN_SIZE=1024 -DWOLFSSL_ASN_ALLOW_0_SERIAL -DWOLFSSL_ALLOW_MD5_CERT_SIGS"`
  to the wolfSSL configure line. These only relax limits for the legacy test
  data; leave them out of production builds.
+ `make check` stops at the first failing script, so run
  `make check-keys`, `make check-dsig` and `make check-enc`.
+ Expected totals (OK / failed / skipped): testKeys 7/0/0, testDSig 169/32/11,
  testEnc 497/0/0.
+ The 32 failed testDSig steps are 16 DSA tests that load a DSA private key
  from PKCS#12 or PKCS#8. wolfSSL `PKCS12_parse()` only handles RSA and ECC
  keys, and wolfSSL does not load DSA keys from PKCS#8.
+ The skipped tests use gost and MD5 transforms (off in xmlsec by default) and
  RIPEMD-160.

## Notes
+ With wolfSSL, do not share a keys manager or X509 store between threads:
  wolfSSL RSA keys keep per-operation state, and `X509_verify_cert()` changes
  the store.
+ There is no password prompt: wolfSSL does not build `EVP_read_pw_string()`.
  Give the password of an encrypted key with `--pwd` or a password callback.
+ Pass trusted certificates explicitly (`--trusted-pem`, `--trusted-der` or
  `xmlSecCryptoAppKeysMngrCertLoad()`). Only the first certificate of a
  `$SSL_CERT_FILE` bundle is loaded, and no system CA is trusted when neither
  `$SSL_CERT_FILE` nor `$SSL_CERT_DIR` is set.
+ wolfSSL has no implicit rejection for RSA PKCS#1 v1.5 decryption, so the
  `rsa-1_5` key transport reveals bad padding. Use `rsa-oaep-mgf1p`.
+ DSA private keys load only in the traditional PEM or DER format, not from
  PKCS#8 or PKCS#12.
