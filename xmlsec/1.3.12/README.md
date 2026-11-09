## xmlsec 1.3.12

xmlsec1 1.3.12 (XML Security Library) with its OpenSSL backend
(`libxmlsec1-openssl` and the `xmlsec1` tool) on the wolfSSL OpenSSL
compatibility layer. All C changes in `xmlsec1-1.3.12.patch` are under
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
+ Download xmlsec 1.3.12 with
  `curl -fLO https://github.com/lsh123/xmlsec/releases/download/1.3.12/xmlsec1-1.3.12.tar.gz`
  (sha256 `24045199af12d93fe5fdbbbf7e386e823e4842071e9432e2b90ac108b889a923`).
+ Unarchive it with `tar xf xmlsec1-1.3.12.tar.gz` and cd into xmlsec1-1.3.12.
+ Patch the source code with `patch -p1 < xmlsec1-1.3.12.patch`, adjusting the
  path to the patch file accordingly.
+ The patch changes `configure.ac`. Regenerate `configure` with
  `autoreconf -fi` (needs autoconf, automake, libtool and pkg-config).
+ Configure xmlsec with
  ```
  OPENSSL_CFLAGS="-I/usr/local/include -I/usr/local/include/wolfssl -DWOLFSSL_USE_OPTIONS_H" \
  OPENSSL_LIBS="-L/usr/local/lib -Wl,-rpath,/usr/local/lib -lwolfssl" \
  CPPFLAGS="-DNO_OLD_WC_NAMES" \
  ./configure --with-default-crypto=openssl --without-nss --without-gnutls \
      --without-gcrypt
  ```
  `-DNO_OLD_WC_NAMES` hides wolfCrypt's old type names (`Sha256` for
  `wc_Sha256`, ...), which clash with xmlsec's digest names. It only removes
  name macros, not wolfSSL features. Configure prints
  `openssl version 'wolfSSL'` and `DH support... disabled`. Do not enable
  RIPEMD-160 (off by default): wolfSSL `EVP_ripemd160()` is a stub.
+ Compile with `make` and install with `sudo make install`.

## Testing
+ The test suite uses a 512-bit RSA CA, MD5-signed certificates and
  certificates with serial number 0, and it generates 1024-bit RSA keys. To run
  it, add
  `CFLAGS="-DWOLFSSL_MIN_RSA_BITS=512 -DRSA_MIN_SIZE=1024 -DWOLFSSL_ASN_ALLOW_0_SERIAL -DWOLFSSL_ALLOW_MD5_CERT_SIGS"`
  to the wolfSSL configure line. These only relax limits for the legacy test
  data; leave them out of production builds.
+ `make check` stops at the first failing script, so run
  `make check-unit-tests`, `make check-keys`, `make check-dsig` and
  `make check-enc`.
+ Expected totals (OK / failed / skipped): unit tests 194/0, testKeys 33/5/20,
  testDSig 399/38/42, testEnc 666/0/66.
+ All failed steps use DSA keys. The 5 failed testKeys steps and 38 failed
  testDSig steps (19 tests) load a DSA private key from PKCS#12 or PKCS#8.
  wolfSSL `PKCS12_parse()` only handles RSA and ECC keys, and wolfSSL does
  not load DSA keys from PKCS#8.
+ Skipped with wolfSSL only: Camellia, DH and the key derivations (ConcatKDF,
  PBKDF2, HKDF, so also ECDH-ES and DH-ES), which xmlsec has only for the
  OpenSSL 3 `EVP_KDF` API. The other tests are skipped with OpenSSL 3.0 too.

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
+ EC keys on non-NIST curves (brainpool, secp256k1) work only in the SEC1
  format. From PKCS#8 or PKCS#12 wolfSSL loads them on the NIST curve of the
  same size, and their signatures do not verify.
+ wolfSSL `X509_NAME` drops attributes with unknown OIDs, and
  `X509_NAME_cmp()` compares the one-line name, so CAs whose names differ only
  there, or in a value with '/', look the same to xmlsec. A CRL in the
  document can then be matched to the wrong CA and ignored, and a CRL from
  `--crl-pem` or `--crl-der` can be shadowed by a newer one of the other CA.
  Do not trust such CAs or rely on CRLs in the document. Load CRLs with
  `--verify-crls`, which fails closed.
+ A '#hex' value in `X509SubjectName` or `X509IssuerName` matches the raw value
  bytes; with OpenSSL 3.0 such a name finds no certificate. The certificate is
  still verified.
+ PKCS#12 files with malformed bag attributes load without the attribute;
  OpenSSL rejects them.
