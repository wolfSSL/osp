# Unix Build Instructions

## Build wolfSSL
+ Configure wolfSSL with `./configure --enable-stunnel`. Add `--enable-debug` if you want to enable the debug version of wolfSSL.
+ Compile with `make`.
+ Install wolfSSL into /usr/local with `sudo make install`.

## Build stunnel
+ Download stunnel 5.71 with `curl -O https://www.stunnel.org/archive/5.x/stunnel-5.71.tar.gz`.
+ Unarchive stunnel-5.71.tar.gz with `tar xvf stunnel-5.71.tar.gz`. cd into stunnel-5.71.
+ Patch the source code with `patch -p1 < stunnel-5.71.patch`, adjusting the path to the patch file accordingly.
+ Regenerate the configure script with `autoreconf -fi`.
+ Configure stunnel with `./configure --enable-wolfssl`.
    + wolfSSL is expected in `/usr/local`. Use `--with-ssl=DIR` to point at a
      different installation prefix.
    + Add `--enable-wolfssldebug` to route the wolfSSL debug log into the
      stunnel log. This requires wolfSSL built with `--enable-debug`.
+ Compile with `make`.
+ Install stunnel into /usr/local with `sudo make install`.

Building without `--enable-wolfssl` still produces a regular OpenSSL build.
`configure` fails early with a clear message if wolfSSL cannot be found.

## Build for Windows (MinGW)
+ Build wolfSSL as a DLL and install it into `/opt/wolfssl_dll`, or set
  `win32_ssl_dir` to its prefix.
+ Configure stunnel with `--enable-wolfssl`, then run `make mingw` (32-bit) or
  `make mingw64` (64-bit). Both targets use `src/mingw_wolfssl.mk`, which
  carries the same hardening flags as the upstream `src/mingw.mk`.

# Run the tests
+ Run the test suite with `make check`. All of the tests either pass or are skipped (see below).
+ This patch also adds the ability to run a single test plugin. To do this, run the test like this `python maketest.py --plugin p13_resume`.

Verified against stunnel 5.71 and wolfSSL 5.9.2 on x86_64 Linux:

```
wolfSSL:  succeeded: 46  failed: 0  skipped: 8
OpenSSL:  succeeded: 50  failed: 0  skipped: 4
```

# Differences from the OpenSSL build

## OCSP
stunnel's own OCSP client and OCSP stapling implementation (`src/ocsp.c`) is
not compiled with wolfSSL. Instead, the `OCSP` and `OCSPaia` options are mapped
onto wolfSSL's built-in OCSP client (`wolfSSL_CTX_SetOCSP_OverrideURL()` and
`wolfSSL_CTX_EnableOCSP()`), which performs the status check inside the
handshake. Consequences:

+ TLS-level OCSP stapling is not available in either client or server mode.
  `SSL_set_tlsext_status_type()` and `SSL_CTX_set_tlsext_status_cb()` require
  wolfSSL built with `--enable-ocspstapling`, and wolfSSL does not verify a
  stapled response on stunnel's behalf.
+ The OCSP verdict is reported by wolfSSL as a certificate verification error
  (`Invalid OCSP Status Error`) rather than through stunnel's `OCSP:` log
  messages.
+ `OCSPnonce` and `OCSPflag` are accepted but have no effect, because wolfSSL
  drives the responder exchange itself. stunnel logs a notice when either is
  set in a wolfSSL build.
+ `OCSP` and `OCSPaia` are mutually exclusive, since wolfSSL selects the
  responder either from the override URL or from the AIA extension, not both.
  Setting both is a configuration error.
+ wolfSSL's built-in HTTP client requires a responder that returns a complete
  HTTP response header. The Python OCSP responder used by the stunnel test
  suite sends neither `Content-Length` nor `Content-Type`, so wolfSSL rejects
  it with `wolfIO_HttpProcessResponse header ended early`.

For these reasons the four `p27_ocsp` tests (271-274) are skipped in a wolfSSL
build. They still run, and pass, in an OpenSSL build.

## FIPS
The four FIPS tests (101, 111-113) are skipped because the OpenSSL FIPS
provider is not available. The wolfSSL `fips_cipher_list` default is therefore
not exercised by the suite; treat it as untested until the port is run against
a FIPS-validated wolfSSL.

## Changes that also apply to an OpenSSL build
A few hunks of this patch are not guarded by `WITH_WOLFSSL` and so affect a
plain `./configure` build too:

+ `SSL_get_ex_data()` NULL guards in the PSK, session, ticket-key, SNI and
  session-cache callbacks. These previously crashed; they now fail closed.
  `verify_callback()` rejects the peer and logs an internal error.
+ `cb_dup_addr()` returns success instead of dereferencing a NULL source.
+ `SSL_get_SSL_CTX()` is called through a cast that discards `const`.

## Ciphers
wolfSSL does not implement the OpenSSL cipher string syntax, so the default
`ciphers` value is `DEFAULT` instead of `HIGH:!aNULL:!SSLv2:!DH:!kDHEPSK`
(and `FIPS:!DH:!kDHEPSK` in FIPS mode). Set `ciphers` explicitly if you need
to restrict the cipher list. The TLS 1.3 `ciphersuites` value is unchanged.

## CRL
CRLs are loaded through the OpenSSL compatibility layer
(`X509_load_crl_file()`), which defers signature verification until the issuer
is known — this is required because the CRL issuer may only arrive in the peer
chain. Adding a CRL implicitly turns on `WOLFSSL_CRL_CHECKALL` in wolfSSL,
which would require a CRL for every certificate of the chain, so the patch
clears it to match the OpenSSL `X509_V_FLAG_CRL_CHECK` behaviour.

## Trusted CA list
wolfSSL implements neither `SSL_add_file_cert_subjects_to_stack()` nor its
directory counterpart, so the list of trusted CA names advertised to clients is
built from `CAfile` only. A `CApath` directory is still loaded into the trust
store and is fully used for verification, but its subjects are not advertised
during the handshake, and stunnel logs `Trusted CA list not available for
CApath` at the info level. Clients that rely on the advertised list to pick a
certificate should be given a `CAfile`.

## Other
+ DH parameters are read from the certificate file with
  `wolfSSL_CTX_SetTmpDH_file()` instead of `dh_read()`. If the file contains
  no DH parameters, stunnel falls back to the dynamic parameters that are
  regenerated by the `per-day` thread, exactly as it does with OpenSSL.
+ The DH ciphersuite scan (`SSL_CIPHER_description()` matching ` Kx=DH`) is
  skipped, so every server section that has a certificate initializes DH.
  Client sections and certificate-less (PSK-only) sections are skipped.
+ ECDH parameters are detected by wolfSSL from the ECC key, so the `curves`
  option is not applied through `SSL_CTX_set1_groups_list()`.
+ Engine support is disabled (`OPENSSL_NO_ENGINE`), so `engine`, `engineNum`,
  `CAengine`, `cert`/`key` engine identifiers and `ui_retry()`'s engine
  password prompts are unavailable.
+ Compression is disabled (`OPENSSL_NO_COMP`).
+ Intermediate certificates from a PKCS#12 file are installed one at a time
  with `SSL_CTX_add_extra_chain_cert()`, since wolfSSL does not expose
  `SSL_CTX_set0_chain()`.
+ `DEFAULT_STACK_SIZE` is raised to 131072 to accommodate wolfSSL's default
  fastmath with timing resistance.
