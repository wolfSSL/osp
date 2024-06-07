For passing the most `make test` tests, build wolfSSL with the configure

```
./configure --enable-maxfragment --enable-opensslall --enable-opensslextra --enable-dtls --enable-oldtls --enable-tlsv10 --enable-ipv6 CPPFLAGS="-DWOLFSSL_NO_DTLS_SIZE_CHECK -DOPENSSL_COMPATIBLE_DEFAULTS"
```

Download socat-1.8.0.0.tar.gz and apply patch:

```
curl -O http://www.dest-unreach.org/socat/download/socat-1.8.0.0.tar.gz
tar xvf socat-1.8.0.0.tar.gz
cd socat-1.8.0.0
patch -p1 < socat-1.8.0.0.patch
autreconf -fvi
./configure --with-wolfssl=/usr/local
make
```


Current fail cases seen with `make test` are:

```
FAILED:  146 216 309 310 386 402 459 460
```

- Test 146 is with a DSA certificate and gets a -501 (bad cipher suite). wolfSSL
does not support DSA cipher suites.
- Test 216 "socat[294052] W exiting on signal 15"
- Test 309 and 310 fail even before for the port when linked with OpenSSL.
- Test 402 "i2v function not yet implemented for Subject Alternative Name"
- Test 459 and 460 "socat[292771] E parseopts_table(): unknown option "ispeed""

