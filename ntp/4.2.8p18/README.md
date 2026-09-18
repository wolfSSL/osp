## Build Instructions

### Build wolfSSL
+ Configure wolfSSL with `./configure --enable-ntp CFLAGS="-DOPENSSL_EXTRA_BSD"`. NTP uses `MD5Init`/`MD5Update`/`MD5Final`, which wolfSSL only provides under `OPENSSL_EXTRA_BSD`. Add `--enable-debug` if you want to enable the debug version of wolfSSL.
+ Compile with `make`.
+ Install wolfSSL into /usr/local with `sudo make install`.

### Build NTP
+ Download ntp 4.2.8p18 with `curl -O http://www.eecis.udel.edu/~ntp/ntp_spool/ntp4/ntp-4.2/ntp-4.2.8p18.tar.gz`.
+ Unarchive ntp-4.2.8p18.tar.gz with `tar xvf ntp-4.2.8p18.tar.gz`. cd into ntp-4.2.8p18.
+ Patch the source code with `patch -p1 < ntp-4.2.8p18.patch`, adjusting the path to the patch file accordingly. 
+ Regenerate the configure script with `./bootstrap`.
+ Configure ntp with `./configure --with-wolfssl=/usr/local`.
+ Compile with `make`.
+ To pass all tests with `make check` compile wolfSSL additionally with `--enable-md4`.
