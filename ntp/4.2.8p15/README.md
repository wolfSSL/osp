## Build Instructions

### Build wolfSSL
+ Configure wolfSSL with `./configure --enable-ntp`. Add `--enable-debug` if you want to enable the debug version of wolfSSL.
+ Compile with `make`.
+ Install wolfSSL into /usr/local with `sudo make install`.

### Build NTP
+ Download ntp 4.2.8p15 with `curl -O http://www.eecis.udel.edu/~ntp/ntp_spool/ntp4/ntp-4.2/ntp-4.2.8p15.tar.gz`.
+ Unarchive ntp-4.2.8p15.tar.gz with `tar xvf ntp-4.2.8p15.tar.gz`. cd into ntp-4.2.8p15.
+ Patch the source code with `patch -p1 < ntp-4.2.8p15.patch`, adjusting the path to the patch file accordingly. 
+ Regenerate the configure script with `./bootstrap`.
+ Configure ntp with `./configure --with-wolfssl=/usr/local`.
+ Compile with `make`.
+ Run tests with `make check`.
