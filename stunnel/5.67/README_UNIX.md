# Unix Build Instructions

## Build wolfSSL
+ Configure wolfSSL with `./configure --enable-stunnel`. Add `--enable-debug` if you want to enable the debug version of wolfSSL.
+ Compile with `make`.
+ Install wolfSSL into /usr/local with `sudo make install`.

## Build stunnel
+ Download stunnel 5.67 with `curl -O https://www.stunnel.org/archive/5.x/stunnel-5.67.tar.gz`.
+ Unarchive stunnel-5.67.tar.gz with `tar xvf stunnel-5.67.tar.gz`. cd into stunnel-5.67.
+ Patch the source code with `patch -p1 < stunnel-5.67.patch`, adjusting the path to the patch file accordingly.
+ Regenerate the configure script with `autoreconf`.
+ Configure stunnel with `./configure --enable-wolfssl`.
+ Compile with `make`.
+ Install stunnel into /usr/local with `sudo make install`.

# Run the tests
+ All of the stunnel tests run with `make check` should pass. Some might be skipped if you lack IPv6 support or if you are not building in FIPS mode.
+ This patch also adds the ability to run a single test plugin. To do this, run the test like this `python maketest.py --plugin p13_resume`.
