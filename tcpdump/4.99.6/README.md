# Building tcpdump with wolfSSL
+ Configure wolfSSL with `./configure --enable-tcpdump`. This turns on the OpenSSL compatibility layer, 3DES (ESP decryption) and MD5 (TCP MD5 signature option). Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download tcpdump-4.99.6 with `curl -O https://www.tcpdump.org/release/tcpdump-4.99.6.tar.gz`.
+ Unarchive this tar ball with `tar xvf tcpdump-4.99.6.tar.gz`.
+ Apply the tcpdump-4.99.6.patch file with `patch -p1 < tcpdump-4.99.6.patch` (assuming the patch file is in the tcpdump-4.99.6 directory; adjust the path according to your situation).
+ Regenerate the configure script with `autoreconf -ivf`.
+ Configure tcpdump with `./configure --with-wolfssl=/usr/local`. Update the path if you've installed wolfSSL using a different prefix than /usr/local. If that prefix is not on the dynamic linker search path, export `LD_LIBRARY_PATH=<prefix>/lib` before running tcpdump or the tests.
+ Run `make` to compile.
+ Run `make check`. All tests should pass.

## libpcap
libpcap 1.10.4 (the version shipped by Ubuntu 24.04) reads pcap timestamps as signed 32-bit values, which makes the `time_2038_overflow`, `time_2039`, `time_2106` and `time_2106_max` tests fail regardless of the crypto library. Use libpcap 1.10.5 or newer. The easiest way is to build it in a `libpcap` directory next to the tcpdump directory (`./configure && make`); tcpdump's configure script picks it up automatically.
