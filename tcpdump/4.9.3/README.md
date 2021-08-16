# Building tcpdump with wolfSSL
+ Configure wolfSSL with `./configure --enable-tcpdump`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download tcpdump-4.9.3 with `curl -O https://www.tcpdump.org/release/tcpdump-4.9.3.tar.gz`.
+ Unarchive this tar ball with `tar xvf tcpdump-4.9.3.tar.gz`.
+ Apply the tcpdump-4.9.3.patch file with `patch -p1 < tcpdump-4.9.3.patch` (assuming the patch file is in the tcpdump-4.9.3 directory; adjust the path according to your situation).
+ Regenerate the configure script with `autoreconf -ivf`.
+ Configure tcpdump with `./configure --with-wolfssl=/usr/local`. Update the path if you've installed wolfSSL using a different prefix than /usr/local.
+ Run `make` to compile.
+ Run `make check`. All tests should pass.
