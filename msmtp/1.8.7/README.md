# Building msmtp with wolfSSL
+ Configure wolfSSL with `./configure --enable-opensslextra --enable-opensslall`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download msmtp-1.8.7 with `curl -O https://marlam.de/msmtp/releases/msmtp-1.8.7.tar.xz`.
+ Unarchive this tar ball with `tar xvf msmtp-1.8.7.tar.xz`. `cd msmtp-1.8.7`.
+ Apply the wolfssl-msmtp-1.8.7.patch file with `patch -p1 < wolfssl-msmtp-1.8.7.patch` (assuming the patch file is in the msmtp-1.8.7 directory; adjust the path according to your situation).
+ Regenerate the configure script with `autoreconf -ivf`.
+ Configure msmtp with `./configure --with-tls=wolfssl`.
+ Run `make` to compile.
