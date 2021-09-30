The [master branch of libssh2](https://github.com/libssh2/libssh2) supports wolfSSL natively, but this hasn't made it into a release, yet. If you're using libssh2 1.10.0 or older, you will need to use the approach described below.

# Building libssh2 with wolfSSL

+ Configure wolfSSL with `./configure --enable-libssh2`. Add `--enable-debug` if you're going to be debugging. Add `--enable-fips=v2` if using wolfSSL FIPS.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download libssh2-1.9.0 with `curl -O https://www.libssh2.org/download/libssh2-1.9.0.tar.gz`.
+ Unarchive this tar ball with `tar xvf libssh2-1.9.0.tar.gz` and `cd libssh2-1.9.0`.
+ Apply the libssh2-1.9.0.patch file with `patch -p1 < libssh2-1.9.0.patch` (assuming the patch file is in the libssh2-1.9.0 directory; adjust the path according to your situation).
+ Regenerate the configure script with `./buildconf`.
+ Configure libssh2 with `./configure --with-crypto=wolfssl --with-wolfssl=/usr/local`. Update the path if you've installed wolfSSL using a different prefix than /usr/local.
+ Run `make` to compile.
+ Ensure all tests pass with `make check`.
