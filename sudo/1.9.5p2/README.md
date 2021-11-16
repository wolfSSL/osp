# Upstream Support
As of commit `cc6157d7d4ceec624da6ca0ac6bfc581fc868491`, [sudo supports using
wolfSSL upstream](https://github.com/sudo-project/sudo). There is no official
release with wolfSSL support, yet.

# Building sudo with wolfSSL
+ Configure wolfSSL with `./configure --enable-opensslall
CPPFLAGS="-DHAVE_EX_DATA"`. Add `--enable-debug` if you're going to be
debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download sudo-1.9.5p2 with
`curl -O https://www.sudo.ws/dist/sudo-1.9.5p2.tar.gz`.
+ Unarchive this tar ball with `tar xvf sudo-1.9.5p2.tar.gz`. `cd sudo-1.9.5p2`.
+ Apply the wolfssl-sudo-1.9.5p2.patch file with
`patch -p1 < wolfssl-sudo-1.9.5p2.patch` (assuming the patch file is in the
sudo-1.9.5p2 directory; adjust the path according to your situation).
+ Regenerate the configure script with `./autogen.sh`.
+ Configure sudo with `./configure --with-wolfssl=/usr/local`. Update the path
if you've installed wolfSSL using a different prefix than /usr/local.
+ Run `make` to compile.
+ Run `make check`. All tests should pass.
