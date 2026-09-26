# Building openvswitch (ovs) with wolfSSL
+ Configure wolfSSL with `./configure --enable-sessioncerts --enable-certgen --enable-opensslall --enable-opensslextra`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download ovs-2.17.1 with `curl -O -L https://github.com/openvswitch/ovs/archive/refs/tags/v2.17.1.tar.gz`.
+ Unarchive this tar ball with `tar xvf v2.17.1.tar.gz`. `cd ovs-2.17.1`.
+ Apply the openvswitch-2.17.1.patch file with `patch -p1 < openvswitch-2.17.1.patch` (assuming the patch file is in the ovs-2.17.1 directory; adjust the path according to your situation).
+ Regenerate the configure script with `./boot.sh`.
+ Configure ovs with `./configure --with-wolfssl=/usr/local`. Update the path if you've installed wolfSSL using a different prefix than /usr/local.
+ Run `make` to compile.
+ Run `make check`. All tests should pass. You can run tests in parallel to speed things up with `make check TESTSUITEFLAGS="-j<num CPUs>"`.
