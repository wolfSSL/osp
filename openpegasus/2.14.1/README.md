# Building OpenPegasus with wolfSSL
+ Configure wolfSSL with `./configure --enable-opensslextra --enable-opensslall --enable-certgen`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into `/usr/local`.
+ Download pegasus-2.14.1 with `curl -O https://collaboration.opengroup.org/pegasus/documents/32572/pegasus-2.14.1.tar.gz`.
+ Unarchive this tar ball with `tar xvf pegasus-2.14.1.tar.gz`. `cd pegasus`.
+ Apply the wolfssl-openpegasus-2.14.1.patch file with `patch -p1 < wolfssl-openpegasus-2.14.1.patch` (assuming the patch file is in the pegasus directory; adjust the path according to your situation).
+ Set up the necessary environment variables in wolfssl_env.sh.
    + Set `PEGASUS_ROOT` to the path to the pegasus directory.
    + Set `PEGASUS_HOME` to the path to the pegasus directory.
    + Set `PEGASUS_PLATFORM` to your platform. For example, for x86_64 Linux, use `LINUX_X86_64_GNU`. Other values can be found in the configure script. Note that we aren't advising that you use the configure script, as the OpenPegasus developers recommend setting everything up via environment variables instead.
    + Set `PEGASUS_HAS_SSL` to `1`.
    + Set `PEGASUS_HAS_WOLFSSL` to `1`.
    + Set `PEGASUS_DEBUG` to `1`. This shouldn't be necessary, in theory, but it seems that OpenPegasus 2.14.1 shipped with some lines that will cause compilation errors if this isn't defined.
    + Set `PEGASUS_ENABLE_SSL_CRL_VERIFICATION` to `false`. wolfSSL currently doesn't support all the necessary OpenSSL CRL functions for this feature.
    + Set `WOLFSSL_HOME` to the wolfSSL installation prefix. For example, if you configured wolfSSL with the default prefix on Linux, you'd set this to `/usr/local`.
+ `source wolfssl_env.sh` to export the environment variables (assuming wolfssl_env.sh is in the pegasus directory; adjust the path according to your situation).
+ Run `make build` to compile.

OpenPegasus does come with tests, but we have been unsuccessful in getting them all passing, even when using OpenSSL instead of wolfSSL. The testing setup is also quite involved, so we're omitting testing from this document, for now.
