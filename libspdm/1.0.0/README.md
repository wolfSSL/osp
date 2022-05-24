# Building libspdm with wolfSSL
+ Configure wolfSSL with `./configure --enable-keygen --enable-certgen --enable-opensslall --enable-opensslextra`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Clone the libspdm repository with `git clone https://github.com/DMTF/libspdm.git`. `cd libspdm`.
+ Checkout version 1.0.0 with `git checkout 1.0.0`.
+ Apply the libspdm-1.0.0.patch file with `patch -p1 < libspdm-1.0.0.patch` (assuming the patch file is in the libspdm directory; adjust the path according to your situation).
+ Set up the git submodules with `git submodule update --init`.
+ Make a build directory with `mkdir build` and `cd build`.
+ Run cmake with `cmake -DENABLE_BINARY_BUILD=1 -DTARGET=Debug -DTOOLCHAIN=GCC -DARCH=x64 -DCRYPTO=wolfssl -DWOLFSSL_PREFIX=/usr/local ..`. Note that these settings are for building on a Linux, x64-based system using GCC.
+ Compile with `make`.
+ Run the crypto tests with `./bin/test_crypt`. They should all pass.
