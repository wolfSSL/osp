# chrony with wolfSSL

## Building
+ Configure wolfSSL with `./configure --enable-chrony`. Add `--enable-debug` if debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download chrony-4.1 with `curl -O https://download.tuxfamily.org/chrony/chrony-4.1.tar.gz`.
+ Unarchive this tar ball with `tar xvf chrony-4.1.tar.gz`.
+ Apply the patch file with `patch -p1 < wolfssl-chrony-4.1.patch` (assuming the patch file is in the chrony-4.1 directory; adjust the path according to your situation).
+ Configure chrony with `./configure --enable-wolfssl`. Add `--enable-debug` if debugging.
+ Run `make` to compile.

## Testing
+ `cd test/unit && make check` to run the unit tests.
+ To run the simulation tests, you first need to build clknetsim.
    + Clone it from GitHub with `git clone https://github.com/mlichvar/clknetsim.git`.
    + `cd clknetsim && make` to build clknetsim.
    + `export CLKNETSIM_PATH=$(pwd)` to set the `CLKNETSIM_PATH` environment variable, which is required for the simulation tests.
+ Go back to the chrony-4.1 directory and `cd test/simulation && ./run` to run the simulation tests.
