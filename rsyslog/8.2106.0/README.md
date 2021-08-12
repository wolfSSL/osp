# Building rsyslog with wolfSSL

## Install Dependencies
+ libfastjson development package
    + [Debian](https://packages.debian.org/sid/libfastjson-dev)
    + [Ubuntu](https://packages.ubuntu.com/focal/libfastjson-dev)
    + [Source](https://github.com/rsyslog/libfastjson)
+ libestr development package
    + [Debian](https://packages.debian.org/sid/libestr-dev)
    + [Ubuntu](https://packages.ubuntu.com/focal/libdevel/libestr-dev)
    + [Source](https://github.com/rsyslog/libestr)

## Build rsyslog
+ Configure wolfSSL with `./configure --enable-rsyslog`. Add `--enable-debug` if you're going to be debugging. Add `--enable-fips=v2` if using wolfSSL FIPS.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download rsyslog-8.2106.0 with `curl -O https://www.rsyslog.com/download/files/download/rsyslog/rsyslog-8.2106.0.tar.gz`.
+ Unarchive this tar ball with `tar xvf rsyslog-8.2106.0.tar.gz` and `cd rsyslog-8.2106.0`.
+ Apply the rsyslog-8.2106.0.patch file with `patch -p1 < rsyslog-8.2106.0.patch` (assuming the patch file is in the rsyslog-8.2106.0 directory; adjust the path according to your situation).
+ Regenerate the configure script with `autoreconf -ivf`. The warnings can be ignored.
+ Configure rsyslog with `./configure --enable-omstdout --enable-imdiag --enable-testbench --without-valgrind-testbench --enable-helgrind=no --with-wolfssl=/usr/local`. Update the path to the wolfSSL installation if you've installed wolfSSL using a prefix other than /usr/local. Add `--enable-debug` if debugging.
+ Run `make` to compile.
+ Ensure all tests pass with `make check`.
