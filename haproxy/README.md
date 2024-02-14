# wolfssl-haproxy

## wolfSSL Support in Haproxy

wolfSSL is supported in Haproxy.

see:

https://www.haproxy.com/blog/announcing-haproxy-2-8#wolfssl-support
https://github.com/haproxy/haproxy/blob/master/INSTALL#L287


This is how it was tested:

cd $HOME
git clone git@github.com:wolfSSL/wolfssl.git
cd $HOME/wolfssl && ./autogen.sh &&
./configure --prefix=/opt/wolfssl/ --enable-debug --enable-quic --enable-haproxy && make && sudo make install

cd $HOME
git clone https://github.com/vtest/VTest
cd $HOME/VTest && make FLAGS="-g" && sudo make install

cd $HOME
git clone git@github.com:haproxy/haproxy.git
cd $HOME/haproxy && make -j7 TARGET=linux-glibc V=1 DEBUG_CFLAGS='-ggdb3' DEBUG='-DDEBUG_MEMORY_POOLS -DDEBUG_STRICT' CPU_CFLAGS='-O2' USE_OPENSSL_WOLFSSL=1 USE_QUIC=1 SSL_INC=/opt/wolfssl/include/ SSL_LIB=/opt/wolfssl/lib/ ADDLIB='-Wl,-rpath=/opt/wolfssl/lib'

VTEST_PROGRAM=$HOME/VTest/vtest make reg-tests reg-tests/ssl

Please be aware that while most tests will pass, some may fail as Haproxy tests are not entirely decoupled from OpenSSL.

You can also execute individual tests as follows. For example,
VTEST_PROGRAM=$HOME/VTest/vtest make reg-tests -- --debug reg-tests/ssl/new_del_ssl_cafile.vtc 2>&1 | tee log.new_del_ssl_cafile.log
