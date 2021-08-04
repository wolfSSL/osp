# Overview

MariaDB comes with a bundled version of wolfSSL that can be used with the MariaDB server. This is limited in a few ways:

+ libmariadb, which is used by MariaDB clients, isn't set up to be built with wolfSSL. If the server is built with wolfSSL, libmariadb gets builts with GnuTLS.
+ The wolfSSL version is tied to whatever version MariaDB has been bundled with.
+ The bundled version isn't FIPS.

This port makes it so a system-installed version of wolfSSL can be used for both the server and libmariadb. This also makes it possible to use wolfSSL FIPS with MariaDB. This has been tested with both wolfSSL FIPS and non-FIPS 4.8.1.

# Build Instructions

## Build wolfSSL
+ Configure wolfSSL with `./configure CPPFLAGS="-DRSA_MAX_SIZE=8196 -DFP_MAX_BITS=16384 -DNO_OLD_TIMEVAL_NAME -DWOLFSSL_MYSQL_COMPATIBLE -DWOLFSSL_AES_DIRECT -DKEEP_OUR_CERT -DHAVE_AES_ECB -DWOLFSSL_NO_DEF_TICKET_ENC_CB -DHAVE_EX_DATA" --enable-opensslall --enable-crl --enable-sessioncerts --enable-aesctr --enable-rsapss --enable-keygen --enable-des3`. Add `--enable-debug` if you want to enable the debug version of wolfSSL.
+ Compile with `make`.
+ Install wolfSSL into /usr/local with `sudo make install`.

## Build MariaDB
+ Clone the MariaDB server GitHub repo with `git clone git@github.com:MariaDB/server.git mariadb-server`. `cd mariadb-server`.
+ Check out the 10.5.11 tag with `git checkout mariadb-10.5.11`.
+ Set up the libmariadb submodule with `git submodule init && git submodule update`.
+ Patch the source code with `patch -p1 < mariadb-10.5.11.patch`, adjusting the path to the patch file accordingly. 
+ Create a build directory with `mkdir build` and `cd build`.
+ Configure MariaDB with `cmake -DWITH_SSL=system-wolfssl ..`. Add `-DCMAKE_BUILD_TYPE=Debug` if debugging. Note that this configuration requires libwolfssl and the wolfSSL headers to be installed in a standard location that can be found by CMake (e.g. /usr/local).
+ Compile with `make`.

## Testing
+ The tests take a long time to run. We recommend running them in the background with `nohup` to prevent accidentally ending the tests prematurely: `nohup mysql-test/mtr --force > test_errors.txt 2>&1 &`. You can then follow the test progress with `tail -f test_errors.txt`.

### Known Broken Tests
+ `main.ssl_cipher`: Fails due to the client trying to establish a TLS 1.3 connection with a non-TLS-1.3 cipher suite (`TLS_RSA_WITH_AES_128_CBC_SHA`). Other TLS implementations may choose to use TLS 1.2 (which is also supported by the client in this case via the supported versions extension) based on the fact that the cipher isn't TLS 1.3. It looks like wolfSSL requires the client to use the highest TLS version in the client's supported versions extension from the client hello.
+ `main.openssl_1`: Fails because it's using a 512-bit RSA key that's also expired.
+ `main.tls_version`: Fails because the test is expecting TLS 1.1 to be used but TLS 1.2 is used instead.
+ `main.ssl_7937`: This test runs `$MYSQL --ssl --ssl-verify-server-cert -e "call test.have_ssl()"`. Because no CA is specified, MariaDB sets the verify mode (via `SSL_CTX_set_verify`) to `SSL_VERIFY_NONE`. During the handshake, OpenSSL will still check the server certificate and set the `SSL` object's `verify_result` member accordingly. In this case, the certificate is self-signed, so it gets set to `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN`. However, in OpenSSL's function `tls_process_server_certificate`, as long as the verify mode is `SSL_VERIFY_NONE`, this error gets ignored and the connection proceeds successfully. Later, MariaDB checks the value of `verify_result` directly in `ma_tls_connect` because the flag `CLIENT_SSL_VERIFY_SERVER_CERT` has been set (via `--ssl-verify-server-cert`). If `verify_result != X509_V_OK`, then MariaDB generates an error. In contrast to OpenSSL, wolfSSL won't check the cert and set `verify_result` to an error value if the verify mode is `SSL_VERIFY_NONE`. Because of this difference, the `verify_result` is `X509_V_OK` when the check in `ma_tls_connect` is performed. So, the OpenSSL case will fail, and the wolfSSL case will succeed.
