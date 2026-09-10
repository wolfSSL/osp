# MariaDB 10.6.28 with system wolfSSL

This patch builds the MariaDB server and its included Connector/C 3.3.20 against
an installed wolfSSL library. Apply it to an unmodified MariaDB 10.6.28 source
tree.

## Changes

- `WITH_SSL=system-wolfssl` selects installed wolfSSL for the server and, by
  default, Connector/C. `CMAKE_PREFIX_PATH` supports a nonstandard installation.
- `WOLFSSL_USE_OPTIONS_H` makes the integration use the installed library's
  configuration, including builds advertising the OpenSSL 1.1 API.
- System wolfSSL allocates its EVP cipher contexts through
  `EVP_CIPHER_CTX_new/free`, so different wolfSSL AES table configurations do not
  require changes to MariaDB's fixed context buffer size.
- Connector/C uses wolfSSL for TLS and its crypto-dependent authentication
  plugins. It preserves transport callbacks, asynchronous waits and timeout
  units, and balances initialization/cleanup locking.
- Requesting server certificate verification enables chain verification even
  when no explicit CA file was supplied.

MariaDB's AES-ECB/CBC service modes are available with this port; its AES-CTR/GCM
service modes are disabled. TLS AES-GCM suites are supported.

## Build

Build and install wolfSSL first, with OpenSSL and MariaDB compatibility enabled.
The following non-FIPS configuration was tested with wolfSSL 5.9.2. Run these
commands from the wolfSSL source directory, adjusting the installation prefix as
needed. `autogen.sh` is only needed for a Git checkout.

```sh
./autogen.sh
./configure --prefix=/opt/wolfssl \
  CPPFLAGS="-DRSA_MAX_SIZE=8196 -DFP_MAX_BITS=16384 -DNO_OLD_TIMEVAL_NAME \
    -DWOLFSSL_MYSQL_COMPATIBLE -DWOLFSSL_AES_DIRECT -DKEEP_OUR_CERT \
    -DHAVE_AES_ECB -DWOLFSSL_NO_DEF_TICKET_ENC_CB -DHAVE_EX_DATA" \
  --enable-opensslall --enable-crl --enable-sessioncerts --enable-aesctr \
  --enable-rsapss --enable-keygen --enable-des3 --enable-aesgcm=table
make -j8
make check
sudo make install
```

The installed `wolfssl/options.h` must match the installed library. MariaDB reads
this header automatically when configured to use system wolfSSL.

For a FIPS build, follow the configuration and build procedure supplied with the
licensed wolfSSL module. This version of the port has not been validated with a
FIPS build.

Download the [MariaDB 10.6.28 source release](https://archive.mariadb.org/mariadb-10.6.28/source/mariadb-10.6.28.tar.gz),
which already includes Connector/C and the other bundled sources:

```sh
curl -fLO https://archive.mariadb.org/mariadb-10.6.28/source/mariadb-10.6.28.tar.gz
# SHA-256: 13d9330f3120c739757b215a3220a9c9e2ddf3c3c1b8beff5cd43942868f3d72
tar xf mariadb-10.6.28.tar.gz
cd mariadb-10.6.28
patch --fuzz=0 -p1 < /path/to/osp/mariadb/10.6.28/mariadb-10.6.28.patch
cmake -S . -B build -G Ninja \
  -DWITH_SSL=system-wolfssl \
  -DCMAKE_PREFIX_PATH=/opt/wolfssl \
  -DWITH_UNIT_TESTS=ON
cmake --build build -j8
```

With CMake 4, also pass `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` for this MariaDB
release's older bundled projects. Start with a fresh build directory when
changing TLS backends or wolfSSL configurations.

Connector/C can also be built separately from the patched release:

```sh
cmake -S libmariadb -B build-connector -G Ninja \
  -DWITH_SSL=SYSTEM_WOLFSSL -DCMAKE_PREFIX_PATH=/opt/wolfssl
cmake --build build-connector -j8
```

## Test

```sh
ctest --test-dir build --output-on-failure -j8
cd build/mysql-test
perl ./mtr --parallel=2 --force \
  main.system_wolfssl main.ssl_7937 main.ssl main.ssl_connect main.ssl_ca \
  main.ssl_timeout main.ssl_timeout-9836 main.func_crypt main.func_des_encrypt \
  main.wolfssl encryption.innodb_encryption \
  encryption.innodb_encryption_filekeys encryption.aria_tiny
```

`main.system_wolfssl` checks verified TLS 1.2 and TLS 1.3 connections and rejection
of an untrusted server. The AES unit test also checks invalid-key initialization.

Test results depend on the wolfSSL configuration. `main.tls_version` expects
TLS 1.1 and fails when old TLS versions are disabled. `main.ssl_cipher` requires
static RSA cipher suites, which can be enabled with `-DWOLFSSL_STATIC_RSA` when
building wolfSSL. OpenSSL-specific tests may skip when the selected provider is
wolfSSL. The full MariaDB test suite has not been run with this port.
