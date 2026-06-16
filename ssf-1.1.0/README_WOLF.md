# Building SSF with wolfSSL

Port of SSF 1.1.0 with Boost/Asio 1.65.1 for wolfSSL. Project completed 07/2018.

## Overview

The SSF tool uses the Boot.Asio component for the TLS interface. WolfSSL has been ported into Boost.Asio and SSF builds. 

The build option `ASIO_USE_WOLFSSL` is used to indicate wolfSSL as the TLS provider.

## Getting Sources

1. Clone the master version of wolfSSL with 

    $ `git clone https://github.com/wolfSSL/wolfssl.git`
    OR
    $ `scp wolfssl-3.15.3.tar.gz ubuntu@204.48.22.68:~/ssfwolfbuild`
    $ `tar -xzf wolfssl-3.15.3.tar.gz`
    $ `mv wolfssl-3.15.3 wolfssl`

2. Execute the following commands from the wolfSSL root directory

    $ `cd wolfssl`
    $ `./autogen.sh` (if git clone)
    $ `./configure --enable-asio` [--enable-debug]
    $ `make`
    $ `make check`
    $ `sudo make install`
    $ `sudo ldconfig`

   To Enable Intel Optimizations use:
   $ `./configure --enable-asio --enable-sp --enable-intelasm --enable-aesni --enable-intelrand`

3. Download SSF 1.1.0 and extract

    https://github.com/securesocketfunneling/ssf/releases
    $ `wget https://github.com/securesocketfunneling/ssf/archive/1.1.0.tar.gz`
    $ `tar -xzf 1.1.0.tar.gz`
    Extracts to ssf-1.1.0

4. Download ASIO 1.65.0 WolfSSL modified

    $ `scp asio_1_65_1.tar.gz ubuntu@204.48.22.68:~/ssfwolfbuild`
    $ `tar -xzf asio_1_65_1.tar.gz`

5. Download boost 1_65_1 into third_party/boost

    https://www.boost.org/users/history
    $ `wget https://dl.bintray.com/boostorg/release/1.65.1/source/boost_1_65_1.tar.gz`
    $ `tar -xzf boost_1_65_1.tar.gz`
    $ `cd boost_1_65_1`
    
    Link boost to SSF from boost_1_65_1 directory
    $ `mv ./boost/asio ./boost/asio_old`
    $ `ln -s ../../../osp/asio_1_65_1 ./boost/asio`

    Link boost to SSF from boost_1_65_1 directory
    $ `cd ../ssf-1.1.0`
    $ `rm -rf ./third_party/boost`
    $ `ln -s ../../boost_1_65_1 ./third_party/boost`


## Building

Execute the following commands from the SSF root directory

    $ `mkdir build`
    $ `cd build`
    $ `cmake -DCMAKE_BUILD_TYPE=Release -DWOLFSSL="/usr/local" ../`
    $ `cmake --build . -- -j 4`


## Testing

If you want to build the unit tests, download gtest 1.7.0 and link it to the third_party/gtest directory

    https://github.com/google/googletest/releases
    $ `wget https://github.com/google/googletest/archive/release-1.7.0.tar.gz`
    $ `tar -xzf release-1.7.0.tar.gz`
    $ `mv googletest-release-1.7.0 gtest-1.7.0`
    $ `cd ssf-1.1.0`
    $ `rm -rf ./third_party/gtest`
    $ `ln -s ../../gtest-1.7.0 ./third_party/gtest`

If you also want to build the unit tests:

    $ `cmake -DCMAKE_BUILD_TYPE=Release -DWOLFSSL="/usr/local" -DBUILD_UNIT_TESTS=ON ../`
    $ `cmake --build . -- -j 4`
    $ `cp -r ../certs ./src/tests/`
    $ `cd ./src/tests/`

    Run each of the tests
    $ `sudo ./load_config_tests`
    $ `sudo ./bouncing_tests`
    $ `sudo ./fiber_asio_tests`
    $ `sudo ./file_copy_from_client_tests`
    $ `sudo ./remote_socks_tests`
    $ `sudo ./remote_stream_forward_tests`
    $ `sudo ./remote_udp_forward_tests`
    $ `sudo ./socks_tests`
    $ `sudo ./ssf_client_server_cipher_suites_tests`
    $ `sudo ./ssf_client_server_tests`
    $ `sudo ./stream_forward_tests`
    $ `sudo ./udp_forward_tests`


For more information please read the README.md from the SSF root directory.



## Support

For questions please email wolfSSL support at support@wolfssl.com.

