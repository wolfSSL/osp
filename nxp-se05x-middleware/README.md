# NXP SE05x Middleware HostCrypto Patch

This directory contains a patch for NXP's SE05x Middleware that adds a
HostCrypto option for using wolfSSL. The primary use case for this functionality
at the time of writing is for users who wish to use wolfSSL to establish
an authenticated SCP03 channel to SE050. This allows use of wolfSSL for both
SCP03 HostCrypto authentication as well as usage of wolfSSL with SE050 support
enabled by an application post-SCP03-authentication.

## Applying the Patch

This patch will apply cleanly on top of the SE05x Middleware version v04.02.00:

```
$ unzip SE05x_MW.zip -d se_mw
$ ls se_mw
se05x_mw_v04.02.00_20220701_151557

$ cd se_mw/se05x_mw_v04.02.00_20220701_151557/simw-top
$ cp <path/to/simw-top.patch> ./
$ patch -p1 < simw-top.patch
```

For more complete wolfSSL SE050 documentation, refer to
[README_SE050.md](https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/port/nxp/README_SE050.md).

## Building SE05x Middlware on Raspberry Pi with SE050 EdgeLock Dev Kit

To build the patched SE05x Middleware linked to wolfSSL, first build wolfSSL.
For use with SE05x Middleware HostCrypto, this requires `--enable-keygen` and
`--enable-cmac`. `WOLFSSL_SE050_NO_TRNG` will also need to be added to CFLAGS
in order to cause wolfSSL to fall back and use `/dev/urandom` instead of trying
to use the SE050 TRNG before SCP03 authenticaiton has completed. You may also
need to define `SIZEOF_LONG_LONG=8` if not correctly detected by configure.

```
$ unzip wolfssl-X.X.X.zip
$ cd wolfssl-X.X.X
$ ./configure --enable-keygen --enable-cmac CFLAGS="-DWOLFSSL_SE050_NO_TRNG -DSIZEOF_LONG_LONG=8"
$ make
$ sudo make install
```

Then, build SE05x Middleware:

```
$ cd se_mw/se05x_mw_v04.02.00_20220701_151557/simw-top
$ cd scripts
$ python create_cmake_projects.py rpi
$ cd se_mw/se05x_mw_v04.02.00_20220701_151557/simw-top_build/raspbian_native_se050_t1oi2c/
$ ccmake .
$ Make sure the following are set:
    "PTMW_Applet" to match your SE050 version (ex: "SE05X_C")
    "PTMW_Host" to "Raspbian"
    "PTMW_HostCrypto" to "WOLFSSL"
    "PTMW_SE05X_Auth" to "PlatfSCP03"
    "PTMW_SE05X_VER" to match your SE050 applet version (ex: "03_XX")
    "PTMW_SMCOM" to "T1oI2C"
$ c # to configure
$ g # to generate
$ q
$ cmake --build .
$ sudo make install
```

You can then verify some of the demos work, for example to run GetInfo:

```
$ cd se_mw/se05x_mw_v04.02.00_20220701_151557/simw-top_build/raspbian_native_se050_t1oi2c/bin
$ ./se05x_GetInfo
```

There should be a line mentioning PlatfSCP03 keys, for example:

```
App   :INFO :Using default PlatfSCP03 keys. You can use keys from file using ENV=EX_SSS_BOOT_SCP03_PATH
```

## Building SE05X Middleware with wolfSSL HostCrypto Support and wolfSSL with SE050 Support

wolfSSL can be built with SE050 support, to offload crypto operations to the
SE050. Building this support plus using wolfSSL with HostCrypto can be done.
On Raspberry Pi / Linux, this requires a roundabout build cycle due to circular
dependencies of SE05X Middleware on wolfSSL, and wolfSSL on SE05X Middleware.

The solution that seems to work for us is:

1. Build and install wolfSSL **WITHOUT** SE050 support:

```
$ unzip wolfssl-X.X.X.zip
$ cd wolfssl-X.X.X
$ ./configure --enable-keygen --enable-cmac CFLAGS="-DWOLFSSL_SE050_NO_TRNG -DSIZEOF_LONG_LONG=8"
$ make
$ sudo make install
```

2. Build and install SE05X Middleware

Follow steps above to build middleware. This will link against wolfSSL for
HostCrypto support, but that wolfSSL will not have SE050 support enabled
internally.

3.  Re-build and install wolfSSL **WITH** SE050 support:

```
$ unzip wolfssl-X.X.X.zip
$ cd wolfssl-X.X.X
$ ./configure --with-se050 --enable-keygen --enable-cmac CFLAGS="-DWOLFSSL_SE050_NO_TRNG -DSIZEOF_LONG_LONG=8"
$ make
$ sudo make install
```

4. Re-build and install SE050 Middleware

Follow the steps above again to build middleware. This time will link against
a wolfSSL version with SE050 support enabled internally.

## wolfSSL Examples for SE050

For examples of wolfSSL on SE050, see the [wolfssl-examples repo](https://github.com/wolfSSL/wolfssl-examples/tree/master/SE050).

## Support

For support, please contact wolfSSL at support@wolfssl.com.

