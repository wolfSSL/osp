This is a list of steps to follow to generate an OpenResty bundle that can be compiled with wolfSSL.

# Get the version you need
- Download the appropriate release from https://openresty.org/en/download.html
- Extract (tar -xf openresty-<version>.tar.gz)

# Modify the configure script
Patch the `configure` script to link against wolfSSL instead of OpenSSL. In the OpenResty directory:
```
patch -p1 < <version>.patch
```
Patches for the following versions are available in this directory:
* 1.19.3.1
* 1.13.6.2

# Compiling wolfSSL
```
./configure --enable-openresty
make
make install
```

# Compiling OpenResty
```
./configure --with-wolfssl=/usr/local
make
```

# Developer notes
When porting to a new version of OpenResty, you need to copy the appropriate Nginx patch from the wolfssl-nginx repo and rename it to `nginx-wolfssl.patch`. The patch file should be placed in the `bundle` directory.
```
cp <path/to/wolfssl/nginx/patch> bundle/nginx-wolfssl.patch
```

Patches are generated with the following command:
```
git format-patch -1
```

