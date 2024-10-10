To configure wolfSSL, use the following command:

```
./configure --enable-static --enable-opensslall --enable-enckeys --enable-certgen --enable-context-extra-user-data
sudo make install
```

Configuring wolfSSL for local installation can be specified with `--prefix=/path/to/install`

Downloading and applying the patch for realm-core v13.26.0.tar.gz or git commit a5e87a39:

```
curl -L -O https://github.com/realm/realm-core/archive/refs/tags/v13.26.0.tar.gz
tar -xvf v13.26.0.tar.gz
cd realm-core-13.26.0
patch -p1 < ../realm-v13.26.0.patch
```

Building realm-core:

```
mkdir build
cmake -B build -DREALM_ENABLE_ENCRYPTION=1 -DREALM_ENABLE_SYNC=1 -DREALM_USE_WOLFSSL=1 -DREALM_WOLFSSL_ROOT_DIR=/usr/local/lib
cmake --build build
./build/test/realm-tests
```

You can also use the build_wolfssl_with_realm.sh script after adjusting the global variables as needed.
