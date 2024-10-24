To configure wolfSSL, use the following command:

```
./configure --enable-static --enable-opensslall --enable-enckeys --enable-certgen --enable-context-extra-user-data
sudo make install
```

Configuring wolfSSL for local installation can be specified with `--prefix=/path/to/install`

Downloading and applying the patch for realm-core git commit a5e87a39:

```
git clone https://github.com/realm/realm-core.git
cd realm-core
git reset --hard HEAD
git checkout a5e87a39
git submodule update --init --recursive
git apply ../realm-v13.26.0.patch
```

Building realm-core:

```
mkdir build
cmake -B build -DREALM_ENABLE_ENCRYPTION=1 -DREALM_ENABLE_SYNC=1 -DREALM_USE_WOLFSSL=1 -DREALM_WOLFSSL_ROOT_DIR=/usr/local/lib
cmake --build build
./build/test/realm-tests
```

You can also use the build_wolfssl_with_realm.sh script after adjusting the global variables as needed.

