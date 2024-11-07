# SQLCipher + wolfSSL

This port contains patches that introduce wolfCrypt as a cryptographic provider for [SQLCipher](https://github.com/sqlcipher/sqlcipher). These patches were generated and tested against SQLCipher `v4.6.1` using wolfSSL `v5.7.4-stable`.

SQLCipher is a standalone fork of the [SQLite](https://www.sqlite.org/) database library that adds 256 bit AES encryption of database files, along with a host of other security features.

SQLCipher is maintained by Zetetic, LLC, and additional information and documentation is available on the official [SQLCipher site](https://www.zetetic.net/sqlcipher/).


## Patch Files

There are two patch files included in this port:

- `sqlcipher_wolfssl_${sqlcipher_version}_raw.patch`
- `sqlcipher_wolfssl_${sqlcipher_version}_gitinfo.patch`

The raw patch file only contains the raw code changes, suitable if you are not applying the patch to a git repository. The git info patch includes the changes as a git commit, suitable if you wish to apply the changes as a commit to your fork of SQLCipher. Note that applying the raw patch to a git repo will also work, resulting in the patch being applied as unstaged changes, which you can then commit.

To apply the raw patch, navigate to SQLCipher and run:

```sh
git apply /path/to/sqlcipher_wolfssl_v4.6.1_raw.patch
```

To apply the git info patch, navigate to SQLCipher and run:
```
git am < /path/to/sqlcipher_wolfssl_v4.6.1_gitinfo.patch
```

## Prerequisites

1. A working `git` and `autotools` installation on a UNIX-like system
2. SQLite (and SQLCipher) requires the `tcl` development headers installed. On Ubuntu, you can obtain these headers by installing the `tcl-dev` package (`apt install tcl-dev`)

## Build Instructions

1. Clone or download the official SQLCipher release
2. Clone or download wolfSSL
3. Configure, build, and install wolfSSL

```sh
cd /path/to/wolfSSL
./configure --enable-all    # or provide your custom configure options here
make install

# Note: This installs wolfSSL as a shared library on the host system. You can also
# install wolfSSL to a specific directory, or build wolfSSL as a static library
# if desired. Consult the wolfSSL docs for more information.
```

2. Apply the patches to SQLCipher using one of the two methods above
3. Regenerate the SQLCipher `configure` script to include the new wolfSSL option

```sh
autoreconf --install --force
```

4. Configure SQLCipher to use wolfSSL as a cryptographic provider. You should also add any other SQLCipher configuration flags you need at this point. See the SQLCipher documentation for information

```sh
./configure --enable-tempstore=yes --with-crypto-lib=wolfssl --enable-fts5 CFLAGS="-DSQLITE_HAS_CODEC -DSQLCIPHER_TEST" LDFLAGS="-lwolfssl"
```

5. Build SQLCipher and the test fixture

```sh
make
make testfixture
```

6. Run the SQLCipher tests

```sh
./testfixture test/sqlcipher.test
```

Note that SQLCipher also supports linking against static libraries for its crypto implementations. See the SQLCipher documentation for more details.

## Troubleshooting

1. Compiler errors like `fatal error: tcl.h: No such file or directory` indicate that SQLite cannot find the `tcl` development headers on your system. You can install the development headers using the steps in the [Prerequisites](##prerequisites) section. Please refer to the SQLite and SQLCipher documentation for more info.


2. If using a FIPS build of wolfSSL, the sqlcipher tests will all fail as they use a password/key shorter than the minimum FIPS mandated length (14 bytes). There are some tests that are easy to change to accomodate that (`sqlcipher-backup.test`, for example). For these you can run `sed -i 's/testkey/testkey012345678/g'`. Other tests will take too long to fix as they use random keys ("foo", "0123", etc) and others like `sqlcipher-compatibility.test` operate on databases already encrypted with short keys, and so should be skipped.

