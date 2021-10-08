#!/bin/bash

LOGFILE=log.txt
patch_fail=0

echo "Cloning wolfssl master to directory wolfssl-master"
git clone --depth=1 git@github.com:wolfssl/wolfssl.git wolfssl-master
cd wolfssl-master

PATCH_NUMBER=0
pull_patch() {
    printf "PR $PATCH_NUMBER ..."
    curl -O https://patch-diff.githubusercontent.com/raw/wolfSSL/wolfssl/pull/$PATCH_NUMBER.patch &> $LOGFILE
    patch -N -p1 < $PATCH_NUMBER.patch &> $LOGFILE
    if [ $? != 0 ]; then echo fail; patch_fail=1; else echo done; fi
}


PATCH_NUMBER=4293
pull_patch

PATCH_NUMBER=4350
pull_patch

if [ $patch_fail == 0 ]; then
    ./autogen.sh
    ./configure --enable-opensslall --enable-tls13 --enable-tlsx --enable-tlsv10 --enable-postauth --enable-certext --enable-certgen --enable-debug CFLAGS="-DHAVE_EX_DATA -DWOLFSSL_ERROR_CODE_OPENSSL -DHAVE_SECRET_CALLBACK -DWOLFSSL_PYTHON -DWOLFSSL_ALT_NAMES -DWOLFSSL_SIGNER_DER_CERT"
    make
fi


