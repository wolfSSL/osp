#!/bin/bash

echo "Cloning wolfssl master to directory wolfssl-master"
git clone --depth=1 https://github.com/wolfssl/wolfssl wolfssl-master
if [ "${PIPESTATUS[0]}" != 0 ]; then
    echo "clone failed!"
    exit 1
fi
pushd wolfssl-master

echo "Running ./autogen.sh"
./autogen.sh
if [ "${PIPESTATUS[0]}" != 0 ]; then
    echo "autogen.sh failed"
    popd
    exit 1
fi

echo "Running ./configure"
./configure --enable-all --enable-tlsv10 CPPFLAGS="-DHAVE_SECRET_CALLBACK -DWOLFSSL_PYTHON"
if [ "${PIPESTATUS[0]}" != 0 ]; then
    echo "./configure failed"
    popd
    exit 1
fi

echo "Compiling wolfSSL"
make check
if [ "${PIPESTATUS[0]}" != 0 ]; then
    echo "make failed"
    popd
    exit 1
fi

popd

echo "wolfSSL compiled, please install with:"
echo ""
echo "$ cd wolfssl-master"
echo "$ sudo make install"

