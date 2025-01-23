#!/bin/bash

THIS_GIT_CONFIG="--config core.fileMode=false"
THIS_CLONE_DEPTH=
THIS_OSP_BRANCH="pr-realm-vs2022"
THIS_WOLFSSL_VERSION="v5.7.6-stable"
THIS_WOLFSSL_CLONE_DEPTH="--depth 1"

echo "git clone osp/$THIS_OSP_BRANCH"
git clone $THIS_GIT_CONFIG --branch $THIS_OSP_BRANCH      https://github.com/gojimmypi/osp.git   $THIS_CLONE_DEPTH

echo "got clone wolfssl/$THIS_WOLFSSL_VERSION"
git clone $THIS_GIT_CONFIG --branch $THIS_WOLFSSL_VERSION https://github.com/wolfssl/wolfssl.git $THIS_WOLFSSL_CLONE_DEPTH

echo "call build_wolfssl_with_realm.sh -i -r"
cd osp/realm
./build_wolfssl_with_realm.sh -i -r
