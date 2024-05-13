#!/bin/sh

if [ ! -e ./qtbase ]; then
    echo Please use the script at the same level of qtbase folder.
    exit
fi

patch ./qtbase/src/network/ssl/qsslcertificate_openssl.cpp qsslcertificate_openssl_v5159.patch
