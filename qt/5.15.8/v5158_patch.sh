#!/bin/sh

if [ ! -e ./qtbase ]; then
    echo Please use the script at the same level of qtbase folder.
    exit
fi

patch ./qtbase/src/network/ssl/qsslsocket_openssl_symbols_p.h qsslsymbols_h.patch
patch ./qtbase/src/network/ssl/qsslsocket_openssl_symbols.cpp qsslsymbols_cpp.patch
patch ./qtbase/src/network/ssl/qsslcertificate_openssl.cpp qsslcertificate.patch
