#!/bin/bash

# Copyright 2022 wolfSSL Inc. All rights reserved.
# Original Author: Anthony Hu.
#
# Script to generate SPHINCS+ NIST Level 1,3 and 5 certificate chains; both
# small and fast variants. We will only use the SHAKE256 construction and not
# SHA256 nor HARAKA. We will only use the simple variant and not the robust
# variant. We do not label them with SHAKE256 nor simple and we remove the '+'
# for the sake of simplicity, brevity and to avoid syntax problems.
#
# Execute this script in the openssl directory after building OQS's fork of
# OpenSSL. Please see the README.md file for more details.

if [ "$OPENSSL" = "" ]; then
   OPENSSL=./apps/openssl
fi

# Generate conf files.
printf "\
[ req ]\n\
prompt                 = no\n\
distinguished_name     = req_distinguished_name\n\
\n\
[ req_distinguished_name ]\n\
C                      = CA\n\
ST                     = ON\n\
L                      = Waterloo\n\
O                      = wolfSSL Inc.\n\
OU                     = Engineering\n\
CN                     = Root Certificate\n\
emailAddress           = root@wolfssl.com\n\
\n\
[ ca_extensions ]\n\
subjectKeyIdentifier   = hash\n\
authorityKeyIdentifier = keyid:always,issuer:always\n\
keyUsage               = critical, keyCertSign\n\
basicConstraints       = critical, CA:true\n" > root.conf

printf "\
[ req ]\n\
prompt                 = no\n\
distinguished_name     = req_distinguished_name\n\
\n\
[ req_distinguished_name ]\n\
C                      = CA\n\
ST                     = ON\n\
L                      = Waterloo\n\
O                      = wolfSSL Inc.\n\
OU                     = Engineering\n\
CN                     = Entity Certificate\n\
emailAddress           = entity@wolfssl.com\n\
\n\
[ x509v3_extensions ]\n\
subjectAltName = IP:127.0.0.1\n\
subjectKeyIdentifier   = hash\n\
authorityKeyIdentifier = keyid:always,issuer:always\n\
keyUsage               = critical, digitalSignature\n\
extendedKeyUsage       = critical, serverAuth,clientAuth\n\
basicConstraints       = critical, CA:false\n" > entity.conf

###############################################################################
# SPHINCS+ NIST Level 1; Fast Variant
###############################################################################

# Generate root key and entity private keys.
${OPENSSL} genpkey -algorithm sphincsshake256128fsimple -outform pem -out sphincs_fast_level1_root_key.pem
${OPENSSL} genpkey -algorithm sphincsshake256128fsimple -outform pem -out sphincs_fast_level1_entity_key.pem

# Generate the root certificate
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 20 -key sphincs_fast_level1_root_key.pem -out sphincs_fast_level1_root_cert.pem

# Generate the entity CSR.
${OPENSSL} req -new -config entity.conf -key sphincs_fast_level1_entity_key.pem -out sphincs_fast_level1_entity_req.pem

# Generate the entity X.509 certificate.
${OPENSSL} x509 -req -in sphincs_fast_level1_entity_req.pem -CA sphincs_fast_level1_root_cert.pem -CAkey sphincs_fast_level1_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 21 -out sphincs_fast_level1_entity_cert.pem

###############################################################################
# SPHINCS+ NIST Level 3; Fast Variant
###############################################################################

# Generate root key and entity private keys.
${OPENSSL} genpkey -algorithm sphincsshake256192fsimple -outform pem -out sphincs_fast_level3_root_key.pem
${OPENSSL} genpkey -algorithm sphincsshake256192fsimple -outform pem -out sphincs_fast_level3_entity_key.pem

# Generate the root certificate
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 30 -key sphincs_fast_level3_root_key.pem -out sphincs_fast_level3_root_cert.pem

# Generate the entity CSR.
${OPENSSL} req -new -config entity.conf -key sphincs_fast_level3_entity_key.pem -out sphincs_fast_level3_entity_req.pem

# Generate the entity X.509 certificate.
${OPENSSL} x509 -req -in sphincs_fast_level3_entity_req.pem -CA sphincs_fast_level3_root_cert.pem -CAkey sphincs_fast_level3_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 31 -out sphincs_fast_level3_entity_cert.pem

###############################################################################
# SPHINCS+ NIST Level 5; Fast Variant
###############################################################################

# Generate root key and entity private keys.
${OPENSSL} genpkey -algorithm sphincsshake256256fsimple -outform pem -out sphincs_fast_level5_root_key.pem
${OPENSSL} genpkey -algorithm sphincsshake256256fsimple -outform pem -out sphincs_fast_level5_entity_key.pem

# Generate the root certificate
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 50 -key sphincs_fast_level5_root_key.pem -out sphincs_fast_level5_root_cert.pem

# Generate the entity CSR.
${OPENSSL} req -new -config entity.conf -key sphincs_fast_level5_entity_key.pem -out sphincs_fast_level5_entity_req.pem

# Generate the entity X.509 certificate.
${OPENSSL} x509 -req -in sphincs_fast_level5_entity_req.pem -CA sphincs_fast_level5_root_cert.pem -CAkey sphincs_fast_level5_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 51 -out sphincs_fast_level5_entity_cert.pem

###############################################################################
# SPHINCS+ NIST Level 1; Small Variant
###############################################################################

# Generate root key and entity private keys.
${OPENSSL} genpkey -algorithm sphincsshake256128ssimple -outform pem -out sphincs_small_level1_root_key.pem
${OPENSSL} genpkey -algorithm sphincsshake256128ssimple -outform pem -out sphincs_small_level1_entity_key.pem

# Generate the root certificate
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 20 -key sphincs_small_level1_root_key.pem -out sphincs_small_level1_root_cert.pem

# Generate the entity CSR.
${OPENSSL} req -new -config entity.conf -key sphincs_small_level1_entity_key.pem -out sphincs_small_level1_entity_req.pem

# Generate the entity X.509 certificate.
${OPENSSL} x509 -req -in sphincs_small_level1_entity_req.pem -CA sphincs_small_level1_root_cert.pem -CAkey sphincs_small_level1_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 21 -out sphincs_small_level1_entity_cert.pem

###############################################################################
# SPHINCS+ NIST Level 3; Small Variant
###############################################################################

# Generate root key and entity private keys.
${OPENSSL} genpkey -algorithm sphincsshake256192ssimple -outform pem -out sphincs_small_level3_root_key.pem
${OPENSSL} genpkey -algorithm sphincsshake256192ssimple -outform pem -out sphincs_small_level3_entity_key.pem

# Generate the root certificate
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 30 -key sphincs_small_level3_root_key.pem -out sphincs_small_level3_root_cert.pem

# Generate the entity CSR.
${OPENSSL} req -new -config entity.conf -key sphincs_small_level3_entity_key.pem -out sphincs_small_level3_entity_req.pem

# Generate the entity X.509 certificate.
${OPENSSL} x509 -req -in sphincs_small_level3_entity_req.pem -CA sphincs_small_level3_root_cert.pem -CAkey sphincs_small_level3_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 31 -out sphincs_small_level3_entity_cert.pem

###############################################################################
# SPHINCS+ NIST Level 5; Small Variant
###############################################################################

# Generate root key and entity private keys.
${OPENSSL} genpkey -algorithm sphincsshake256256ssimple -outform pem -out sphincs_small_level5_root_key.pem
${OPENSSL} genpkey -algorithm sphincsshake256256ssimple -outform pem -out sphincs_small_level5_entity_key.pem

# Generate the root certificate
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 50 -key sphincs_small_level5_root_key.pem -out sphincs_small_level5_root_cert.pem

# Generate the entity CSR.
${OPENSSL} req -new -config entity.conf -key sphincs_small_level5_entity_key.pem -out sphincs_small_level5_entity_req.pem

# Generate the entity X.509 certificate.
${OPENSSL} x509 -req -in sphincs_small_level5_entity_req.pem -CA sphincs_small_level5_root_cert.pem -CAkey sphincs_small_level5_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 51 -out sphincs_small_level5_entity_cert.pem

###############################################################################
# Verify all generated certificates.
###############################################################################
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile sphincs_fast_level1_root_cert.pem sphincs_fast_level1_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile sphincs_fast_level3_root_cert.pem sphincs_fast_level3_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile sphincs_fast_level5_root_cert.pem sphincs_fast_level5_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile sphincs_small_level1_root_cert.pem sphincs_small_level1_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile sphincs_small_level3_root_cert.pem sphincs_small_level3_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile sphincs_small_level5_root_cert.pem sphincs_small_level5_entity_cert.pem

