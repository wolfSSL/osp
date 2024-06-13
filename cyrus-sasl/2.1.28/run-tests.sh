#!/bin/bash

# Place this file in the root directory of the cyrus-sasl
# project. Then run it:
#   ./run-tests.sh
# cyrus-sasl needs to be compiled with
#   --with-dblib=berkeley - Other db's may work but lmdb
#                           was broken for me.
#   --disable-shared - For some reason this is required.
# Packages required:
#   krb5-kdc krb5-admin-server krb5-otp libkrb5-dev 
#   libsocket-wrapper libnss-wrapper libdb5.3-dev

set -e

TESTDIR_NAME=testing-dir

# Switch to testing dir
rm -rf $TESTDIR_NAME

# Only define it here to not use it in the 'rm -rf'
TESTDIR=$(pwd)/$TESTDIR_NAME

mkdir $TESTDIR_NAME
cd $TESTDIR_NAME

# Create sasldb
echo 1234 | ../utils/saslpasswd2 -p -c -u host.realm.test -f sasldb -p ken

# This is important for following krb commands
export KRB5_CONFIG=$TESTDIR/krb.conf
export KRB5_KDC_PROFILE=$TESTDIR/krb.conf
export KRB5_CLIENT_KTNAME=$TESTDIR/user.keytab
export KRB5_KTNAME=$TESTDIR/test.keytab
export KRB5_TRACE=$TESTDIR/trace.log

# Create krb.conf
cat << EOF >> $KRB5_CONFIG
[libdefaults]
  default_realm = REALM.TEST
  dns_lookup_realm = false
  dns_lookup_kdc = false
  rdns = false
  ticket_lifetime = 24h
  forwardable = yes
  default_ccache_name = FILE://${TESTDIR}/ccache
  udp_preference_limit = 1

[domain_realm]
  .realm.test = REALM.TEST
  realm.test = REALM.TEST

[realms]
 REALM.TEST = {
  kdc = 127.0.0.9
  admin_server = 127.0.0.9
  acl_file = ${TESTDIR}/kadm.acl
  dict_file = /usr/share/dict/words
  admin_keytab = ${TESTDIR}/kadm.keytab
  database_name = ${TESTDIR}/kdc.db
  key_stash_file = ${TESTDIR}/kdc.stash
 }

[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88

[logging]
  kdc = FILE:${TESTDIR}/kdc.log
  admin_server = FILE:${TESTDIR}/kadm.log
  default = FILE:${TESTDIR}/krb5.log
EOF

# Create realm
kdb5_util create -r REALM.TEST -s -P 1234
# Add a user and generate a keytab
kadmin.local -q "addprinc -randkey ken"
kadmin.local -q "ktadd -k $KRB5_CLIENT_KTNAME ken"
# Add a service and generate a keytab
kadmin.local -q "addprinc -randkey host/host.realm.test"
kadmin.local -q "addprinc -randkey host/random.realm.test"
kadmin.local -q "ktadd -k $KRB5_KTNAME host/host.realm.test"
kadmin.local -q "ktadd -k $KRB5_KTNAME host/random.realm.test"

# Setup socket wrappers
# Check we have socket_wrapper (apt install libsocket-wrapper)
pkg-config --exists socket_wrapper
# Check we have socket_wrapper (apt install libnss-wrapper)
pkg-config --exists nss_wrapper
WRAPDIR=$TESTDIR/w
mkdir $WRAPDIR
echo '127.0.0.9 host.realm.test' > $WRAPDIR/hosts
export LD_PRELOAD='libsocket_wrapper.so libnss_wrapper.so'
export SOCKET_WRAPPER_DIR=$WRAPDIR
export SOCKET_WRAPPER_DEFAULT_IFACE=9
export NSS_WRAPPER_HOSTNAME='host.realm.test'
export NSS_WRAPPER_HOSTS=$WRAPDIR/hosts

krb5kdc -n &
KRB5KDC_PID=$!
trap "kill $KRB5KDC_PID" EXIT
sleep 0.1

../utils/testsuite
