This folder contains patches for net-snmp to work with wolfSSL. Patches make it
easier to add support for newer versions of a target library. The format of
the patch names is:
    <net-snmp version>.patch
Instructions for applying each patch are included in the patch commit
message.

## net-snmp 5.9.5 and newer

Starting with net-snmp 5.9.5 the wolfSSL support is part of upstream net-snmp
(`--with-wolfssl`), so no patch is needed. Tested with net-snmp 5.9.5.2.

wolfSSL
```
./autogen.sh
./configure --enable-net-snmp
make
make install
```

net-snmp
```
git clone --depth 1 --branch v5.9.5.2 https://github.com/net-snmp/net-snmp
cd net-snmp
autoreconf -ivf
./configure --disable-shared --with-wolfssl=/usr/local
make
autoconf --version | grep -P '2\.\d\d' -o > dist/autoconf-version
make test TESTOPTS="-e 'agentxperl'"
```

The `agentxperl` test needs the NetSNMP perl modules (`--with-perl-modules`)
and is excluded, matching the wolfSSL CI job. All other tests pass.
