# wolfSSL support for Apache httpd

wolfSSL provides support for Apache httpd version 2.4.46.
Requires wolfSSL v4.5.0 + patch (https://github.com/wolfSSL/wolfssl/pull/3421) or later

## Building

### Building wolfSSL

Build and install wolfSSL with the enable option `--enable-apachehttpd`:

```sh
./configure --enable-apachehttpd
make
sudo make install
```

### Building Apache httpd

Apache httpd is enabled with wolfSSL support using the option `--with-wolfssl[=DIR]`. The default directory is `/usr/local`.

1. From the base directory, checkout the httpd branch:

```sh
wget https://mirrors.sonic.net/apache/httpd/httpd-2.4.46.tar.gz
tar xvf httpd-2.4.46.tar.gz
mv httpd-2.4.46 httpd
cd httpd
```

Note: The latest v2.4.x branch can be downloaded using: `svn checkout https://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x httpd`

2. Apply patch:

```sh
patch -p1 < ../svn_apache_patch.diff
```

3. If APR and APR-Util are already installed, skip to step 4. Otherwise, get the Apache Portable Runtime library (APR):

```sh
svn co http://svn.apache.org/repos/asf/apr/apr/trunk/ srclib/apr
```

Note: You can optionally add `--with-included-apr` to httpd ./configure in step 4.

4. Build with wolfSSL and install:

```sh
./buildconf
./configure --enable-ssl --with-wolfssl --disable-shared --enable-mods-static=all --with-libxml2 CFLAGS="-I/usr/include/libxml2" --with-included-apr
make
sudo make install
```

The default install directory is `/usr/local/apache2`.

Note: If having error with libxml use `--with-libxml2 CFLAGS="-I/usr/include/libxml2"`
    or use "expat" library and replace with `--with-expat=/usr`.

See `httpd-2.4.39/INSTALL` for more information.

## Running Tests

NOTE: Apache httpd tests require some perl modules. Use `perl -MCPAN -e 'install Bundle::ApacheTest'` to install.
Also `sudo cpan install LWP::Protocol::https`

1. Clone the wolfSSL testing repository and configure:

```sh
svn checkout http://svn.apache.org/repos/asf/httpd/test/framework/trunk/ httpd-test
patch -p1 < ../httpd_test_patch.diff
perl Makefile.PL /usr/local/apache2/bin/apxs
make
sudo make install
```

2. Run all tests through SSL:

```sh
t/TEST -ssl -apxs /usr/local/apache2/bin/apxs
```

To start the test server:

```sh
t/TEST -httpd /usr/local/apache2/bin/httpd -start
```

To run only SSL tests:

```sh
t/TEST t/ssl/
```

More information about apache httpd testing can be found under `httpd-test/README`

## Building Apache httpd with Sniffer

1) Make sure libpcap is installed:

```sh
sudo yum install libpcap-devel
```

2) Build wolfSSL with sniffer support and disable DH (just use ECDHE):

```sh
./configure --enable-apachehttpd --enable-sniffer CFLAGS="-DWOLFSSL_SNIFFER_WATCH"
make
sudo make install
```

3) Rebuild, install and start httpd

4) Run sniffertest to see traffic

```sh
cd ./sslSniffer/sslSnifferTest
sudo ./snifftest

1. eth0 (No description available)
Enter the interface number (1-1) [default: 0]: 1
Enter the port to scan [default: 11111]: 1443
Enter alternate SNI: 

# Decrypted traffic shown
```

Or capture with Wireshark or tcpdump:

```sh
# Run capture
sudo tcpdump -i eth0 -w 0001.pcap port 1443

# Run sniffer
cd ./sslSniffer/sslSnifferTest
./snifftest 0001.pcap ../../certs/statickeys/ecc-secp256r1.pem
```

## Building Apache httpd with FIPS

1) Build wolfSSL with FIPS enabled

```sh
./configure --enable-fips=v2 --enable-apachehttpd
make
./fips-hash.sh
make
sudo make install
```

2) Patch Apache to have FIPS callback

```c
#ifdef HAVE_FIPS
static void myFipsCb(int ok, int err, const char* hash)
{
    printf("in my Fips callback, ok = %d, err = %d\n", ok, err);
    printf("message = %s\n", wc_GetErrorString(err));
    printf("hash = %s\n", hash);

    if (err == IN_CORE_FIPS_E) {
        printf("In core integrity hash check failure, copy above hash\n");
        printf("into verifyCore[] in fips_test.c and rebuild\n");
    }
}
#endif /* HAVE_FIPS */

#ifdef HAVE_FIPS
    wolfCrypt_SetCb_fips(myFipsCb);
#endif
```

## Debugging Apache httpd

Run `t/TEST -verbose=1`.

/usr/local/apache2/bin/httpd  -d /home/dgarske/GitHub/httpd-test/t -f /home/dgarske/GitHub/httpd-test/t/conf/httpd.conf -D APACHE2 -D APACHE2_4 -D PERL_USEITHREADS
