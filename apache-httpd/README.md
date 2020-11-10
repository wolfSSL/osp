# wolfSSL support for Apache httpd

wolfSSL provides support for Apache httpd version 2.4.46.
Requires wolfSSL v4.5.0 + patch (https://github.com/wolfSSL/wolfssl/pull/3421) or later

## Building

### Building wolfSSL

Apply the patch from the link above in the root directory of the wolfssl code:
```sh
wget https://github.com/wolfSSL/wolfssl/pull/3421.diff
patch -p1 < 3421.diff
```

Build and install wolfSSL with the enable options `--enable-apachehttpd --enable-postauth`:
```sh
./configure --enable-apachehttpd --enable-postauth
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

2. Apply the patch svn_apache_patch.diff in the root directory of the checked out httpd code:

```sh
patch -p1 < ../svn_apache_patch.diff # Assuming patch file is in the directory above
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
make clean
make -j4
sudo make install
```

If you get an error from buildconf about libtool not being found, you may need to install the libtool binary (libtool-bin on Ubuntu/Debian).

The default install directory is `/usr/local/apache2`.

Note: If having error with libxml2, make sure you have it installed (libxml2-dev on Ubuntu/Debian). You still might get an error about includes; if so, try `--with-libxml2 CFLAGS="-I/usr/include/libxml2"` or use "expat" library and replace with `--with-expat=/usr`.

See `httpd-2.4.39/INSTALL` for more information.

## Running Simple HTTPS

1) Create a configuration file:

```
sudo vim /usr/local/apache2/ssl.conf

ServerName 192.168.0.4
Listen 80
Listen 443

<VirtualHost *:443>
DocumentRoot /var/www/html
ServerName 192.168.0.4
SSLEngine on
SSLCertificateFile /home/[username]/wolfssl/certs/server-cert.pem
SSLCertificateKeyFile /home/[username]/wolfssl/certs/server-key.pem
</VirtualHost>
```

2) Run standalone: `httpd -d /usr/local/apache2 -f ssl.conf`

## Debugging httpd

```sh
# Build httpd with `--enable-debug`

sudo gdb ./httpd
b ap_process_request
run -X -d /usr/local/apache2 -f ssl.conf
```

## Running Tests

NOTE: Apache httpd tests require some perl modules. Use `perl -MCPAN -e 'install Bundle::ApacheTest'` to install.
Also `sudo cpan install LWP::Protocol::https`

1. Check out the httpd testing repository and configure:

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

Note: Requires at least wolfSSL v4.5.0 with PR https://github.com/wolfSSL/wolfssl/pull/3476

1) Make sure libpcap is installed:

```sh
sudo yum install libpcap-devel # CentOS
sudo apt install libpcap-dev   # Debian/Ubuntu
```

2) Build wolfSSL with sniffer support and disable DH (just use ECDHE):

```sh
./configure --enable-apachehttpd --enable-postauth --enable-sniffer CFLAGS="-DWOLFSSL_SNIFFER_WATCH"
make
sudo make install
```

3) Copy static ephemeral keys:

```sh
sudo cp ./certs/statickeys/dh-ffdhe2048.pem /usr/local/apache2/
sudo cp ./certs/statickeys/ecc-secp256r1.pem /usr/local/apache2/
```

4) Rebuild, install and start httpd

5) Run sniffertest to see traffic

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
./configure --enable-fips=v2 --enable-apachehttpd --enable-postauth
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

## Support

For questions please email support@wolfssl.com.
