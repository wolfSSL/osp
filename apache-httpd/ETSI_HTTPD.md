# wolfSSL ETSI Key Manager Demo Instructions

This document describes the steps for setting up our ETSI Key Manager to demonstrate using it for middle-box style decryption of TLS v1.3 traffic.

## Building

### Building wolfSSL (TLS library / sniffer)

Note: Requires at least wolfSSL v4.7.0 with PR https://github.com/wolfSSL/wolfssl/pull/3832

```sh
$ ./autogen.sh
$ git clone https://github.com/wolfssl/wolfssl
$ cd wolfssl
$ ./autogen.sh
$ ./configure --enable-certservice --enable-sniffer --enable-apachehttpd --enable-postauth CFLAGS="-DWOLFSSL_DH_EXTRA -DWOLFSSL_SNIFFER_WATCH"
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

Notes:

* To enable all Intel (AESNI/AVX) speedups use `--enable-intelasm --enable-sp --enable-sp-asm`
* To enable all ARMv8 (aarch64) speedups use `--enable-armasm --enable-sp --enable-sp-asm`

### Building / Installing Dependencies

* libtool libtool-bin autoconf libevent libpcap-dev

#### Libevent

Install libevent version 2.0+

```sh
$ sudo apt install libevent-dev # Debian/Ubuntu
# OR
$ sudo yum install libevent-dev # RedHat/CentOS
```

Or directly from sources:

```sh
$ git clone https://github.com/libevent/libevent.git
$ cd libevent
$ ./autogen.sh
$ ./configure
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

#### libpcap

```sh
sudo apt install libpcap-dev   # Debian/Ubuntu
# OR
sudo yum install libpcap-devel # RedHat/CentOS
```

### Building wolfSSL Key Manager

Building wolfKeyMgr on *nix from git repository

```sh
$ git clone https://github.com/wolfSSL/wolfKeyMgr.git
$ cd wolfKeyMgr
$ ./autogen.sh
$ ./configure
$ make
$ make check   # (optional, but highly recommended)
$ sudo make install
```

Note: A custom install location can be specified using: `./configure --prefix=/opt/local`
Note: Use `./configure -?` to see build options.


### Building Apache httpd

Apache httpd is enabled with wolfSSL support using the option `--with-wolfssl[=DIR]`. The default directory is `/usr/local`.

Apache httpd with ETSI and Sniffer support tested with tested with Chrome, Firefox, Opera and Safari.

1) Get httpd sources

```sh
git clone https://github.com/dgarske/httpd.git
cd httpd
git checkout wolfssl_apache_etsi
```

2) Get Apache Portable Runtime library (APR)

If APR and APR-Util are already installed, skip to step 3. Otherwise, get the Apache Portable Runtime library (APR):

```sh
svn co http://svn.apache.org/repos/asf/apr/apr/trunk/ srclib/apr
```

Note: You can optionally add `--with-included-apr` to httpd ./configure below.

3) Build httpd with wolfSSL and install

```sh
./buildconf
./configure --enable-ssl --with-wolfssl --enable-mods-static=all --with-libxml2 CFLAGS="-I/usr/include/libxml2" --with-included-apr
make clean
make -j4
sudo make install
```

The default install directory is `/usr/local/apache2`.

Note: If you get an error from buildconf about libtool not being found, you may need to install the libtool binary (libtool-bin on Ubuntu/Debian).

Note: If having error with libxml2, make sure you have it installed (libxml2-dev on Ubuntu/Debian). You still might get an error about includes; if so, try `--with-libxml2 CFLAGS="-I/usr/include/libxml2"` or use "expat" library and replace with `--with-expat=/usr`.

See `httpd-2.4.39/INSTALL` for more information.


## Running wolf Key Manager for ETSI

```
$ ./src/wolfkeymgr -?
wolfKeyManager 0.4
-?          Help, print this usage
-i          Don't chdir / in daemon mode
-b          Daemon mode, run in background
-p <str>    Pid File name, default ./wolfkeymgr.pid
-l <num>    Log Level (1=Error to 4=Debug), default 4
-f <str>    Log file name, default None
-o <num>    Max open files, default  1024
-s <num>    Seconds to timeout, default 60
-r <num>    Key renewal timeout, default 3600
-t <num>    Thread pool size, default  48
-d          TLS Disable Mutual Authentication
-k <pem>    TLS Server TLS Key, default ./certs/server-key.pem
-w <pass>   TLS Server Key Password, default wolfssl
-c <pem>    TLS Server Certificate, default ./certs/server-cert.pem
-A <pem>    TLS CA Certificate, default ./certs/ca-cert.pem
```

## Running the Sniffer

From wolfSSL:
```sh
# Build the ETSI sniffer client
make sslSniffer/sslSnifferTest/sniffetsi
cd ./sslSniffer/sslSnifferTest
sudo ./sniffetsi

1. eth0 (No description available)
2. lo (No description available)
Enter the interface number (1-2) [default: 0]: 1
Enter the port to scan [default: 1443]: 1443
Enter the server key [default: https://localhost:8119]: 

# Decrypted traffic shown
```


## Running Apache

1) Create a configuration file:

```sh
mkdir /usr/local/apache2/
vim /usr/local/apache2/ssl.conf
```

```
Listen 1443
ErrorLog /var/log/apache2/error.log
CustomLog /var/log/apache2/access.log wolf
LogLevel info ssl:warn

<VirtualHost *:1443>
DocumentRoot /var/www/html
ServerName localhost
SSLEngine on
SSLCertificateFile /usr/local/apache2/test-cert.pem
SSLCertificateKeyFile /usr/local/apache2/test-key.pem
</VirtualHost>
```

2) Copy ETSI server certificate and Sniffer static ephemeral keys

From wolfKeyMgr:

```sh
cp ./certs/ca-cert.pem /usr/local/apache2/
cp ./certs/client-cert.pem /usr/local/apache2/
cp ./certs/client-key.pem /usr/local/apache2/

cp ./certs/test-key.pem /usr/local/apache2/
cp ./certs/test-cert.pem /usr/local/apache2/
```

3) Setup an HTML index page and mime.types

From httpd:

```sh
cp ./docs/docroot/index.html /var/www/html/
mkdir /usr/local/apache2/conf/
cp ./docs/conf/mime.types /usr/local/apache2/conf/
```

4) Running:

Daemon:

```sh
./httpd -d /usr/local/apache2 -f ssl.conf
```

Standalone Single Thread:

```sh
./httpd -X -d /usr/local/apache2 -f ssl.conf
```

Debugging:

```sh
gdb ./httpd
run -X -d /usr/local/apache2 -f ssl.conf
```

5) Open a web page to `https://localhost:1443` and bypass all the self-signed certificate warnings.
Or use a real server certificate and common name.

Notes:

1) Some browsers behave different with localhost and will not send the SNI extension, which may cause issues with Apache httpd. Using the physical ethernet interface IP address (example https://192.168.0.4:1443) may work better.

2) To generate a different common name in the self-signed certificate see `wolfKeyMgr/certs/gen-certs.sh` and modify CN= and copy new certificate to `/usr/local/apache2/`: 
`openssl req -new -x509 -nodes -key ./certs/test-key.pem -out ./certs/test-cert.pem -sha256 -days 7300 -batch -subj "/C=US/ST=CA/L=Seattle/O=wolfSSL/OU=Development/CN=localhost/emailAddress=info@wolfssl.com"`

3) If you get "Permission denied" errors add `sudo` to the above commands.

## Support

For questions please email support@wolfssl.com
