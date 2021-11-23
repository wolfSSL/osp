# wolfSSL support for Apache httpd and curl (Post-Quantum Edition)

wolfSSL provides support for Apache httpd version 2.4.46.
Requires wolfSSL v5.0.1 + or master branch at 618b9619c5c54922d6d00a5b3b26b697199083c6 or later.

## Building

### Building liboqs

See the section in wolfSSL's INSTALL file titled "Building with liboqs for TLS 1.3 [EXPERIMENTAL]". There you will find instructions for building liboqs and the OQS team's fork of OpenSSL as well as  instructions for generating the falcon certificates. Note that when you generate your certificates, you will need to add your IP Address as a subject alternative name. See here for more details: https://www.openssl.org/docs/manmaster/man5/x509v3_config.html

Do not follow the instructions for building wolfSSL. Return here.

### Building wolfSSL

Build and install wolfSSL with the following configuration:

```sh
./configure --enable-apachehttpd --enable-postauth --enable-opensslall --enable-opensslextra --with-liboqs
make
sudo make install
```

### Building Apache httpd

Apache httpd is enabled with wolfSSL support using the option `--with-wolfssl[=DIR]`. The default directory is `/usr/local`.

1. From the base directory, checkout the httpd branch:

```sh
curl -O https://archive.apache.org/dist/httpd/httpd-2.4.46.tar.gz
tar xvf httpd-2.4.46.tar.gz
mv httpd-2.4.46 httpd
cd httpd
```

Note: The latest v2.4.x branch can be downloaded using: `svn checkout https://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x httpd`

2. Apply the patches svn_apache_patch.diff and apache-wolfssl--with-liboqs.patch in that order in the root directory of the checked out httpd code:

```sh
patch -p0 -i ../svn_apache_patch.diff           
patch -p0 -i ../apache-wolfssl-post-quantum.patch
```

(Note: This assumes the patch files are in the directory above)

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

### Building curl

Requires curl 7.80.0 or later.
After unpacking curl, do the following: 

```sh
./configure --with-wolfssl
make all
sudo make install
```

This will install the curl executable in the default location: `/usr/local/bin/curl`

## Running

### Running Simple HTTPS

1) Create a configuration file:

```
sudo vim /usr/local/apache2/ssl.conf

ServerName <YOUR_IP_ADDRESS>
Listen 80
Listen 443

<VirtualHost *:443>
DocumentRoot /usr/local/apache2/htdocs
ServerName <YOUR_IP_ADDRESS>
SSLEngine on
SSLCertificateFile /absolute/path/to/falcon_level1_entity_cert.pem
SSLCertificateKeyFile /absolute/path/to/falcon_level1_entity_key.pem 
</VirtualHost>
```

2) Run standalone: `sudo ./httpd -d /usr/local/apache2 -f ssl.conf`

## Running curl

Run curl like this:

```sh
LD_LIBRARY_PATH=/usr/local/lib /usr/local/bin/curl \
    --ciphers TLS_AES_256_GCM_SHA384 \
    --cacert /absolute/path/to/falcon_level1_root_cert.pem \
    --curve P521_KYBER_LEVEL5 \
    https://<YOUR_IP_ADDRESS>
```

You should see the following output:

```sh
<html><body><h1>It works!</h1></body></html>
```

Congratulations, you have just achieved a fully quantum-safe TLS 1.3 connection using AES-256 for symmetric encryption, the FALCON signature scheme for authentication and ECDHE hybridized with KYBER KEM for key establishment.

## Support

For questions please email support@wolfssl.com.
