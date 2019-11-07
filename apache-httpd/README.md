# wolfSSL support for Apache httpd
wolfSSL provides support for Apache httpd version 2.4.39.
## Building
### Building wolfSSL
Build and install wolfSSL with the enable option `--enable-apachehttpd`:
```
$   ./configure --enable-apachehttpd
$   make && sudo make install
```
### Building Apache httpd
Apache httpd is enabled with wolfSSL support using the option `--with-wolfssl[=DIR]`. The default directory is `/usr/local`.

1. From the base directory, checkout the httpd branch:
    ```console
    $   svn checkout https://svn.apache.org/repos/asf/httpd/httpd/branches/2.4.x httpd-2.4.x/
    ```
2. Apply patch:
    ```
    $   cd httpd-2.4.x
    $   svn patch ../svn_apache_patch.diff
    ```
3. If APR and APR-Util are already installed, skip to step 4. Otherwise, get the Apache Portable Runtime library (APR):
    ```
    $   svn co http://svn.apache.org/repos/asf/apr/apr/trunk srclib/apr
    ```
4. Build with wolfSSL and install:
    ```
    $   ./buildconf
    $   ./configure --enable-ssl --with-wolfssl --disable-shared --enable-mods-static=all --with-libxml2
    $   make && sudo make install
    ```
    The default install directory is `/usr/local/apache2`.

See `httpd-2.4.39/INSTALL` for more information.

## Running Tests

NOTE: Apache httpd tests require the openssl command line utility.

1. Clone the wolfSSL testing repository and configure:
    ```
    $   git clone https://github.com/wolfssl/testing.git
    $   cd httpd-test/third-party/apache_httpd/httpd-test
    $   perl Makefile.PL /usr/local/apache2/bin/apxs 
    $   make
    ```
2. Run all tests through SSL:
    ```
    $   t/TEST -ssl -apxs /usr/local/apache2/bin/apxs 
    ```
To run only SSL tests:
    ```
    $   t/TEST t/ssl/
    ```
More information about apache httpd testing can be found under `httpd-test/README`

