# wolfSSL support for Apache httpd
wolfSSL provides support for Apache httpd version 2.4.39.
## Building
### Building wolfSSL
Build and install wolfSSL with the enable option `--enable-apachehttpd`:
```
$	./configure --enable-apachehttpd
$	make && sudo make install
```
---
### Building Apache httpd
Apache httpd is enabled with wolfSSL support using the option `--with-wolfssl[=DIR]`. The default directory is `/usr/local`.

1. From the base directory, clone and unzip the repository:
	```console
	$	curl -o httpd-2.4.39.tar.gz http://apache.cs.utah.edu//httpd/httpd-2.4.39.tar.gz
	$	tar -xzvf httpd-2.4.39.tar.gz
	```
2. Apply patch:
	```
	$	cd httpd-2.4.39
	$	patch -p1 < ../apache_httpd_patch.diff
	```
3. Build with wolfSSL and install:
	```
	$	./configure --enable-ssl --with-wolfssl --disable-shared --enable-mods-static=all --with-libxml2
	$	make && sudo make install
	```
---

## Running Tests
TODO: add test information
