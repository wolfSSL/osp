# Building OpenLDAP with wolfSSL
+ Configure wolfSSL with `./configure --enable-openldap`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download OpenLDAP with `curl -O https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.6.7.tgz`.
+ Unarchive the tar ball with `tar xvf openldap-2.6.7.tgz`. `cd into openldap-2.6.7`.
+ Patch the OpenLDAP source code with `patch -p1 < openldap-2.6.7.patch` (assuming the patch file is in the openldap-2.6.7 directory; adjust the path according to your situation).
+ OpenLDAP developers use very old versions of autotools (see build/README). I have been able to successfully build the project without using these old tools (I'm using autoconf 2.69), but your mileage may vary.
+ Delete aclocal.m4 with `rm aclocal.m4`. If you don't do this step, you'll get weird libtool errors when you try to run make later on.
+ Regenerate the configure script with `autoreconf -ivf`. This should fail at the automake step because OpenLDAP doesn't use a Makefile.am. That's ok. We just want to run everything else (e.g. autoheader, autoconf, etc.).
+ Configure OpenLDAP with `./configure CPPFLAGS="-I/usr/local/include/wolfssl" --with-tls=wolfssl`.
+ Compile dependencies with `make depend`.
+ Compile everything else with `make`.
+ Install with `sudo make install`.

# Testing
The certificates used for testing in OpenLDAP have some issues (like using '0' for the serial number). To pass all the tests run with `make check` configure wolfSSL additionally with `CPPFLAGS=-DWOLFSSL_NO_ASN_STRICT`.

