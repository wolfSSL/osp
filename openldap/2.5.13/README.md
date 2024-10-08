# Building OpenLDAP with wolfSSL
+ Configure wolfSSL with `./configure --enable-openldap`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download OpenLDAP with `curl -O https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.5.13.tgz`.
+ Unarchive the tar ball with `tar xvf openldap-2.5.13.tgz`. `cd into openldap-2.5.13`.
+ Patch the OpenLDAP source code with `patch -p1 < openldap-2.5.13.patch` (assuming the patch file is in the openldap-2.5.13 directory; adjust the path according to your situation).
+ OpenLDAP developers use very old versions of autotools (see build/README). I have been able to successfully build the project without using these old tools (I'm using autoconf 2.69), but your mileage may vary.
+ Delete aclocal.m4 with `rm aclocal.m4`. If you don't do this step, you'll get weird libtool errors when you try to run make later on.
+ Regenerate the configure script with `autoreconf -ivf`. This should fail at the automake step because OpenLDAP doesn't use a Makefile.am. That's ok. We just want to run everything else (e.g. autoheader, autoconf, etc.).
+ Configure OpenLDAP with `./configure CPPFLAGS="-I/usr/local/include/wolfssl" --with-tls=wolfssl`. Add `--disable-bdb --disable-hdb` if you don't have BerkeleyDB installed and/or don't want to install it.
+ Compile dependencies with `make depend`.
+ Compile everything else with `make`.
+ Install with `sudo make install`.

# Testing
The certificates used for testing in OpenLDAP have some issues (like using '0' for the serial number). To pass all the tests run with `make check` configure wolfSSL additionally with `CPPFLAGS=-DWOLFSSL_NO_ASN_STRICT`.

# Example
This example was built using information gathered from the following:
    + https://wiki.archlinux.org/index.php/OpenLDAP
    + https://www.openldap.org/doc/admin24/quickstart.html
Unless your user has root access, commands modifying stuff under /usr will need to be prepended with sudo.

## Server Setup
+ cd to /usr/local/etc/openldap.
+ Create an ssl directory with `mkdir ssl`.
+ To enable TLS, we need to specify server certificate and private key files. We'll use the server-cert.pem and server-key.pem files from wolfssl/certs for these. Copy server-cert.pem and server-key.pem into this directory. cd back to /usr/local/etc/openldap.
+ Edit slapd.conf, which is the OpenLDAP server configuration file.
    + Add these lines to the end of slapd.conf:

    ```
    TLSCertificateFile    /usr/local/etc/openldap/ssl/server-cert.pem
    TLSCertificateKeyFile /usr/local/etc/openldap/ssl/server-key.pem
    ```

+ If you specified `--disable-bdb --disable-hdb` when configuring OpenLDAP earlier, you'll now need to create the directory /usr/local/var/openldap-data with `mkdir /usr/local/var/openldap-data`, or the next command will fail.
+ Initialize an empty database with `slapadd -l /dev/null -f slapd.conf`.
+ Create the directory slapd.d with `mkdir slapd.d`.
+ Generate the configuration for the server in slap.d with `slaptest -f slapd.conf -F slapd.d`.
+ Start the server in a terminal window with `/usr/local/libexec/slapd -d any -F /usr/local/etc/openldap/slapd.d -h "ldaps://127.0.0.1"`.

## Client Setup
+ Copy wolfssl/certs/ca-cert.pem into /usr/local/etc/openldap/ssl. This is the cert for the CA that signed server-cert.pem. The client needs it to check the server's certificate during the TLS handshake.
+ Edit the client configuration file /usr/local/etc/openldap/ldap.conf to add this line:

```
TLS_CACERT /usr/local/etc/openldap/ssl/ca-cert.pem
```

## Putting It All Together
+ With the server running in one terminal window, run a search using `ldapsearch -x -b 'dc=example,dc=com' '(objectclass=*)' -H ldaps://127.0.0.1`. You should see a response that looks like this:

```
# extended LDIF
#
# LDAPv3
# base <dc=example,dc=com> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 32 No such object

# numResponses: 1
```

+ If you were to observe this traffic in Wireshark, you'd see that it was encrypted with TLS. If you start the server without the `-h "ldaps://127.0.0.1"` part and remove the `-H ldaps://127.0.0.1` from the search command, the traffic is unencrypted in Wireshark, and the protocol would be shown as LDAP.
