# Building msmtp with wolfSSL
+ Configure wolfSSL with `./configure --enable-opensslextra --enable-opensslall`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download msmtp-1.8.32 with `curl -O https://marlam.de/msmtp/releases/msmtp-1.8.32.tar.xz`.
+ Unarchive this tar ball with `tar xvf msmtp-1.8.32.tar.xz`. `cd msmtp-1.8.32`.
+ Apply the wolfssl-msmtp-1.8.32.patch file with `patch -p1 < wolfssl-msmtp-1.8.32.patch` (assuming the patch file is in the msmtp-1.8.32 directory; adjust the path according to your situation).
+ Regenerate the configure script with `autoreconf -ivf`.
+ Configure msmtp with `./configure --with-tls=wolfssl`.
+ Run `make` to compile.
+ Run `make check` to run the tests (`tests/test-basic.sh`, `tests/test-auth-plain.sh`, `tests/test-header-handling.sh`). All three are expected to pass. They do not exercise TLS: `test-basic.sh` only runs `msmtp --version` and `--help`, the other two exchange mail with `msmtpd` over plain SMTP. They also need an IPv6 loopback because `msmtpd` is bound to `::1`.
+ wolfSSL verifies the peer certificate during the handshake while OpenSSL leaves that to the application. msmtp does its own checking after the handshake, so the patch turns verification off for the `tls_fingerprint` and disabled `tls_certcheck` cases, which would otherwise abort the handshake, and turns it on explicitly for `tls_trust_file` accounts so that the result does not depend on the library default.
+ `msmtp --version` reports `TLS/SSL library: wolfSSL`.
+ TLS was verified by hand against a local TLS SMTP server: `tls_trust_file`, `tls_fingerprint` and a disabled `tls_certcheck` connect, while a wrong CA, a wrong fingerprint and a hostname mismatch are rejected, with and without STARTTLS.
