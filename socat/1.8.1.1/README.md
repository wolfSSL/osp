# socat 1.8.1.1 with wolfSSL

Build wolfSSL with the configure line used by the wolfSSL CI job
(`.github/workflows/socat.yml`):

```
./configure --enable-all --enable-oldtls --enable-tlsv10 --enable-ipv6 'CPPFLAGS=-DWOLFSSL_NO_DTLS_SIZE_CHECK -DOPENSSL_COMPATIBLE_DEFAULTS'
make
make install
```

Download socat-1.8.1.1.tar.gz, apply the patch and build:

```
curl -O http://www.dest-unreach.org/socat/download/socat-1.8.1.1.tar.gz
tar xvf socat-1.8.1.1.tar.gz
cd socat-1.8.1.1
patch -p1 < socat-1.8.1.1.patch
autoreconf -vfi
./configure --with-wolfssl=/usr/local --enable-default-ipv=4
make
```

`--with-wolfssl=PATH` points at the wolfSSL install prefix (default
`/usr/local`). Add `PATH/lib` to `LD_LIBRARY_PATH` when running socat if
wolfSSL was installed outside the system library path.

Run the tests with:

```
SOCAT=$PWD/socat SHELL=/bin/bash ./test.sh -t 1.0
```

The wolfSSL CI job (`.github/workflows/socat.yml` in the wolfSSL repo)
runs the same suite in parallel bwrap network namespaces with
`--expect-fail 23,146,155,156,307,321,386,399,467,468,475,478,491,492,495,528,529`.

A full local `./test.sh -t 1.0` run as root, with stdin not a terminal
and no IPv6, gives 423 ok / 9 failed / 173 could not be performed:

```
FAILED:  146 304 326 386 399 410 487 492 495
```

TLS related:

- Test 146 OPENSSLLISTENDSA uses a DSA certificate and gets -501 (bad
  cipher suite). wolfSSL does not support DSA cipher suites.
- Test 386 OPENSSL_ECDHE requests cipher ECDHE-ECDSA-AES256-GCM-SHA384
  against an RSA server certificate. It only passes with OpenSSL because
  TLS 1.3 gets negotiated there; wolfSSL offers exactly the named suite.
- Test 399 OPENSSL_DTLS_CLIENT: when the suite runs non-interactively
  socat's stdin is at EOF, so it closes the DTLS connection before
  `openssl s_server` sends its data. It fails the same way when socat is
  linked with OpenSSL and passes when stdin is held open.
- Test 475 RCVTIMEO_DTLS: wolfSSL handles DTLS timeouts internally.
  Setting so-rcvtimeo on the socket does not affect the timeout.
- Test 402 OPENSSL_SERVERALTIP4AUTH, fixed by this patch: with an IPv6
  loopback present test.sh adds `IP.2 = ::1` to testalt.crt. wolfSSL
  returns the subjectAltName stack in reverse order, so socat compared
  the `::1` entry first and resolved the peer name `127.0.0.1` with an
  AF_INET6 hint; that lookup fails and socat treats it as fatal, so the
  client died mid-handshake. The patch skips IPv6 entries when the peer
  name is an IPv4 literal, and the test passes with and without IPv6.
  Checked here with a hand-made `::1` certificate, since this machine has
  no IPv6. The 1.8.0.x CI lists carry 402 as an expected failure for this
  reason.

The configure.ac changes force `autoreconf -vfi`, and autoheader then
regenerates the hand-maintained `config.h.in`. An `AH_BOTTOM` block in
configure.ac keeps the derived defines socat only carries in that file
(HAVE_TERMIOS_ISPEED/OSPEED/SPEED, WITH_STREAMS, HAVE_HOSTS_DENY_TABLE),
so the ispeed/ospeed terminal options and the tcpwrap deny-table options
are still compiled in; tests 459 MISSING_INTEGER and 460 INTEGER_GARBAGE
pass. The 1.8.0.x wolfSSL patches do not have this block.

Not TLS related (environment):

- Test 304 IOCTL_VOID: TIOCEXCL does not exclude root.
- Test 326 READLINE_OVFL: needs a terminal on stdin.
- Test 410 VSOCK_ECHO: no vsock device.
- Test 487 NETNS_EXEC: needs `ip netns` rights.
- Test 491 SOCKETPAIR_BOUNDARIES and test 205 TCP4ENDCLOSE: timing races
  that only show up on a loaded machine; they pass on their own with both
  wolfSSL and OpenSSL.
- Test 492 ACCEPT_FD: systemd-socket-activate drops LD_LIBRARY_PATH, so
  the exec'd socat cannot find libwolfssl.so when wolfSSL is installed
  outside the system library path.
- Test 495 POSIXMQ_RECV_MAXCHILDREN: output ordering timing race.

Tests 304, 326, 399, 410, 487 and 495 fail the same way with a socat
built against OpenSSL 3.0 on the same machine.

The remaining `--expect-fail` numbers (23, 155, 156, 307, 321, 467, 468,
478, 528, 529) are carried over unchanged from the 1.8.0.3 CI list - the
test numbering of 1.8.1.1 is identical up to test 593 and the new tests
are appended after it. They are not TLS tests (SCTP, fd handling,
statistics, procan, SOCKS chaining) and they either pass or report
"could not be performed" locally; they are kept because they are
environment-dependent in the CI runners.

Test 318 OPENSSL_ANULL exercises `ciphers=aNULL` on both ends. It needs
wolfSSL with the "aNULL" cipher list fix (anonymous suites generated and
allowed by `SSL_CTX_set_cipher_list`) to complete the handshake; without
it both ends error out. Note that upstream test.sh counts this test as
ok whatever happens, so the suite result does not show the difference.

The configure.ac was updated to have `[ ]` instead of `[]` because of
autoconf's expected format with AC_DEFINE.
