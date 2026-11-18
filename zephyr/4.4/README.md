## How to setup wolfSSL support for standard Zephyr TLS Sockets and RNG (Zephyr 4.4)

wolfSSL can also be used as the underlying implementation for the default Zephyr TLS socket interface.
With this enabled, all existing applications using the Zephyr TLS sockets will now use wolfSSL inside
for all TLS operations. This will also enable wolfSSL as an alternative RNG implementation. To enable
this feature, first ensure wolfSSL has been added to the west manifest using the instructions from the
README.md here: https://github.com/wolfSSL/wolfssl/tree/master/zephyr

This integration needs a wolfSSL master revision that contains pull request
[wolfSSL/wolfssl#11977](https://github.com/wolfSSL/wolfssl/pull/11977) (merged 2026-11-06), or the
first release after 5.9.4. The patches were tested against that merge commit. wolfSSL 5.9.4 is not
enough: the OCSP scenarios do not build with it and the `tls_ext` suites fail. Its Zephyr module
also lacks the `WOLFSSL_IP_ALT_NAME` option the socket layer selects; Kconfig drops that select
silently, and IP address SANs then never match.

On STM32 targets, wolfSSL's old `RNG` type name collides with the CMSIS `RNG` peripheral macro.
A plain build only warns, but twister's `-Werror` turns it into an error. Pull request
[wolfSSL/wolfssl#12044](https://github.com/wolfSSL/wolfssl/pull/12044) removes the old name.

Then patch the Zephyr tree (run inside the `zephyr` directory). The integration ships as three
patches, all generated against the Zephyr **4.4.2** release:

- **`zephyr-tls-4.4.2.patch`** - the core wolfSSL backend (the BSD-sockets TLS layer and the
  RNG/CSPRNG). This is all that is required to use wolfSSL for TLS sockets.
- **`zephyr-tls-4.4.2-tests.patch`** - the wolfSSL twister test scenarios and the echo_server
  sample overlay. Apply it only if you want to run the test suite yourself; it is not needed to
  use the integration. It depends on the core patch, so apply the core patch first.
- **`zephyr-tls-4.4.2-mbedtls-decoupling.patch`** - optional. Removes the remaining hard mbedTLS
  dependencies from subsystems whose crypto already runs through the PSA API or the TLS socket
  layer (mcumgr/UpdateHub DTLS, LwM2M, WireGuard, and uuid v5), so an image using wolfSSL plus the
  wolfPSA PSA provider can drop `CONFIG_MBEDTLS` entirely. Apply on top of the core patch. The
  provider side is not part of this patch set: it ships in wolfPSA itself, which is a Zephyr
  module of its own (`zephyr/` subdirectory, `CONFIG_WOLFPSA=y`) - see
  https://github.com/wolfSSL/wolfPSA/tree/master/zephyr.

```
# required:
git apply /path/to/your/osp/zephyr/4.4/zephyr-tls-4.4.2.patch
# optional, only to run the tests:
git apply /path/to/your/osp/zephyr/4.4/zephyr-tls-4.4.2-tests.patch
# optional, to drop mbedTLS entirely (needs wolfSSL + the wolfPSA PSA provider):
git apply /path/to/your/osp/zephyr/4.4/zephyr-tls-4.4.2-mbedtls-decoupling.patch
```

The tests patch adds binary DER fixtures for the OCSP tests, which `patch -p1` cannot apply, so
use `git apply` for it. The other two patches also apply with `patch -p1`.

The tests patch also includes one small, wolfSSL-independent test fix -
`sizeof(sec_tag_list_verify_none)` in `tests/net/lib/http_server/tls/src/main.c`, which the
`net.http.server.tls` scenario needs on 64-bit builds. The fix is upstream in Zephyr 4.5.0 but
not in 4.4.2.

The 4.4 mbedTLS module also requires the `tf-psa-crypto` west project - make sure it is in
your manifest's allowlist before `west update`.

### Patch set version

These patches are patch set **2026.11**. The first line of each `.patch` file names its patch set,
and a tree patched with it defines `CONFIG_NET_SOCKETS_TLS_WOLFSSL_PATCH_VERSION` in every wolfSSL
TLS build, so a build shows which patch set it carries. An application can also log the string at
start-up. A wolfSSL TLS build without the symbol carries a patch set older than 2026.11.

```
grep PATCH_VERSION build/zephyr/.config
```

| Patch set | Zephyr | Changes                                                                               |
|-----------|--------|---------------------------------------------------------------------------------------|
| 2026.11   | 4.4.2  | Rebased onto 4.4.2, see [Changes since the 4.4.1 patch](#changes-since-the-441-patch) |
| 2026.08   | 4.4.1  | Optional mbedTLS-decoupling patch, backend fixes                                      |
| 2026.06   | 4.4.1  | First release                                                                         |

### Minimum prj.conf

Use `tests/net/socket/tls/prj_wolfssl.conf` as a template. At minimum the application needs
`CONFIG_MBEDTLS=n`, `CONFIG_WOLFSSL=y`, and Zephyr POSIX support (`CONFIG_POSIX_API=y`,
`CONFIG_POSIX_TIMERS=y`, `CONFIG_POSIX_THREADS=y`; without `CONFIG_POSIX_API` also set
`CONFIG_POSIX_SYSTEM_INTERFACES=y` - Zephyr 4.4 gates the POSIX option groups on it).
Size `CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE` to the application footprint.

A TLS client peaks at about 31 KB of heap and 5.3 KB of thread stack per connection with the
wolfSSL module defaults and an RSA-2048 certificate chain (measured on a Cortex-M4). A server
needs about 19 KB of heap and 3.6 KB of stack, or 27 KB and 5.2 KB when it verifies client
certificates. `CONFIG_WOLFSSL_SMALL_STACK=y` (wolfSSL/wolfssl#12044) brings both stacks to about
2 KB for about 1.5 KB more heap; with an older wolfSSL, define `WOLFSSL_SMALL_STACK` in a settings
file or with `CONFIG_COMPILER_OPT="-DWOLFSSL_SMALL_STACK"`. The first `sys_csrand_get()` call
instantiates the wolfSSL DRBG on the caller's stack, which takes about 1.5 KB on a Cortex-M33.

### Changes since the 4.4.1 patch

- **Rebased onto Zephyr 4.4.2.** The client session cache now shares upstream's new
  `session_cache_lock` instead of taking a second lock of its own.
- **Socket option number (rebuild required).** `TLS_CERT_VERIFY_CALLBACK_WOLFSSL` moved from 21
  to 22, because 21 is now `TLS_MAX_FRAGMENT_LENGTH`, backported from Zephyr 4.5 with the same
  number. Applications compiled against the 4.4.1 patch must be rebuilt.
- **Session resumption is on by default.** The socket layer now implies
  `CONFIG_WOLFSSL_SESSION_EXPORT`, which the client session cache needs. Before, `TLS_SESSION_CACHE`
  was accepted without it and every reconnect ran a full handshake.
- **Server sockets share one `WOLFSSL_CTX`.** A listening socket builds its context at the first
  `accept()` and every accepted socket takes a reference, instead of parsing all credentials again
  per connection. The listener rebuilds it when an option the context is built from is set on it
  or a credential is added or deleted. As a side effect, a client reconnecting to the same
  listener can resume a TLS 1.3 session.
- **`TLS_CERT_VERIFY_RESULT` matches mbedTLS.** It reports `MBEDTLS_X509_BADCERT_SKIP_VERIFY`
  under `TLS_PEER_VERIFY_NONE` and for PSK, and `MBEDTLS_X509_BADCERT_MISSING` when a server got no
  client certificate. A resumed client session reports the result its first handshake had.
- **Resumption under `TLS_PEER_VERIFY_REQUIRED`.** A `REQUIRED` client resumes only a cached
  session whose certificate was verified, or one a PSK authenticated. A session first set up under
  `OPTIONAL` or `NONE` costs a full handshake.
- **A TCP FIN without close_notify is an error.** `recv()` fails with `EIO` instead of returning
  0, as on mbedTLS, so a truncated stream no longer looks complete.
- **TLS 1.0, 1.1 and DTLS 1.0 sockets run as 1.2** instead of failing with `ENOTSUP`, as on
  mbedTLS 4, which builds none of those versions.
- **`send()` sends one TLS record per call** on stream sockets and returns the number of bytes it
  took, as mbedTLS does. An oversized DTLS datagram fails with `ECONNABORTED`.
- **IP address SANs** match a `TLS_HOSTNAME` that is an IP literal (the socket layer selects
  `CONFIG_WOLFSSL_IP_ALT_NAME`), and `TLS_HOSTNAME` set to `NULL` turns the name check off.
- **Builds against a client-only (`NO_WOLFSSL_SERVER`) or server-only (`NO_WOLFSSL_CLIENT`)
  wolfSSL**; a socket of the missing role then fails with `ENOTSUP`.
- **New options:** OCSP stapling and must-staple, and the maximum fragment length (see below).
- **DTLS Connection ID.** The `TLS_DTLS_CID*` socket options now work on wolfSSL (see below).
- **Peer chain certificates no longer become trusted CAs.** Under `TLS_PEER_VERIFY_OPTIONAL`, or
  with a wolfSSL verify callback that accepts a failed certificate, wolfSSL added the peer's CA
  certificates to the socket's trust store, so a later handshake on the same listener or DTLS
  socket could verify against them. The socket layer now drops them after each handshake.
- Many smaller fixes to DTLS timeouts and retransmission, session teardown, secret scrubbing,
  `poll()` after `shutdown()`, `connect()` on a socket set up as a DTLS server, and error
  reporting.

### What changed compared to the Zephyr 4.3 integration

Zephyr 4.4 restructured the TLS socket layer and the random subsystem; the integration follows:

- **Per-session TLS contexts / DTLS multi-client servers.** Upstream 4.4 moved the TLS session
  state into per-session contexts (`struct tls_session_context`), allowing a DTLS server socket
  to serve multiple clients concurrently (bounded by
  `CONFIG_NET_SOCKETS_TLS_MAX_SESSION_CONTEXTS`). The wolfSSL backend implements full parity:
  one `WOLFSSL` object per session sharing the per-socket `WOLFSSL_CTX`, with incoming datagrams
  matched to sessions by peer address, or by DTLS Connection ID when the client's address
  changes (see below).
- **Socket option naming.** Upstream renamed the TLS socket options to `ZSOCK_TLS_*` (with
  legacy `TLS_*` aliases in `<zephyr/net/net_compat.h>`). The integration adds
  `ZSOCK_TLS_CERT_VERIFY_CALLBACK_WOLFSSL` (22) plus a `TLS_CERT_VERIFY_CALLBACK_WOLFSSL`
  compat alias, and the option struct is `struct zsock_tls_cert_verify_cb_wolfssl`
  (compat alias `tls_cert_verify_cb_wolfssl`).
- **TLS handshake timeout.** Handshakes during `connect()`/`accept()` are now bounded by the
  upstream `CONFIG_NET_SOCKETS_TLS_CONNECT_TIMEOUT` (default 10 s) on both backends.
- **RNG.** Zephyr 4.4 removed `random_ctr_drbg.c` (the CSPRNG is PSA-based now). The wolfSSL
  RNG integration is therefore a new CSPRNG choice option `CONFIG_WOLFSSL_CSPRNG_GENERATOR`
  (file `subsys/random/random_wolfssl.c`, wolfSSL Hash-DRBG seeded from the entropy driver).
  It is the default CSPRNG when wolfSSL is built.
- **Minimum TLS version.** Upstream 4.4 enforces a minimum TLS version derived from the socket
  protocol. The wolfSSL backend pins `IPPROTO_TLS_1_2` and `IPPROTO_TLS_1_3` sockets to exactly
  that version: an `IPPROTO_TLS_1_2` socket will not upgrade to 1.3. Treating it as a minimum
  would move every TLS 1.2 socket to TLS 1.3 under the wolfSSL module defaults, where this
  branch's client cache cannot resume. The 4.5 integration treats the version as a minimum.
- **Kconfig rename (action required when migrating from 4.3).** The option gating the
  wolfSSL-style verify callback was renamed from `CONFIG_WOLFSSL_VERIFY_CALLBACK` to
  `CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK` (the old name risked colliding with the
  wolfSSL module's own Kconfig namespace). A 4.3-era `prj.conf` still setting the old name
  fails the build with `error: Aborting due to Kconfig warnings` /
  `attempt to assign the value 'y' to the undefined symbol WOLFSSL_VERIFY_CALLBACK` -
  rename the option in your application config.

### Configuration options

Kconfig help text is authoritative:
- wolfSSL module: https://github.com/wolfSSL/wolfssl/blob/master/zephyr/Kconfig
- Zephyr TLS socket layer: `subsys/net/lib/sockets/Kconfig` (after applying the patch)

Options added by this integration:

| Kconfig | Purpose |
|---|---|
| `NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK` | Enable wolfSSL-native per-cert verify callback via the `TLS_CERT_VERIFY_CALLBACK_WOLFSSL` socket option (named `WOLFSSL_VERIFY_CALLBACK` in the 4.3 integration) |
| `NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING` | Make client sockets send the certificate status request extension, so the server staples an OCSP response and revocation is checked without reaching a responder |
| `NET_SOCKETS_TLS_WOLFSSL_OCSP_MUST_STAPLE` | Fail the handshake when the server staples no OCSP response |
| `NET_SOCKETS_TLS_WOLFSSL_MAX_FRAGMENT_LENGTH` | Largest record a client socket asks the peer to send (default 16384, which sends no extension) |
| `NET_SOCKETS_TLS_WOLFSSL_PSK_TLS13_CIPHERSUITE_CHOICE` | The ciphersuite the TLS 1.3 PSK callbacks return, since a Zephyr PSK credential carries no hash |
| `WOLFSSL_CSPRNG_GENERATOR` | Use the wolfSSL DRBG as the system CSPRNG (`sys_csrand_get`) |

`CONFIG_NET_SOCKETS_SOCKOPT_TLS` force-selects the wolfSSL module options the backend relies
on, so an application config does not have to set them:

| Kconfig | Purpose |
|---|---|
| `WOLFSSL_OPENSSL_EXTRA_X509_SMALL` | Exposes `WOLFSSL_X509_STORE_CTX::current_cert`, which the verify callback reads for the leaf CN/SAN match |
| `WOLFSSL_ALWAYS_VERIFY_CB` | Invoke verify callback on success in addition to failure - without it the CN/SAN match is silently bypassed |
| `WOLFSSL_SESSION_CACHE` | Without it no session can be resumed, and `TLS_SESSION_CACHE` has nothing to switch off |
| `WOLFSSL_IP_ALT_NAME` | Match IP address SANs against an IP literal in `TLS_HOSTNAME` |

It also implies `WOLFSSL_SESSION_EXPORT`, which the client session cache needs; a size-constrained
build can turn it off and lose client resumption.

Only `WOLFSSL_ALWAYS_VERIFY_CB` is strictly required; the others are selected because their
absence costs behaviour rather than compilation. A settings-file build cannot see these selects
at all, and the backend builds without them: the CN/SAN match falls back to
`wolfSSL_check_domain_name()` (which insists on a syntactically valid FQDN, so short names and IP
literals stop working), and `NO_SESSION_CACHE` simply means no resumption.

`CONFIG_WOLFSSL_SNI` is optional: with it disabled the Server Name Indication extension is not
sent, but a configured `TLS_HOSTNAME` still drives the certificate CN/SAN match that
`TLS_PEER_VERIFY` relies on. `CONFIG_WOLFSSL_CRYPTO_ONLY` is incompatible with TLS sockets and
is rejected with a build error. Existing wolfSSL module options (`WOLFSSL_DTLS`, `WOLFSSL_ALPN`,
`WOLFSSL_PSK`, `WOLFSSL_TLS_VERSION_1_3`) are opt-in as usual.

### OCSP stapling

With `CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING`, a client socket asks the server to staple an
OCSP response for its certificate. What happens to a bad response follows `TLS_PEER_VERIFY`:
under `REQUIRED` a revoked or invalid response fails the handshake, and under `OPTIONAL` and
`NONE` the handshake goes on and `TLS_CERT_VERIFY_RESULT` reports it
(`MBEDTLS_X509_BADCERT_REVOKED` for a revoked certificate). Must-staple is enforced only under
`REQUIRED`. An OCSP response carries its own validity dates, so a target without a trusted clock
needs `CONFIG_WOLFSSL_NO_ASN_TIME_CHECK`, which also stops those dates being checked. Server
sockets staple a response only if the application supplies one.

### Maximum fragment length

The default of 16384 sends no max_fragment_length extension. Set
`CONFIG_NET_SOCKETS_TLS_WOLFSSL_MAX_FRAGMENT_LENGTH` to 512, 1024, 2048 or 4096 to make the peer
send smaller records, or use the `TLS_MAX_FRAGMENT_LENGTH` socket option per socket. The wolfSSL
module used to advertise 2048 through `CONFIG_WOLFSSL_MAX_FRAGMENT_LEN`, which wolfSSL 5.9.4
removed; set the socket-layer option instead. A reused DTLS socket keeps a length it already
advertised.

### DTLS Connection ID

The `TLS_DTLS_CID*` socket options work once wolfSSL is built with `WOLFSSL_DTLS_CID`. Use
wolfSSL/wolfssl#12044 or later, which adds `CONFIG_WOLFSSL_DTLS_CID` and fixes CBC suites when
only one peer sends a CID. A DTLS server then keeps a session when its client's address changes,
and moves the session to the new address only after a record from there authenticates. Two
differences from mbedTLS:

- The server finds a moved client by the server's own CID, so set `TLS_DTLS_CID_ENABLED` on the
  server socket. With `TLS_DTLS_CID_SUPPORTED` it sends no CID and cannot follow a client that
  moves.
- Each server session draws its own random CID unless `TLS_DTLS_CID_VALUE` sets one. A set CID
  is shared by all sessions of the socket, so the server can then follow only the first of them.

### Limitations

- A client that never sets `TLS_HOSTNAME` is rejected under `TLS_PEER_VERIFY_REQUIRED`, because
  there is no name to check the peer certificate against. This matches the mbedTLS backend, which
  sets an empty hostname for that case so no certificate can match. Set `TLS_HOSTNAME`, or use
  `TLS_PEER_VERIFY_OPTIONAL` and read `TLS_CERT_VERIFY_RESULT`, or `TLS_PEER_VERIFY_NONE`.
- TLS 1.3 client sessions are not resumed: the client cache stores a session at `connect()`,
  before a TLS 1.3 server sends its ticket. TLS 1.2 client sessions resume.
- A `REQUIRED` server can resume a TLS 1.2 session that another listener verified against a
  different CA. The mbedTLS backend behaves the same.
- With `HAVE_SECURE_RENEGOTIATION`, a renegotiation fails when a certificate above the leaf
  fails verification, even under `TLS_PEER_VERIFY_OPTIONAL` or a wolfSSL verify callback that
  accepts it. A listening socket that allows TLS 1.2 and uses either of those also gives each
  accepted socket its own context in such a build, so its session tickets do not resume across
  connections.
- With `OPENSSL_COMPATIBLE_DEFAULTS`, wolfSSL reports certificate errors in OpenSSL's codes, so
  `TLS_CERT_VERIFY_RESULT` shows them as `MBEDTLS_X509_BADCERT_OTHER`.
- The mbedTLS-style `TLS_CERT_VERIFY_CALLBACK` socket option is not supported on the wolfSSL backend.
- `TLS_CERT_NOCOPY` has no effect - certificates are always copied.
- TLS 1.3 0-RTT not wired on the wolfSSL path.
- CRL handling is library-internal on both backends, and there is no Zephyr socket-option API
  for it.
- The test suites use the wolfSSL-internal `SendAlert()` API (via `<wolfssl/internal.h>`) to
  inject fatal alerts; that is a test-only dependency that may need attention on wolfSSL uprevs.

### Run Zephyr TLS samples

```
west build -b <your_board> samples/net/sockets/echo_server -DEXTRA_CONF_FILE=overlay-wolfssl.conf
```

### Run Zephyr TLS tests

```
west twister -p native_sim -s tests/net/socket/tls/net.socket.tls.wolfssl
west twister -p native_sim -s tests/net/socket/tls/net.socket.tls.wolfssl_dtls_cid
west twister -p native_sim -s tests/net/socket/tls_ext/net.socket.tls.ext.wolfssl
west twister -p native_sim -s tests/net/socket/tls_ext/net.socket.tls.ext.wolfssl.verify_cb
west twister -p native_sim -s tests/subsys/random/rng/crypto.rng.random_wolfssl
```

All wolfSSL scenarios, including OCSP stapling and must-staple and the ones for
`tests/net/socket/register`, `tests/net/lib/tls_credentials`, `tests/net/lib/http_server/tls`
and `tests/net/lib/coap_server`, run with `west twister -p native_sim --tag wolfssl`. On a 64-bit
host without 32-bit multilib, use `-p native_sim/native/64`.

### References

- Zephyr TLS sockets: https://docs.zephyrproject.org/latest/connectivity/networking/api/sockets.html
- wolfSSL Zephyr module: https://github.com/wolfSSL/wolfssl/tree/master/zephyr
