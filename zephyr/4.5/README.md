## How to setup wolfSSL support for standard Zephyr TLS Sockets and RNG (Zephyr 4.5)

wolfSSL can also be used as the underlying implementation for the default Zephyr TLS socket interface.
With this enabled, all existing applications using the Zephyr TLS sockets will now use wolfSSL inside
for all TLS operations. This will also enable wolfSSL as an alternative RNG implementation. To enable
this feature, first ensure wolfSSL has been added to the west manifest using the instructions from the
README.md here: https://github.com/wolfSSL/wolfssl/tree/master/zephyr

This integration needs a wolfSSL master revision that contains pull requests
[wolfSSL/wolfssl#11977](https://github.com/wolfSSL/wolfssl/pull/11977) (merged 2026-11-06) and
[wolfSSL/wolfssl#12044](https://github.com/wolfSSL/wolfssl/pull/12044), or the first release after
both. Without #12044, wolfSSL does not build against Zephyr 4.5 at all. #12044 also removes
wolfSSL's old `RNG` type name, which collides with the CMSIS `RNG` peripheral macro on STM32
targets. wolfSSL 5.9.4 is not enough, for the same reasons as on 4.4: no OCSP build, failing
`tls_ext` suites, and no `WOLFSSL_IP_ALT_NAME` option, so IP address SANs never match.

Then patch the Zephyr tree (run inside the `zephyr` directory). The integration ships as five
patches, all generated against the Zephyr **4.5.0** release:

- **`zephyr-tls-4.5.0.patch`** - the core wolfSSL backend (the BSD-sockets TLS layer and the
  RNG/CSPRNG). This is all that is required to use wolfSSL for TLS sockets.
- **`zephyr-tls-4.5.0-tests.patch`** - the wolfSSL twister test scenarios and the echo_server
  sample overlay. Apply it only if you want to run the test suite yourself; it is not needed to
  use the integration. It depends on the core patch, so apply the core patch first.
- **`zephyr-tls-4.5.0-mbedtls-decoupling.patch`** - optional. Removes the remaining hard mbedTLS
  dependencies from subsystems whose crypto already runs through the PSA API or the TLS socket
  layer (mcumgr/UpdateHub DTLS, LwM2M and WireGuard), so an image using wolfSSL plus the wolfPSA
  PSA provider can drop `CONFIG_MBEDTLS` entirely. Apply on top of the core patch. The provider
  side is not part of this patch set: it ships in wolfPSA itself, which is a Zephyr module of its
  own (`zephyr/` subdirectory, `CONFIG_WOLFPSA=y`) - see
  https://github.com/wolfSSL/wolfPSA/tree/master/zephyr.
- **`zephyr-tls-4.5.0-private-key-id.patch`** - optional. Adds the `TLS_CREDENTIAL_PRIVATE_KEY_ID`
  credential type for a private key held by a crypto device (see below). Apply on top of the core
  patch.
- **`zephyr-tls-4.5.0-private-key-id-tests.patch`** - optional. The test scenarios for the
  private-key-id patch. Apply it after the tests patch and the private-key-id patch.

```
# required:
git apply /path/to/your/osp/zephyr/4.5/zephyr-tls-4.5.0.patch
# optional, only to run the tests:
git apply /path/to/your/osp/zephyr/4.5/zephyr-tls-4.5.0-tests.patch
# optional, to drop mbedTLS entirely (needs wolfSSL + the wolfPSA PSA provider):
git apply /path/to/your/osp/zephyr/4.5/zephyr-tls-4.5.0-mbedtls-decoupling.patch
# optional, for private keys held by a crypto device:
git apply /path/to/your/osp/zephyr/4.5/zephyr-tls-4.5.0-private-key-id.patch
# optional, only to run the private-key-id tests:
git apply /path/to/your/osp/zephyr/4.5/zephyr-tls-4.5.0-private-key-id-tests.patch
```

The tests patch adds binary DER fixtures for the OCSP tests, which `patch -p1` cannot apply, so
use `git apply` for it. The other patches also apply with `patch -p1`.

The 4.5 mbedTLS module also requires the `tf-psa-crypto` west project - make sure it is in
your manifest's allowlist before `west update`.

### Patch set version

These patches are patch set **2026.11**. The first line of each `.patch` file names its patch set,
and a tree patched with it defines `CONFIG_NET_SOCKETS_TLS_WOLFSSL_PATCH_VERSION` in every wolfSSL
TLS build, so a build shows which patch set it carries. An application can also log the string at
start-up. A wolfSSL TLS build without the symbol carries a patch set older than 2026.11.

```
grep PATCH_VERSION build/zephyr/.config
```

| Patch set | Zephyr | Changes       |
|-----------|--------|---------------|
| 2026.11   | 4.5.0  | First release |

### Minimum prj.conf

Use `tests/net/socket/tls/prj_wolfssl.conf` as a template. At minimum the application needs
`CONFIG_MBEDTLS=n`, `CONFIG_WOLFSSL=y`, and Zephyr POSIX support (`CONFIG_POSIX_API=y`,
`CONFIG_POSIX_TIMERS=y`, `CONFIG_POSIX_THREADS=y`; without `CONFIG_POSIX_API` also set
`CONFIG_POSIX_SYSTEM_INTERFACES=y`, which gates the POSIX option groups).
Size `CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE` to the application footprint.

A TLS client peaks at about 31 KB of heap and 5.3 KB of thread stack per connection with the
wolfSSL module defaults and an RSA-2048 certificate chain (measured on a Cortex-M4). A server
needs about 19 KB of heap and 3.6 KB of stack, or 27 KB and 5.2 KB when it verifies client
certificates. `CONFIG_WOLFSSL_SMALL_STACK=y` brings both stacks to about 2 KB for about 1.5 KB
more heap. The first `sys_csrand_get()` call instantiates the wolfSSL DRBG on the caller's stack,
which takes about 1.5 KB on a Cortex-M33.

### What changed compared to the Zephyr 4.4 integration

- **The TLS version is a minimum.** As on mbedTLS, an `IPPROTO_TLS_1_2` stream socket runs
  TLS 1.3 with a peer that offers it, when wolfSSL is built with TLS 1.3. A socket whose
  ciphersuite list holds no TLS 1.3 suite stays on TLS 1.2. DTLS stays at 1.2, as mbedTLS has no
  DTLS 1.3.
- **TLS 1.3 client sessions resume.** The client cache stores a TLS 1.3 session when its
  NewSessionTicket arrives, as the mbedTLS backend does.
- **The persistent session cache** (`CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT`) builds and
  works with wolfSSL.
- **`tls_credential_expiry()`** parses the certificate with wolfCrypt, so it works with the
  wolfSSL backend (except under `NO_ASN_TIME`).
- **`TLS_MAX_FRAGMENT_LENGTH`** is an upstream socket option in 4.5 (21). The integration keeps
  `ZSOCK_TLS_CERT_VERIFY_CALLBACK_WOLFSSL` at 22, the number the 4.3 and 4.4 integrations use too.
- **`TLS_CREDENTIAL_PRIVATE_KEY_ID`** ships here as an optional patch. It is not part of the 4.4
  or 4.3 integrations.
- The `http_server` test fix that the 4.4 tests patch carries is upstream in 4.5.0.

Otherwise the integration matches the 4.4 one: one `WOLFSSL` object per session with DTLS server
sessions matched by peer address, a shared `WOLFSSL_CTX` per listening socket, the
`CONFIG_WOLFSSL_CSPRNG_GENERATOR` CSPRNG choice, and `TLS_CERT_VERIFY_RESULT`, resumption and
close semantics that follow the mbedTLS backend.

### Configuration options

Kconfig help text is authoritative:
- wolfSSL module: https://github.com/wolfSSL/wolfssl/blob/master/zephyr/Kconfig
- Zephyr TLS socket layer: `subsys/net/lib/sockets/Kconfig` (after applying the patch)

Options added by this integration:

| Kconfig | Purpose |
|---|---|
| `NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK` | Enable wolfSSL-native per-cert verify callback via the `TLS_CERT_VERIFY_CALLBACK_WOLFSSL` socket option |
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

### Private keys held by a crypto device

The private-key-id patch adds `TLS_CREDENTIAL_PRIVATE_KEY_ID` to `enum tls_credential_type`, for
a private key that must not leave the hardware holding it. Register the device's reference to the
key in place of `TLS_CREDENTIAL_PRIVATE_KEY`, on the same tag as the certificate:

```c
wc_CryptoCb_RegisterDevice(MY_DEVID, my_crypto_cb, NULL);

tls_credential_add(tag, TLS_CREDENTIAL_PUBLIC_CERTIFICATE, cert, cert_len);
tls_credential_add(tag, TLS_CREDENTIAL_PRIVATE_KEY_ID, key_ref, key_ref_len);
```

Nothing selects the device explicitly. The reference is bound to `wc_CryptoCb_DefaultDevID()`,
which is `WC_USE_DEVID` when the wolfSSL build names one (as a hardware port's settings normally
do) and otherwise the first device registered. A build that names its device with `WC_USE_DEVID`
also gives every TLS context that device, so the rest of the handshake is offloaded wherever the
device supports it. Otherwise only the private key operation goes to the device. With no device
registered, `connect()` or `accept()` on a socket holding the reference fails with `ENODEV`. A
wolfSSL build with `WC_NO_DEFAULT_DEVID` has no default device, so `setsockopt(TLS_SEC_TAG_LIST)`
refuses the reference with `ENOTSUP`.

The reference is passed to wolfSSL uninterpreted. `setsockopt(TLS_SEC_TAG_LIST)` checks only that
it is at most 32 bytes long (`EINVAL` otherwise), and a certificate that does not match the key is
not caught until the handshake. The two credentials may be registered in either order.

The device must be registered before the first TLS socket is created, and wolfCrypt must be
initialized before that: either set `CONFIG_WOLFSSL_SYS_INIT=y` or call `wolfSSL_Init()` yourself
first, otherwise `wc_CryptoCb_RegisterDevice()` fails with `BUFFER_E`.

This is wolfSSL-only: the mbedTLS backend, and a wolfSSL build without crypto callbacks, reject
the credential with `-ENOTSUP`. `TLS_CREDENTIAL_PRIVATE_KEY_PSA` is not supported on the wolfSSL
backend and returns `-ENOTSUP` too.

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

All wolfSSL scenarios, including OCSP stapling and must-staple, the persistent session cache and
the ones for `tests/net/socket/register`, `tests/net/lib/tls_credentials`,
`tests/net/lib/http_server/tls` and `tests/net/lib/coap_server`, run with
`west twister -p native_sim --tag wolfssl`. On a 64-bit host without 32-bit multilib, use
`-p native_sim/native/64`.

### References

- Zephyr TLS sockets: https://docs.zephyrproject.org/latest/connectivity/networking/api/sockets.html
- wolfSSL Zephyr module: https://github.com/wolfSSL/wolfssl/tree/master/zephyr
