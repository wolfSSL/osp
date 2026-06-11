## How to setup wolfSSL support for standard Zephyr TLS Sockets and RNG (Zephyr 4.4)

wolfSSL can also be used as the underlying implementation for the default Zephyr TLS socket interface.
With this enabled, all existing applications using the Zephyr TLS sockets will now use wolfSSL inside
for all TLS operations. This will also enable wolfSSL as an alternative RNG implementation. To enable
this feature, first ensure wolfSSL has been added to the west manifest using the instructions from the
README.md here: https://github.com/wolfSSL/wolfssl/tree/master/zephyr

This integration depends on Kconfig options and a few small fixes in the wolfSSL Zephyr module:
Zephyr default TLS support (`WOLFSSL_SESSION_EXPORT`, `WOLFSSL_KEEP_PEER_CERT`,
`WOLFSSL_ALWAYS_VERIFY_CB`, and the `native_sim` timer gate extension) plus three Zephyr 4.4 fixes
(a `wolfio.h` include guard for the retyped 4.4 zsock prototypes, an `arpa/inet.h` include in
`test.h`, and a malloc-arena bump in the `wolfssl_tls_sock` sample). These are all in wolfSSL
upstream (master), so a recent wolfSSL revision needs no extra module patching.

Then patch the Zephyr tree (run inside the `zephyr` directory). The integration ships as two
patches, both generated against the Zephyr **4.4.1** release:

- **`zephyr-tls-4.4.1.patch`** — the core wolfSSL backend (the BSD-sockets TLS layer and the
  RNG/CSPRNG). This is all that is required to use wolfSSL for TLS sockets.
- **`zephyr-tls-4.4.1-tests.patch`** — the wolfSSL twister test scenarios and the echo_server
  sample overlay. Apply it only if you want to run the test suite yourself; it is not needed to
  use the integration. It depends on the core patch, so apply the core patch first.

```
# required:
patch -p1 < /path/to/your/osp/zephyr/4.4/zephyr-tls-4.4.1.patch
# optional, only to run the tests:
patch -p1 < /path/to/your/osp/zephyr/4.4/zephyr-tls-4.4.1-tests.patch
```

The tests patch also includes one small, wolfSSL-independent test fix —
`sizeof(sec_tag_list_verify_none)` in `tests/net/lib/http_server/tls/src/main.c`, which the
`net.http.server.tls` scenario needs on 64-bit builds. That fix is being submitted upstream
separately and is expected to land in Zephyr 4.4.2; if you apply the tests patch to a tree that
already contains it, drop the corresponding one-line hunk.

The 4.4 mbedTLS module also requires the `tf-psa-crypto` west project — make sure it is in
your manifest's allowlist before `west update`.

### Minimum prj.conf

Use `tests/net/socket/tls/prj_wolfssl.conf` as a template. At minimum the application needs
`CONFIG_MBEDTLS=n`, `CONFIG_WOLFSSL=y`, and Zephyr POSIX support (`CONFIG_POSIX_API=y`,
`CONFIG_POSIX_TIMERS=y`, `CONFIG_POSIX_THREADS=y`; without `CONFIG_POSIX_API` also set
`CONFIG_POSIX_SYSTEM_INTERFACES=y` — Zephyr 4.4 gates the POSIX option groups on it).
Size `CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE` to the application footprint.

### What changed compared to the Zephyr 4.3 integration

Zephyr 4.4 restructured the TLS socket layer and the random subsystem; the integration follows:

- **Per-session TLS contexts / DTLS multi-client servers.** Upstream 4.4 moved the TLS session
  state into per-session contexts (`struct tls_session_context`), allowing a DTLS server socket
  to serve multiple clients concurrently (bounded by
  `CONFIG_NET_SOCKETS_TLS_MAX_SESSION_CONTEXTS`). The wolfSSL backend implements full parity:
  one `WOLFSSL` object per session sharing the per-socket `WOLFSSL_CTX`, with incoming datagrams
  matched to sessions by peer address. Session matching by DTLS Connection ID is **not**
  supported on the wolfSSL backend (the `TLS_DTLS_CID*` socket options return `-ENOPROTOOPT`,
  as in 4.3); the upstream CID-based address-migration test reports as skipped under the
  wolfssl scenarios.
- **Socket option naming.** Upstream renamed the TLS socket options to `ZSOCK_TLS_*` (with
  legacy `TLS_*` aliases in `<zephyr/net/net_compat.h>`). The integration adds
  `ZSOCK_TLS_CERT_VERIFY_CALLBACK_WOLFSSL` (21) plus a `TLS_CERT_VERIFY_CALLBACK_WOLFSSL`
  compat alias, and the option struct is `struct zsock_tls_cert_verify_cb_wolfssl`
  (compat alias `tls_cert_verify_cb_wolfssl`).
- **TLS handshake timeout.** Handshakes during `connect()`/`accept()` are now bounded by the
  upstream `CONFIG_NET_SOCKETS_TLS_CONNECT_TIMEOUT` (default 10 s) on both backends.
- **RNG.** Zephyr 4.4 removed `random_ctr_drbg.c` (the CSPRNG is PSA-based now). The wolfSSL
  RNG integration is therefore a new CSPRNG choice option `CONFIG_WOLFSSL_CSPRNG_GENERATOR`
  (file `subsys/random/random_wolfssl.c`, wolfSSL Hash-DRBG seeded from the entropy driver,
  personalization string via `CONFIG_WOLFSSL_CSPRNG_PERSONALIZATION`). Select it inside
  `choice CSPRNG_GENERATOR_CHOICE` instead of the deprecated `CTR_DRBG_CSPRNG_GENERATOR`.
- **Minimum TLS version.** Upstream 4.4 enforces a minimum TLS version derived from the socket
  protocol. The wolfSSL backend keeps the 4.3 exact-version method selection
  (`wolfTLSv1_2/1_3_*_method`), which is stricter: an `IPPROTO_TLS_1_2` socket negotiates
  exactly TLS 1.2 and will not upgrade to 1.3.
- **Kconfig rename (action required when migrating from 4.3).** The option gating the
  wolfSSL-style verify callback was renamed from `CONFIG_WOLFSSL_VERIFY_CALLBACK` to
  `CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK` (the old name risked colliding with the
  wolfSSL module's own Kconfig namespace). A 4.3-era `prj.conf` still setting the old name
  fails the build with `error: Aborting due to Kconfig warnings` /
  `attempt to assign the value 'y' to the undefined symbol WOLFSSL_VERIFY_CALLBACK` —
  rename the option in your application config.

### Configuration options

Kconfig help text is authoritative:
- wolfSSL module: https://github.com/wolfSSL/wolfssl/blob/master/zephyr/Kconfig
- Zephyr TLS socket layer: `subsys/net/lib/sockets/Kconfig` (after applying the patch)

Options added by this integration:

| Kconfig | Purpose |
|---|---|
| `WOLFSSL_SESSION_EXPORT` | External session cache (serialize sessions across connections) |
| `WOLFSSL_KEEP_PEER_CERT` | Retain peer certificate after handshake |
| `WOLFSSL_ALWAYS_VERIFY_CB` | Invoke verify callback on success in addition to failure |
| `NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK` | Enable wolfSSL-native per-cert verify callback via the `TLS_CERT_VERIFY_CALLBACK_WOLFSSL` socket option (named `WOLFSSL_VERIFY_CALLBACK` in the 4.3 integration) |
| `WOLFSSL_CSPRNG_GENERATOR` | Use the wolfSSL DRBG as the system CSPRNG (`sys_csrand_get`) |
| `WOLFSSL_CSPRNG_PERSONALIZATION` | Personalization string for the wolfSSL DRBG |

Existing wolfSSL module options (`WOLFSSL_DTLS`, `WOLFSSL_ALPN`, `WOLFSSL_PSK`,
`WOLFSSL_TLS_VERSION_1_3`, `WOLFSSL_MAX_FRAGMENT_LEN`) are opt-in as usual.

### Limitations

- TLS 1.0 and 1.1 disabled (`NO_OLD_TLS`).
- The mbedTLS-style `TLS_CERT_VERIFY_CALLBACK` socket option is not supported on the wolfSSL backend.
- `TLS_CERT_NOCOPY` has no effect — certificates are always copied.
- TLS 1.3 0-RTT not wired on the wolfSSL path.
- DTLS Connection ID (`TLS_DTLS_CID*`) is not supported; DTLS server sessions are matched by
  peer address only.
- OCSP and CRL handling is library-internal on both backends; there is no Zephyr socket-option API for it.
- The test suites use the wolfSSL-internal `SendAlert()` API (via `<wolfssl/internal.h>`) to
  inject fatal alerts; that is a test-only dependency that may need attention on wolfSSL uprevs.

### Run Zephyr TLS samples

```
west build -b <your_board> samples/net/sockets/echo_server -DEXTRA_CONF_FILE=overlay-wolfssl.conf
```

### Run Zephyr TLS tests

```
west twister -p native_sim -s tests/net/socket/tls/net.socket.tls.wolfssl
west twister -p native_sim -s tests/net/socket/tls_ext/net.socket.tls.ext.wolfssl
west twister -p native_sim -s tests/net/socket/tls_ext/net.socket.tls.ext.wolfssl.verify_cb
west twister -p native_sim -s tests/subsys/random/rng/crypto.rng.random_wolfssl
```

(Additional wolfssl-tagged scenarios exist for `tests/net/socket/register`,
`tests/net/lib/tls_credentials`, `tests/net/lib/http_server/tls` and
`tests/net/lib/coap_server`: `west twister -p native_sim --tag wolfssl`.)

### References

- Zephyr TLS sockets: https://docs.zephyrproject.org/latest/connectivity/networking/api/sockets.html
- wolfSSL Zephyr module: https://github.com/wolfSSL/wolfssl/tree/master/zephyr
