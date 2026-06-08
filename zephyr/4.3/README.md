## How to setup wolfSSL support for standard Zephyr TLS Sockets and RNG (Zephyr 4.3)

wolfSSL can also be used as the underlying implementation for the default Zephyr TLS socket interface.
With this enabled, all existing applications using the Zephyr TLS sockets will now use wolfSSL inside
for all TLS operations. This will also enable wolfSSL as the default RNG implementation. To enable this
feature, first ensure wolfSSL has been added to the west manifest using the instructions from the
README.md here: https://github.com/wolfSSL/wolfssl/tree/master/zephyr

This integration depends on new Kconfig options added to the wolfSSL Zephyr module; use a wolfSSL
revision that includes the PR adding Zephyr 4.3 default TLS support (`WOLFSSL_SESSION_EXPORT`,
`WOLFSSL_KEEP_PEER_CERT`, `WOLFSSL_ALWAYS_VERIFY_CB`, and the `native_sim` timer gate extension).

Once the west manifest has been updated, run west update, then run the following command to patch the sources

```
patch -p1 < /path/to/your/osp/zephyr/4.3/zephyr-tls-4.3.0.patch
```

### Minimum prj.conf

Use `tests/net/socket/tls/overlay-wolfssl.conf` as a template. At minimum the application needs
`CONFIG_MBEDTLS=n`, `CONFIG_WOLFSSL=y`, and Zephyr POSIX support (`CONFIG_POSIX_API=y`,
`CONFIG_POSIX_TIMERS=y`, `CONFIG_POSIX_THREADS=y`). Size `CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE`
to the application footprint.

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
| `WOLFSSL_VERIFY_CALLBACK` | Enable wolfSSL-native per-cert verify callback via the `TLS_CERT_VERIFY_CALLBACK_WOLFSSL` socket option |

Existing wolfSSL module options (`WOLFSSL_DTLS`, `WOLFSSL_ALPN`, `WOLFSSL_PSK`,
`WOLFSSL_TLS_VERSION_1_3`, `WOLFSSL_MAX_FRAGMENT_LEN`) are opt-in as usual.

### Limitations

- TLS 1.0 and 1.1 disabled (`NO_OLD_TLS`).
- The mbedTLS-style `TLS_CERT_VERIFY_CALLBACK` socket option is not supported on the wolfSSL backend.
- `TLS_CERT_NOCOPY` has no effect — certificates are always copied.
- TLS 1.3 0-RTT not wired on the wolfSSL path.
- OCSP and CRL handling is library-internal on both backends; there is no Zephyr socket-option API for it.

### Run Zephyr TLS samples

```
west build -b <your_board> samples/net/sockets/echo_server -DEXTRA_CONF_FILE=overlay-wolfssl.conf
```

### Run Zephyr TLS tests

```
west build -b <your_board> tests/net/socket/tls_ext/ -DEXTRA_CONF_FILE=overlay-wolfssl.conf
```

```
west build -b <your_board> tests/net/socket/tls/ -DEXTRA_CONF_FILE=overlay-wolfssl.conf
```

### References

- Zephyr TLS sockets: https://docs.zephyrproject.org/latest/connectivity/networking/api/sockets.html
- wolfSSL Zephyr module: https://github.com/wolfSSL/wolfssl/tree/master/zephyr
