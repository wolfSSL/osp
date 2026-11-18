## Moving a Zephyr TLS socket application from mbedTLS to wolfSSL

The wolfSSL backend implements the same Zephyr TLS socket API as the mbedTLS one, so application
code that only uses `zsock_*`, `SOL_TLS` socket options and `tls_credential_add()` builds and runs
unchanged. Most of the work is in the build configuration. These steps apply to the 4.3, 4.4 and
4.5 patch series; the version README has the details for each.

### 1. Add wolfSSL and apply the patches

1. Add wolfSSL to the west manifest as described in
   https://github.com/wolfSSL/wolfssl/tree/master/zephyr, at the revision the version README
   names, and run `west update`.
2. Apply the core patch for your Zephyr release with `git apply`, inside the `zephyr` directory.
3. If another subsystem in your image selects `CONFIG_MBEDTLS` (mcumgr or UpdateHub over DTLS,
   LwM2M, WireGuard, uuid v5), also apply the mbedTLS decoupling patch and add the wolfPSA module
   (https://github.com/wolfSSL/wolfPSA/tree/master/zephyr) as the PSA Crypto provider. Without it,
   those subsystems keep mbedTLS in the image.

### 2. Change prj.conf

Replace `CONFIG_MBEDTLS=y` and every `CONFIG_MBEDTLS_*` line with:

```
CONFIG_MBEDTLS=n
CONFIG_WOLFSSL=y
CONFIG_POSIX_API=y
CONFIG_POSIX_TIMERS=y
CONFIG_POSIX_THREADS=y
CONFIG_COMMON_LIBC_MALLOC_ARENA_SIZE=65536
```

wolfSSL allocates from the libc heap, so the arena takes the place of `CONFIG_MBEDTLS_HEAP_SIZE`.
A TLS client needs about 31 KB per connection and a server about 19 KB; measure your application
and adjust. Give each thread that runs a handshake at least 6 KB of stack, or set
`CONFIG_WOLFSSL_SMALL_STACK=y` for about 2 KB (see the version README).

Then map the mbedTLS options the application used:

| mbedTLS option | wolfSSL equivalent |
|---|---|
| `MBEDTLS_SSL_PROTO_TLS1_3` | `WOLFSSL_TLS_VERSION_1_3` |
| `MBEDTLS_SSL_PROTO_DTLS` | `WOLFSSL_DTLS` |
| `MBEDTLS_SSL_ALPN` | `WOLFSSL_ALPN` |
| `MBEDTLS_SSL_SERVER_NAME_INDICATION` (4.4 and later) | `WOLFSSL_SNI` |
| `MBEDTLS_KEY_EXCHANGE_PSK_ENABLED` | `WOLFSSL_PSK`; pick the TLS 1.3 PSK suite with `NET_SOCKETS_TLS_WOLFSSL_PSK_TLS13_CIPHERSUITE_CHOICE` |
| `MBEDTLS_SSL_CACHE_C` | nothing to set: the server cache is built in, and the client cache needs `WOLFSSL_SESSION_EXPORT`, which is on by default |
| `MBEDTLS_SSL_MAX_CONTENT_LEN` and the in/out lengths | none; wolfSSL sizes record buffers per record. To make the peer send smaller records, set `NET_SOCKETS_TLS_WOLFSSL_MAX_FRAGMENT_LENGTH` |
| `MBEDTLS_SSL_DTLS_CONNECTION_ID` | `WOLFSSL_DTLS_CID`; a server socket needs `TLS_DTLS_CID_ENABLED` to follow a client that moves (see the version README) |
| `MBEDTLS_USER_CONFIG_FILE` | `WOLFSSL_SETTINGS_FILE`; the file replaces the module's Kconfig-driven settings, and the socket layer's wolfSSL selects no longer apply |
| `NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK` | `NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK` (`WOLFSSL_VERIFY_CALLBACK` on 4.3), see below |

The wolfSSL DRBG becomes the system CSPRNG (`CONFIG_WOLFSSL_CSPRNG_GENERATOR`) without further
configuration. Algorithms (ECC, RSA and its maximum key size, ciphers) are chosen through the
wolfSSL module's own `CONFIG_WOLFSSL_*` options; its Kconfig help lists them.

### 3. Check the application code

Nothing changes for code that uses only the socket API, with these exceptions:

- **Certificate verify callback.** `TLS_CERT_VERIFY_CALLBACK` takes an mbedTLS callback and
  returns `-ENOTSUP` on wolfSSL. Port the callback to `TLS_CERT_VERIFY_CALLBACK_WOLFSSL`, whose
  `struct tls_cert_verify_cb_wolfssl` holds a context pointer and a wolfSSL verify callback,
  `int cb(int preverify_ok, void *store_ctx)`. Cast `store_ctx` to `WOLFSSL_X509_STORE_CTX *`
  inside the callback.
- **`TLS_CERT_VERIFY_RESULT`** still returns `MBEDTLS_X509_BADCERT_*` flags, from
  `<zephyr/net/tls_verify.h>`, so code that checks them keeps working without mbedTLS headers.
  Code that included `<mbedtls/x509.h>` for those names should include that header instead.
- **`TLS_CREDENTIAL_PRIVATE_KEY_PSA`** returns `-ENOTSUP`. On 4.5, the optional private-key-id
  patch adds `TLS_CREDENTIAL_PRIVATE_KEY_ID` for a key held by a crypto device.
- **`TLS_CERT_NOCOPY`** has no effect: credentials are always copied.
- **Direct mbedTLS calls** (`mbedtls_*` or `psa_*` used outside the socket layer) need either
  wolfCrypt equivalents or the wolfPSA provider for the `psa_*` ones.
- `ZSOCK_TLS_CERT_VERIFY_CALLBACK_WOLFSSL` is socket option 22 on every series; applications built
  against an older 4.3 or 4.4 patch, where it was 21, must be rebuilt.

Behaviour that applications can observe follows the mbedTLS backend: the verify levels, the
`TLS_CERT_VERIFY_RESULT` flags, session resumption, and errors such as `EIO` for a connection
closed without close_notify. The version README lists the remaining differences under
Limitations.

### 4. Verify

Build the application and run the wolfSSL test scenarios from the tests patch, for example
`west twister -p native_sim --tag wolfssl`. The mbedTLS scenarios keep passing with the patches
applied, so a mixed fleet can move one image at a time.
