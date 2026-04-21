## How to setup wolfSSL support for standard Zephyr TLS Sockets and RNG (Zephyr 4.3)

wolfSSL can also be used as the underlying implementation for the default Zephyr TLS socket interface.
With this enabled, all existing applications using the Zephyr TLS sockets will now use wolfSSL inside
for all TLS operations. This will also enable wolfSSL as the default RNG implementation. To enable this
feature, first ensure wolfSSL has been added to the west manifest using the instructions from the
README.md here: https://github.com/wolfSSL/wolfssl/tree/master/zephyr

This integration depends on the default Zephyr TLS support changes in the wolfSSL module. The required
changes are contained in wolfSSL after the merge of the associated default-TLS-support PR; use a wolfSSL
revision that includes those changes.

Once the west manifest has been updated, run west update, then run the following command to patch the sources

```
patch -p1 < /path/to/your/osp/zephyr/4.3/zephyr-tls-4.3.0.patch
```

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
