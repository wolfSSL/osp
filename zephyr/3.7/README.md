## How to setup wolfSSL support for standard Zephyr TLS Sockets and RNG (Zephyr 3.7)

wolfSSL can also be used as the underlying implementation for the default Zephyr TLS socket interface.
With this enabled, all existing applications using the Zephyr TLS sockets will now use wolfSSL inside
for all TLS operations. This will also enable wolfSSL as the default RNG implementation. To enable this
feature, first ensure wolfSSL has been added to the west manifest using the instructions from the
README.md here: https://github.com/wolfSSL/wolfssl/tree/master/zephyr

Once the west manifest has been updated, run west update, then run the following command to patch the sources

```
patch -p1 < /path/to/your/osp/zephyr/3.7/zephyr-tls-3.7.0-rc3.patch
```

### Run Zephyr TLS samples

```
west build -b <your_board> samples/net/sockets/echo_server -DOVERLAY_CONFIG=overlay-wolfssl.conf
```

### Run Zephyr TLS tests

```
west build -b <your_board> tests/net/socket/tls_ext/ -DOVERLAY_CONFIG=overlay-wolfssl.conf
```

```
west build -b <your_board> tests/net/socket/tls/ -DOVERLAY_CONFIG=overlay-wolfssl.conf
```
