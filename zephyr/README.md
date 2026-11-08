## wolfSSL support for standard Zephyr TLS Sockets and RNG

This directory contains the patches that enable wolfSSL as the underlying
implementation for Zephyr's default TLS socket interface, organized by
Zephyr release.

| Zephyr version | Patch set | Patch and instructions                     |
|----------------|-----------|--------------------------------------------|
| 3.7            | -         | [3.7/README.md](3.7/README.md)             |
| 4.3            | 2026.11   | [4.3/README.md](4.3/README.md)             |
| 4.4            | 2026.11   | [4.4/README.md](4.4/README.md)             |
| 4.5            | 2026.11   | [4.5/README.md](4.5/README.md)             |

Each release of the patches carries a date-based patch set version.
The README of each Zephyr version lists them and shows how to check
which one a tree carries.

Moving an existing application from mbedTLS: [MIGRATING-FROM-MBEDTLS.md](MIGRATING-FROM-MBEDTLS.md).

For general information on wolfSSL as a Zephyr module, see
https://github.com/wolfSSL/wolfssl/tree/master/zephyr.
