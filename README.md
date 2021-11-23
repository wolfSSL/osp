# wolfSSL Open Source Project (osp) Ports

This repository contains wolfSSL ports into Open Source projects and packages. When porting the [wolfSSL](https://www.wolfssl.com/products/wolfssl/) lightweight SSL/TLS library into an existing Open Source project, wolfSSL tries to upstream changes/patches. This is not always possible, and as such we maintain this repository of patches and modified projects.

# Why use wolfSSL?

wolfSSL can provide several advantages over using the default SSL/TLS implementation in a project, product, or system. Some of these include:

* Portability across platforms and OS/RTOS environments
* Low/optimized memory use (runtime and footprint)
* [Best-tested](https://www.wolfssl.com/overview-of-testing-in-wolfssl/) SSL/TLS/crypto implementation available, reducing vulnerabilities
* Current protocol support, up to [TLS 1.3](https://www.wolfssl.com/tls13) and DTLS 1.2
* Progressive algorithm support (ChaCha20, Poly1305, Curve/Ed25519, etc)
* [Commercial support](https://www.wolfssl.com/products/support-and-maintenance/) available direct from wolfSSL engineers
* [Commercial licenses](https://www.wolfssl.com/license/) available (in addition to standard GPLv2)

For a full list of features, please visit the [wolfSSL product page](https://www.wolfssl.com/products/wolfssl/).

# List of Open Source Project Ports

Each project port included in this repository is contained in its own subdirectory.

| Directory | Description | Home Page | Blog | Port Documentation |
| :--- | :--- | :--- | :--- | :--- |
| apache-httpd | Apache HTTP Server | [Link](https://httpd.apache.org/) | [Link](https://www.wolfssl.com/support-apache-httpd-2-4-46-2/) | [README](./apache-httpd/README.md) |
| asio | Asio C++ Library | [Link](http://think-async.com/Asio/) | [Link](https://www.wolfssl.com/wolfssl-support-asio-boost-asio-c-libraries/) | [README](./asio/asio/README) |
| bind9 | DNS software system | [Link](https://bind9.net/) | | [README](./bind9/README) |
| cjose | JOSE for C/C++ | [Link](https://github.com/cisco/cjose) | [Link](https://www.wolfssl.com/wolfssl-cisco-cjose-port/) | [README](./cjose/README) |
| freeradius-server-2.1.12 | FreeRADIUS Server Project | [Link](https://freeradius.org/) | | [README](.freeradius-server-2.1.12/README) |
| haproxy | HAProxy | [Link](https://www.haproxy.org/) |  | [README](./haproxy/README) |
| libest | Cisco EST stack written in C | [Link](https://github.com/cisco/libest) | [Link](https://www.wolfssl.com/wolfssl-cisco-libest-port/) | [README](./libest/README) |
| libimobiledevice | Library to communicate with services on iOS devices | [Link](https://libimobiledevice.org/) | | [README](./libimobiledevice/README) |
| libsignal-protocol-c | Signal Protocol C Library | [Link](https://github.com/signalapp/libsignal-protocol-c) | [Link](https://www.wolfssl.com/wolfssl-use-with-signal/) | [README](./libsignal-protocol-c/README.md) |
| libssh2 | client-side C library for SSH2 | [Link](https://www.libssh2.org/) | [Link](https://www.wolfssl.com/open-source-project-ports-libssh2/) | [README](./libssh2/1.9.0/README.md) |
| lighttpd | lighttpd web server | [Link](https://www.lighttpd.net/) | [Link](https://www.wolfssl.com/lighttpd-support-wolfssl/) | [README](./lighttpd/README) |
| mariadb | MariaDB relational database | [Link](https://mariadb.org/) | | [README](./mariadb/10.5.11/README.md) |
| net-snmp | Simple Network Management Protocol | [Link](http://www.net-snmp.org/) | | [README](./net-snmp/README.md) |
| ntp | Network Time Protocol | [Link](http://www.ntp.org/) | [Link](https://www.wolfssl.com/open-source-project-ports-ntp/) | [README](./ntp/4.2.8p15/README.md) |
| openldap | Open source lightweight directory access protocol | [Link](https://www.openldap.org/) | [Link](https://www.wolfssl.com/open-source-project-ports-openldap/) | [README](./openldap/2.4.47/README.md) |
| openpegasus  | Open source DMTF CIM and WBEM | [Link](https://collaboration.opengroup.org/pegasus/) | [Link](https://www.wolfssl.com/openpegasus-port-support-added-wolfssl/) | [README](./openpegasus/2.14.1/README.md) |
| openresty | Nginx and LuaJIT-based web platform | [Link](https://openresty.org/en/) | | [README](./openresty/INSTRUCTIONS.md) |
| openssh-patches | OpenSSH | [Link](https://www.openssh.com/) | [Link](https://www.wolfssl.com/wolfssl-openssh-expanded-openssl-compatibility/) | [README](./openssh-patches/README) |
| ppp | Paul's PPP Package | [Link](https://ppp.samba.org/) | | [README](./ppp/README) |
| Python | Python language and interpreter | [Link](https://www.python.org/) | | [README](./Python/README.txt) |
| qt | Qt | [Link](https://www.qt.io/) | [Link](https://www.wolfssl.com/building-qt-with-wolfssl/) | [README](./qt/README.md) |
| rsyslog | rocket-fast Syslog Server | [Link](https://www.rsyslog.com/) | [Link](https://www.wolfssl.com/wolfssl-ported-rsyslog-8-2106-0/) | [README](./rsyslog/8.2106.0/README.md) |
| sblim-sfcb | SBLIM Small-footprint CIM Broker | [Link](http://sblim.sourceforge.net/wiki/index.php/Sfcb) | | [README](./sblim-sfcb/1.4.9/README.md) |
| socat | socat Multipurpose relay | [Link](http://www.dest-unreach.org/socat/) | [Link](https://www.wolfssl.com/open-source-project-ports-socat/) | 1.7.3.4 [README](./socat/1.7.3.4/README.md)<br/>1.7.4.1 [README](./socat/1.7.4.1/README.md) |
| stunnel | stunnel Proxy | [Link](https://www.stunnel.org/) | [Link](https://www.wolfssl.com/securing-stunnel-tls-1-3/) | 5.57 Unix [README](./stunnel/5.57/README_UNIX.md)<br/>5.57 Windows [README](./stunnel/5.57/README_WIN.md) |
| tcpdump | command-line packet analyzer | [Link](https://www.tcpdump.org/) | [Link](https://www.wolfssl.com/open-source-project-ports-tcpdump/) | [README](./tcpdump/4.9.3/README.md) |
| urllib3 | urllib3 HTTP client for Python | [Link](https://github.com/urllib3/urllib3) | | [README](./urllib3/README.rst) |
| websocket-client | WebSocket client for python | [Link](https://github.com/websocket-client/websocket-client) | | [README](./websocket-client/README.rst) |
| websocketpp | WebSocket++ | [Link](https://www.zaphoyd.com/projects/websocketpp/) | [Link](https://www.wolfssl.com/building-websocket-wolfssl-support/) | [README](websocketpp/readme.md) |

# Licensing

wolfSSL and wolfCrypt are either licensed for use under the GPLv2 (or at your option any later version) or a standard commercial license. For users who cannot use wolfSSL under GPLv2 (or any later version), a commercial license to wolfSSL and wolfCrypt is available. For license inquiries, please contact wolfSSL Inc. directly at licensing@wolfssl.com.

All non-wolfSSL projects in this repository are licensed under their respective project licenses.

# Support

For support or build issues, please contact the wolfSSL support team at support@wolfssl.com.
