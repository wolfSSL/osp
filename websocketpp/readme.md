WebSocket++ (0.8.1)
==========================

WebSocket++ is a header only C++ library that implements RFC6455 The WebSocket
Protocol. It allows integrating WebSocket client and server functionality into
C++ programs. It uses interchangeable network transport modules including one
based on raw char buffers, one based on C++ iostreams, and one based on Asio 
(either via Boost or standalone). End users can write additional transport
policies to support other networking or event libraries as needed.

Major Features
==============
* Full support for RFC6455
* Partial support for Hixie 76 / Hybi 00, 07-17 draft specs (server only)
* Message/event based interface
* Supports secure WebSockets (TLS), IPv6, and explicit proxies.
* Flexible dependency management (C++11 Standard Library or Boost)
* Interchangeable network transport modules (raw, iostream, Asio, or custom)
* Portable/cross platform (Posix/Windows, 32/64bit, Intel/ARM/PPC)
* Thread-safe

Get Involved
============

[![Build Status](https://travis-ci.org/zaphoyd/websocketpp.png)](https://travis-ci.org/zaphoyd/websocketpp)

**Project Website**
http://www.zaphoyd.com/websocketpp/

**User Manual**
http://docs.websocketpp.org/

**GitHub Repository**
https://github.com/zaphoyd/websocketpp/

GitHub pull requests should be submitted to the `develop` branch.

**Announcements Mailing List**
http://groups.google.com/group/websocketpp-announcements/

**IRC Channel**
 #websocketpp (freenode)

**Discussion / Development / Support Mailing List / Forum**
http://groups.google.com/group/websocketpp/

Author
======
Peter Thorson - websocketpp@zaphoyd.com

Building and testing WebSocket++ with wolfSSL
=============================================
Note: You will need to have the wolfSSL compatible version of Boost.Asio installed.

Install wolfSSL with the following commands:

* $ git clone https://github.com/wolfSSL/wolfssl.git
* $ ./autogen.sh
* $ ./configure --enable-opensslall --enable-opensslextra
* $ make
* $ sudo make install

To run the unit tests with ctest, execute the following commands from the root directory of WebSocket++:

Note: CMake must be installed.

* $ cmake -DBUILD_TESTS=ON -DBUILD_EXAMPLES=ON -DWOLFSSL=/path/to/wolfSSL/installation .
* $ make
* $ ctest .
* $ sudo make install       (if installing)

To run the unit tests with SCons, execute the following commands from the root directory of WebSocket++:

Note: CMake and SCons must be installed.

* $ cmake -DBUILD_TESTS=ON -DBUILD_EXAMPLES=ON -DWOLFSSL=/path/to/wolfSSL/installation .
* $ make
* $ sudo make install       (if installing)
* $ export BOOST_ROOT=/path/to/boost/root
* $ export WOLFSSL_PATH=/path/to/wolfSSL/installation
* $ scons
* $ scons test

Testing with Scons conducts more tests but requires more third party software.

If CTest passes 100% of the tests, it is more than likely that SCons will too.
