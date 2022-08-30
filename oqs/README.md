# Introduction

Here the `openssl` directory has our fork of the OQS (Open Quantum-Safe)
project's fork of OpenSSL. The only files that have been changed in our fork are
configuration and generated files.

The reason we need this fork is that we have chosen to support a different set
of SPHINCS+ variants than those that were chosen by the OQS team. As such, we
enable and disable some variants and then re-generate code. We need the fork of
OpenSSL because it generates our X.509 certificates for us and we do interop
testing against it.

This in turn requires that we use a specific version of liboqs as the OpenSSL
fork expects SIKE and SIDH to be present, but it is no longer there.

Below, you will find some simple instructions on how we generated this fork.

NOTE: These instructions are informational; you can just use our fork as
specified in the instructions in the wolfssl repo's `INSTALL` file.

# liboqs

NOTE: These are the same instructions that can be found in the wolfssl repo's
      `INSTALL` file.

$ mkdir ~/oqs
$ cd ~/oqs
$ git clone --single-branch https://github.com/open-quantum-safe/liboqs.git
$ cd liboqs/
$ git checkout af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82
$ mkdir build
$ cd build
$ make all
$ sudo make install

At this point liboqs is properly installed.

# Creating our Fork of OQS's OpenSSL Fork

$ cd ~/oqs
$ git clone --single-branch --branch=OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git
$ cd openssl
$ git checkout e9160975eeb9796ff3550e8c2c35db63157a409b
$ cp /path/to/osp/oqs/generate.yml oqs-template/generate.yml
$ LIBOQS_DOCS_DIR=~/oqs/liboqs/docs python3 oqs-template/generate.py
$ ./config no-shared
$ make generate_crypto_objects
$ rm -rf configdata.pm Makefile .git
$ cd ~/oqs/
$ cp -a openssl /path/to/osp/oqs/ 

The result is what you see in the openssl directory here.
