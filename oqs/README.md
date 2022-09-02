# Introduction

The `openssl-sphincs.patch` file has our modifications to the OQS (Open
Quantum-Safe) project's fork of OpenSSL. The only files that our patch changes
are configuration and generated files.

The reason we need this patch is that we have chosen to support a different set
of SPHINCS+ variants than those that were chosen by the OQS team. As such, we
enable and disable some variants and then re-generate code. We need the patched
fork of OpenSSL because it generates our X.509 certificates for us and we do
interop testing against it.

This in turn requires that we use a specific version of liboqs as the OpenSSL
fork expects SIKE and SIDH to be present, but it is no longer there.

You can fetch OpenSSL source, apply our patch, build the code and then generate
the certificates. Instructions for doing it all are below.

# Building our Fork

Below, you will find some simple instructions on how to build and patch OQS's
fork of OpenSSL.

## liboqs

NOTE: These are the same instructions that can be found in the wolfssl repo's
      `INSTALL` file. If you already followed the instructions there, you can
      skip this section.

```
$ mkdir ~/oqs
$ cd ~/oqs
$ git clone --single-branch https://github.com/open-quantum-safe/liboqs.git
$ cd liboqs/
$ git checkout af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82
$ mkdir build
$ cd build
$ make all
$ sudo make install
```

At this point liboqs is properly installed.

## OpenSSL

```
$ cd ~/oqs/
$ git clone --single-branch --branch=OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git
$ cd openssl
$ git checkout e9160975eeb9796ff3550e8c2c35db63157a409b
$ patch -p1 < /path/to/osp/oqs/openssl-sphincs.patch
$ ./config no-shared
$ make all
```

NOTE: There is no need to install OpenSSL.

# Generating the Certificates

We have scripts for generating certificate chains for all the variants of all
the post-quantum algorithms that we support. simply copy them into the openssl
directory and execute them to generate the certificate chains.

# References

- Post-quantum Appendix in our wolfSSL manual 
    - https://www.wolfssl.com/documentation/manuals/wolfssl/appendix07.html
- README file for our post-quantum examples
    - https://github.com/wolfSSL/wolfssl-examples/blob/master/pq/README.md

# Generating the Patch

Below, you will find some simple instructions on how we generated the patch
file.

## Creating our Fork of OQS's OpenSSL Fork

NOTE: These instructions are informational; you can just patch and build OpenSSL
      as specified in the instructions above.

```
$ cd ~/oqs/
$ git clone --single-branch --branch=OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git
$ cd openssl
$ git checkout e9160975eeb9796ff3550e8c2c35db63157a409b
$ cp /path/to/osp/oqs/generate.yml oqs-template/generate.yml
$ LIBOQS_DOCS_DIR=~/oqs/liboqs/docs python3 oqs-template/generate.py
$ ./config no-shared
$ make generate_crypto_objects
$ rm configdata.pm Makefile
$ git diff > /path/to/osp/oqs/openssl-sphincs.patch
```
