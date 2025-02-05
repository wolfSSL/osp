# Introduction

In order to do a (D)TLS 1.3 connection using post-quantum authentication scheme
ML-DSA, you will need to generate the certificate chain. This file contains
instructions for using your system's OpenSSL and the OQS Provider to generate
those certificates and keys.

Note: These steps assume you are on a posix system with OpenSSL 3.x.y installed.
      You can check your version of OpenSSL with the following command:

```
openssl version
```

## OQS OpenSSL Provider

```
$ cd ~/oqs/
$ git clone https://github.com/open-quantum-safe/oqs-provider.git 
$ cd oqs-provider
$ git reset --hard afc1de27034a49c48ff656f36c021b9e046daeb0
$ ./scripts/fullbuild.sh
$ openssl list -provider-path _build/lib -provider ./oqsprovider.so -providers
```

The final command should yield the following output:

```
Providers:
  ./oqsprovider.so
    name: OpenSSL OQS Provider
    version: 0.8.1-dev
    status: active
  default
    name: OpenSSL Default Provider
    version: 3.0.2
    status: active
```


Note: OpenSSL Default Provider version might be different.

Note: There is no need to install the oqs provider.

Note: We use a known good GIT Hash. The tip of the `main` branch is probably
      fine.
 
# Generating the Certificates

We have scripts for generating certificate chains for all the variants of 
ML-DSA. simply copy `generate_dilithium_chains_with_provider.sh` into the OQS
Provider directory and execute it to generate the certificate chains. For your
convenience, this directory contains the product of these steps.

# References

- Post-quantum Appendix in our wolfSSL manual 
    - https://www.wolfssl.com/documentation/manuals/wolfssl/appendix07.html
- README file for our post-quantum examples
    - https://github.com/wolfSSL/wolfssl-examples/blob/master/pq/README.md

