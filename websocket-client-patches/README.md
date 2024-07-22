# websocket-client wolfSSL port

This folder contains patches to add support for wolfSSL to websocket-client project.
Subfolder x.yy.zz contains patches for websocket-client version x.yy.zz.

## Installation instructions

1. Clone `websocket-client` repository and checkout to the right version (eg. v0.59.0)
```bash
git clone https://github.com/websocket-client/websocket-client.git
git checkout v0.59.0
```
2. Apply patches from this repository
```bash
git am path/to/osp/websocket-client-patches/v0.59.0/*.patch
```
3. Install wolfssl-py

Follow instructions in [wolfssl-py](https://github.com/wolfssl/wolfssl-py) repository. 

4. Install `websocket-client` from the folder where you applied patches
```bash
python -m pip install -e .
```
5. (Optional) if you want to run the test suite install the following packages
```bash
python -m pip install pysock pytest
```
6. (Optional) run the test suite. Some test requires that wolfSSL native library is compiled with the `--enable-ticket-nonce-malloc` option.
   Also, you may need to point to the right CA certificates using the environment variable WEBSOCKET_CLIENT_CA_BUNDLE, eg:
```bash
TEST_WITH_INTERNET=1 WEBSOCKET_CLIENT_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt python -m pytest websocket/tests
```
