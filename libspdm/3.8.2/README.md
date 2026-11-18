# Building libspdm 3.8.2 with wolfSSL

This folder contains the patch to build libspdm 3.8.2 against wolfSSL. The
patch is named `libspdm-<version>.patch` and its commit message documents the
exact build and test steps. Summary:

+ Configure wolfSSL with
  `./configure --enable-all --enable-static CFLAGS='-DRSA_MIN_SIZE=512'`
  (wolfSSL master or a release that provides `EVP_PKEY_dup`). Add
  `--enable-debug` for debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Clone libspdm with `git clone --branch 3.8.2 https://github.com/DMTF/libspdm.git`
  and `cd libspdm`.
+ Apply the patch with `patch -p1 < <path-to-osp>/libspdm/3.8.2/libspdm-3.8.2.patch`.
+ Set up the git submodules with `git submodule update --init --recursive`.
+ `mkdir build && cd build`.
+ Run cmake with
  `cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=wolfssl -DENABLE_BINARY_BUILD=1 -DCOMPILED_LIBWOLFSSL_PATH=/usr/local/lib/libwolfssl.a -DWOLFSSL_INCDIR=/usr/local/include ..`
  (settings for a Linux x64 GCC build).
+ Compile with `make`.
+ Run the tests from `unit_test/sample_key`:
  `../../build/bin/test_crypt`, `../../build/bin/test_spdm_secured_message`
  and `../../build/bin/test_spdm_crypt`. They should all pass.

The patch also adds the `spdm_unit_test.h` include that upstream's
`unit_test/test_spdm_secured_message/test_spdm_secured_message.c` is missing.
Without it `LIBSPDM_AEAD_AES_256_GCM_SUPPORT` is 0 in `main()` and the binary
runs none of its 12 cmocka cases.

SM2/SM3/SM4 and EdDSA (Ed25519/Ed448) are disabled for the wolfSSL build
(see the patch commit message).
