# FIDO Device Onboard (FDO) Client SDK with wolfSSL

This patch adds a wolfSSL crypto/TLS backend (`TLS=wolfssl`) and an optional wolfTPM
device-attestation stack (`TPM_STACK=wolftpm`) to the
[FDO Client SDK](https://github.com/fido-device-onboard/client-sdk-fidoiot). Upstream is
archived, so the patch applies to its final code commit, `40e5024` (2025-08-06).

Tested with wolfSSL `v5.9.4-stable` and wolfTPM `v4.2.0`.

## Building wolfSSL
+ Download and unpack wolfSSL `v5.9.4-stable`, then `cd` into it.
+ Configure wolfSSL with:
  ```
  ./autogen.sh
  ./configure --prefix=/opt/wolfssl \
      --enable-ecc --enable-keygen --enable-certgen --enable-certreq \
      --enable-certext --enable-aesgcm --enable-aesccm --enable-aescfb \
      --enable-sha --enable-sha256 --enable-sha384 --enable-tls13 \
      --enable-harden --enable-wolftpm --enable-pkcallbacks --enable-curl \
      C_EXTRA_FLAGS="-DWOLFSSL_PUBLIC_MP -DWC_RNG_SEED_CB -DWOLFSSL_CUSTOM_OID -DHAVE_OID_ENCODING"
  ```
  Add `--enable-debug` if debugging.
+ `make` and `sudo make install`.
+ Build curl against this wolfSSL with `--with-wolfssl=/opt/wolfssl` and install it to
  `/opt/curl`.

After the patch is applied, `utils/install_wolfssl_curl.sh -i` does all of the above,
including GPG verification of the wolfSSL and curl tarballs.

## Building the FDO Client SDK
+ Clone the SDK and check out the base commit:
  ```
  git clone https://github.com/fido-device-onboard/client-sdk-fidoiot.git
  cd client-sdk-fidoiot
  git checkout 40e5024d46472020f3e7811dae9f40b0644c17f4
  ```
+ Apply the patch, adjusting the path to the patch file:
  ```
  git apply 2025-08-06-40e5024d46472020f3e7811dae9f40b0644c17f4.patch
  ```
  or `patch -p1 < 2025-08-06-40e5024d46472020f3e7811dae9f40b0644c17f4.patch`.
+ Build safestringlib and tinycbor with `./utils/setup_local_dependencies.sh`, then export
  the `SAFESTRING_ROOT` and `TINYCBOR_ROOT` paths it prints.
+ `export WOLFSSL_ROOT=/opt/wolfssl CURL_ROOT=/opt/curl`
+ Configure and build:
  ```
  cmake -B build -DTLS=wolfssl -DDA=ecdsa384 -DAES_MODE=gcm
  cmake --build build -j$(nproc)
  ```

## Testing
+ Install wolfTPM first with `./utils/install_wolfssl_curl.sh -t` (see wolfTPM below). The
  test script also builds the `tpm20_ecdsa256` and `tpm20_ecdsa384` configurations, which
  include wolfTPM headers and link with `-lwolftpm`, so it fails if only wolfSSL and curl
  (`-i`) are installed. The TPM is mocked, so no TPM hardware is needed.
+ `bash .github/build_wolfssl_ci.sh` builds and runs the unit tests for the ECDSA P-256 and
  P-384, AES-GCM and AES-CCM, and mocked wolfTPM configurations. It exits non-zero if any
  test fails.

## wolfTPM (optional)
+ Build wolfTPM `v4.2.0` against the same wolfSSL with `./utils/install_wolfssl_curl.sh -t`,
  or manually with:
  ```
  ./autogen.sh
  ./configure --prefix=/opt/wolftpm --with-wolfcrypt=/opt/wolfssl --enable-devtpm
  make
  sudo make install
  ```
+ Export the wolfTPM prefix so CMake finds its headers and library, since `/opt/wolftpm` is
  not a standard search path: `export WOLFTPM_ROOT=/opt/wolftpm`
+ Configure the SDK with `-DTPM_STACK=wolftpm -DDA=tpm20_ecdsa384`.

## Yocto
`utils/meta-intel-sdo` provides a `clientsdk-wolfssl` recipe that fetches upstream at
`40e5024` and applies this patch. Copy this patch file into
`utils/meta-intel-sdo/dynamic-layers/wolfssl/recipes-connectivity/clientsdk-wolfssl/files/`
and use meta-wolfssl at `e029e80`. `utils/setup_yocto_wolfssl.sh` checks out `e029e80` only
when it clones meta-wolfssl. If the directory already exists it is left at its current
revision, so check it out yourself:
```
git -C /path/to/yocto/meta-wolfssl fetch
git -C /path/to/yocto/meta-wolfssl checkout e029e80b743fb3096ccb494161144ae3888e1a48
```

See `docs/wolfssl.md` in the patched tree for full details.
