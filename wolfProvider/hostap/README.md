`wolfProvider/hostap/hostap-main-wolfprov.patch` adds support for testing hostap `main`
with wolfProvider. It is needed to test the full testing suite.

The patch makes the following changes:
1. Replaces OpenSSL provider references in `src/crypto/crypto_openssl.c`:
   - Changes "default" provider to "libwolfprov"
   - Changes "legacy" provider to "libwolfprov"
2. Replaces OpenSSL provider reference in `src/crypto/tls_openssl.c`:
   - Changes "pkcs11" provider to "libwolfprov"
3. Fixes crda command failure handling in `tests/hwsim/vm/inside.sh`:
   - Adds `|| true` to handle crda command failure gracefully
