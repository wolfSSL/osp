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

`wolfProvider/hostap/hostap-main-wolfprov-fips.patch` is the FIPS variant. It
includes the changes above and additionally removes hwsim tests that require
AES Key Wrap, which wolfProvider FIPS does not expose via the OpenSSL provider
EVP cipher fetch interface. WPA2's 4-way handshake (message 3/4) encrypts the
GTK with AES Key Wrap, so the affected tests cannot pass under FIPS. Removed:

- `test_ap_wpa2_psk` (`tests/hwsim/test_ap_psk.py`)
- `test_ap_wpa2_eap_tls` (`tests/hwsim/test_ap_eap.py`)
- `test_ap_wpa2_eap_ttls_eap_gtc` (`tests/hwsim/test_ap_eap.py`)
- `test_ap_wpa2_eap_peap_eap_tls` (`tests/hwsim/test_ap_eap.py`)
