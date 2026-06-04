`wolfProvider/hostap/hostap-hostap_2_11-wolfprov.patch` adds support for
testing hostap `hostap_2_11` with non-FIPS wolfProvider. It points the
legacy provider load in `src/crypto/crypto_openssl.c` at `libwolfprov` and
makes the `crda` call in `tests/hwsim/vm/inside.sh` non-fatal (`|| true`).

`wolfProvider/hostap/hostap-hostap_2_11-wolfprov-fips.patch` is the FIPS
variant. It includes the changes above and additionally removes hwsim tests
that require AES Key Wrap, which wolfProvider FIPS does not expose via the
OpenSSL provider EVP cipher fetch interface. WPA2's 4-way handshake
(message 3/4) encrypts the GTK with AES Key Wrap, so the affected tests
cannot pass under FIPS. Removed:

- `test_ap_wpa2_psk` (`tests/hwsim/test_ap_psk.py`)
- `test_ap_wpa2_eap_tls` (`tests/hwsim/test_ap_eap.py`)
- `test_ap_wpa2_eap_ttls_eap_gtc` (`tests/hwsim/test_ap_eap.py`)
- `test_ap_wpa2_eap_peap_eap_tls` (`tests/hwsim/test_ap_eap.py`)

`wolfProvider/hostap/hostap-main-wolfprov.patch` is the equivalent non-FIPS
patch for hostap `main`. It points the default and legacy provider loads in
`src/crypto/crypto_openssl.c` and the `pkcs11` provider load in
`src/crypto/tls_openssl.c` at `libwolfprov`, and makes the same `crda` call
non-fatal.
