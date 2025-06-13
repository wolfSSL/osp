For version 5.67 testing with WPFF support, use the patch `stunnel-WPFF-5.67-wolfprov.patch`
This patch adds support for testing stunnel with `WOLFPROV_FORCE_FAIL=1`
environment variable, which is used to simulate provider failures during
testing. It is only needed if you are testing wolfProvider with
`WOLFPROV_FORCE_FAIL=1`.
The patch includes modifications to certificate generation and session
resumption tests to properly handle this test mode.

For version 5.67 testing with FIPS support, use the patch `stunnel-FIPS-5.67-wolfprov.patch`
Note: use either the WPFF or FIPS patch not both.
