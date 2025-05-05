This patch adds support for testing stunnel with `WOLFPROV_FORCE_FAIL=1`
environment variable, which is used to simulate provider failures during
testing. It is only needed if you are testing wolfProvider with
`WOLFPROV_FORCE_FAIL=1`.
The patch includes modifications to certificate generation and session
resumption tests to properly handle this test mode.