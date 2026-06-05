`wolfProvider/curl/curl-8_4_0-wolfprov.patch` and
`wolfProvider/curl/curl-7_88_1-wolfprov.patch` add support for testing the
respective curl versions with wolfProvider. Both patches disable test 1560
(`[URL API]` libtest) — a non-crypto IDN-related test that fails under the
wolfProvider test-deps container regardless of IDN dependencies installed.

These patches must be applied to the curl source tree (e.g. `patch -p1`)
before running `make test-ci`. If they are not applied, test 1560 will
appear as an unexpected failure in normal-mode runs.
