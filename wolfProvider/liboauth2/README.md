`liboauth2-FIPS-v1.4.5.4-wolfprov.patch` adds testing support for liboauth2 
`v1.4.5.4` with FIPS wolfprovider. To use this patch make sure to configure liboauth2 
with `--enable-wolfprov-fips`. This will disable problematic tests in Docker/valgrind.

`liboauth2-v1.4.5.4-wolfprov.patch` adds support for testing liboauth2 `v1.4.5.4`.
It is only needed if you are testing liboauth2 with full testing suite.

Note: Both of these patches work with master branch of liboauth2. Use either the
FIPS patch or the normal ones not both.
