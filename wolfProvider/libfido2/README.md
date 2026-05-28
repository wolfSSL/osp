`wolfProvider/libfido2/libfido2-1.15.0-wolfprov-fips.patch` adds testing support 
for libfido2 with FIPS wolfprovider. To use this patch make sure to set the flag
`HAVE_FIPS` to `ON` when configuring libfido2. This will disable EdDSA tests.
