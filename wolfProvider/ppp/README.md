`wolfProvider/ppp/ppp-v2.5.2-wolfprov-fips.patch` adds testing support for ppp 
with FIPS wolfprovider. To use this patch make sure to configure ppp with 
`--enable-wolfprov-fips` flag. This will disable MD5 tests.
