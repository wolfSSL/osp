`wolfProvider/libtss2/libtss2-FIPS-4.1.3-wolfprov.patch` adds testing support 
for libtss2 with FIPS wolfprovider. To use this patch make sure to configure 
libtss2 with `--enable-wolfprov-fips`. This will disable SM4 and AES-CFB tests.
