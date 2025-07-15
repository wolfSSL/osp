`wolfProvider/tcpdump/tcpdump-FIPS-tcpdump-4.99.3-wolfprov.patch` adds support
for testing tcpdump `v4.99.3` with FIPS wolfprovider. To use this patch make
sure to configure tcpdump with `--enable-wolfprov-fips`. This will disable
problematic tests using DES3-CBC.
