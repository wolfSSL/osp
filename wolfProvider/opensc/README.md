`wolfProvider/opensc/opensc-0.25.1-wolfprovider.patch` adds wolfProvider support 
for opensc version `0.25.1`. To enable provider, use `--enable-wolfprov`
when configuring opensc and also set env varaible `ENABLE_WOLFPROV=1` when
running tests. To enable FIPS mode jsut set `WOLFSSL_ISFIPS=1` when running
tests.
