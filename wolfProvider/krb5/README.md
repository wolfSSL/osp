krb5-1.20.1-final-wolfprov.patch is needed for core functionality in KRB5 with wolfProvider (specifically for SSKDF usage).
It also modifies the test scripts to not use unsupported algorithms in testing.

krb5-1.20.1-final-wolfprov-fips.patch provides the same core functionality, additionally removes all non-FIPS testing and
changes all passwords used in testing to be >= 14 bytes as required.
