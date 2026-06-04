All patches disable tests that call openssl low level CMAC API that is not
supported with the openssl provider model.
`python3-ntp-NTPsec_1_2_2-wolfprov-fips.patch` also disables a test that uses
non FIPS algorithms. Coincidentally `python3-ntp-master-wolfprov.patch` already
disables this test for FIPS testing on master because it also contains the CMAC
issue in that test.
