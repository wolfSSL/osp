These patches are needed to run the full openpace test suite with wolfProvider.
It is not needed to facilitate core functionality, only modify the test suite
to remove testing for features not supported by wolfProvider. Also adds support
in non-FIPS patch so test suite doesn't exit on failure from segmentation fault
with WPFF and all preceding tests still run.
The FIPS patch disables all non-FIPS approved algorithms to pass the full test
suite with wolfProvider FIPS.
