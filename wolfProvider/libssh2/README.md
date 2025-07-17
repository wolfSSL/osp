The patch for `wolfProvider/libssh2/libssh2-1.10.0-wolfprov.patch` adds support
for testing libssh2 `libssh2-1.10.0` with FIPS and non-FIPS wolfProvider. This patch
configures the ssh2 test to limit the algorithms used and makes minor
doc changes to make the mansyntax.sh test pass.
