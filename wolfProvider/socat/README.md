`socat-1.8.0.0-wolfprov.patch` adds testing support for FIPS and non-FIPS 
socat `v1.8.0.0`. This patch disables problematic test with ecdhe which is
causing unrelating hanging as comments suggest.
