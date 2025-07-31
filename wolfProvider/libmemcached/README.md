`libmemcached-FIPS-wolfprov.patch` disables 2 test that are only failing in
Jenkins and one test that inconsistenly times out in Jenkins. These tests do
not use libhashkit2 crypto library and are apart of the libmemcached
repository.
