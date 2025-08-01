`libcryptsetup-v2.6.1-wolfprov.patch` adds FIPS and non FIPS wolfProvider 
support for libcryptsetup `v2.6.1`. It disables various tests that use out 
of bounds or not supported crypto. examples include: `ripemd160`, `whirlpool`, 
`blake2b-512`, `blake2s-256`, `stribog512`, `kuznyechik`, `argon2i`, `argon2id`, 
and `pbkdf2`.
