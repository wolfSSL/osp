# WolfGuard-go

This directory contains to patches that can be applied to WireGuard-go to form WolfGuard-go, a VPN that leverages the FIPS 140-3 certified wolfCrypt as a crypto engine. This can run on a Linux, macOS or Windows machine and requires a Go version > 1.20. See https://github.com/wolfssl/wolfguard for the linux kernel WolfGuard.

## Patches
- `Wireguard-Go-wolfCrypt-Port.patch` : This patch simply ports the cryptography to use the go-wolfssl wrapper and wolfSSL. The underlying algorithms used in wireguard are the same.
- `Wireguard-Go-FIPS-wolfCrypt-port.patch` : This patch ports wireguard to use FIPS 140-3 wolfCrypt and FIPS approved algorithms. Blake2s is replaced with SHA-256, Chaha20_Poly1305 with AES-GCM 256, and X25519 with ECC P-256.

## Building FIPS WolfGuard
Ensure that you're working with the wolfSSL FIPS bundle and run configure as shown below. Make sure that wolfCrypt tests pass, the normal flow for doing this can be seen below.
```
./configure --enable-fips=v5 --enable-sp="yes, 256"
make
./wolfcrypt/test/testwolfcrypt
./fips-hash.sh
make
./wolfcrypt/test/testwolfcrypt
sudo make install
```

Then clone wireguard-go and apply the `Wireguard-Go-FIPS-wolfCrypt-port.patch` patch. This patch was developed and tested on top of the following wireguard-go commit https://github.com/WireGuard/wireguard-go/commit/12269c2761734b1.
```
git clone https://github.com/WireGuard/wireguard-go.git
cd wireguard-go
patch -p1 < ../Wireguard-Go-FIPS-wolfCrypt-port.patch
```

Finally, install go-wolfssl into the project and run the unit tests.
```
cd wireguard-go
go get -u github.com/wolfssl/go-wolfssl 
go mod edit -replace github.com/wolfssl/go-wolfssl=<path to your go-wolfssl directory>
cd device
go test
```

If go can't find the wolfSSL .so file, you may have to manually specify the lib install location.
```
LD_LIBRARY_PATH=/usr/local/lib/ go test
```

After running `make` in the wireguard-go directory, you'll have the `wolfguard-go` executable available to run. Reference the `main_configuration.patch` file as an example for how to configure the wireguard executable. You can also apply the `gen_key_on_test.patch` to your wireguard-go src so that every run of `go test` generates and prints an ECC 256 Public/Private key pair that you can use for your configuration. 
