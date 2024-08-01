This directory contains to patches that can be applied to wireguard-go to leverage wolfCrypt as a crypto engine.

## Patches
- `Wireguard-Go-wolfCrypt-Port.patch` : This patch simply ports the cryptography to use the go-wolfssl wrapper and wolfSSL. The underlying algorithms used in wireguard are the same.
- `Wireguard-Go-FIPS-wolfCrypt-port.patch` : This patch ports wireguard to use FIPS 140-3 wolfCrypt and FIPS approved algorithms. Blake2s is replaced with SHA-256, Chaha20_Poly1305 with AES-GCM, and X25519 with ECC P-256.

## Building
First, build and install both wolfSSL and go-wolfssl following the instructions here: https://github.com/wolfSSL/go-wolfssl/blob/master/README.md. Make sure that wolfSSL is configured as shown below.
```
./configure --enable-sp="yes, 256"
```

If you're interested in the FIPS build, configure as shown below. Make sure that wolfCrypt tests pass, the normal flow for doing this can be seen below.
```
./configure --enable-fips=v5 --enable-sp="yes, 256"
make
./wolfcrypt/test/testwolfcrypt
./fips-hash.sh
make
./wolfcrypt/test/testwolfcrypt
sudo make install
```

Then clone wireguard-go and apply whichever patch you're intersted in. Note that these patches were developed and tested on top of the following wireguard-go commit https://github.com/WireGuard/wireguard-go/commit/12269c2761734b1.
```
git clone https://github.com/WireGuard/wireguard-go.git
cd wireguard-go
patch -p1 < ../Wireguard-Go-wolfCrypt-Port.patch
```

Finally, install go-wolfssl into the project and run the unit tests.
```
cd wireguard-go
go get -u github.com/wolfssl/go-wolfssl 
go mod edit -replace github.com/wolfssl/go-wolfssl=<path to your go-wolfssl directory>
cd device
go test
```

