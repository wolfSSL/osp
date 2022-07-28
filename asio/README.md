# ASIO with wolfSSL


## Build & install wolfSSL

```
wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.4.0-stable.tar.gz
tar xvf v5.4.0-stable.tar.gz 
./autogen.sh
./configure --enable-asio --enable-enckeys --enable-des3
make -j nproc 
sudo make install
```

Note: The encrypted key and des3 support is used by the `./src/examples/cpp11/ssl/` examples, but not required for ASIO.

## Build upstream ASIO with wolfssl autoconf patch cherry-picked

```sh
git clone https://github.com/chriskohlhoff/asio.git
cd asio
```

Patch configure.ac to support `--with-wolfssl=`:
```sh
patch -p1 < asio_wolfssl_autoconf.diff
# OR
git remote add wolfssl https://github.com/dgarske/asio.git
git fetch --all
git cherry-pick remotes/wolfssl/wolfssl_autoconf
```

```sh
cd asio
./autogen.sh
./configure --with-wolfssl=/usr/local 
make -j nproc 
make -j nproc check 
```

## Example Server and Client Test

```
cd ./src/examples/cpp11/ssl/
./server 9100
./client localhost 9100
```
