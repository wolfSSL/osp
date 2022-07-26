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

## Build upstream ASIO with wolfssl autoconf patch cherry-picked


```
git clone https://github.com/chriskohlhoff/asio.git
cd asio
git remote add wolfssl https://github.com/dgarske/asio.git
git fetch --all
git cherry-pick remotes/wolfssl/wolfssl_autoconf
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
