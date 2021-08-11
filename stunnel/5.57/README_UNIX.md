# Unix Build Instructions

## Build wolfSSL
+ Configure wolfSSL with `./configure --enable-stunnel`. Add `--enable-debug` if you want to enable the debug version of wolfSSL.
+ Compile with `make`.
+ Install wolfSSL into /usr/local with `sudo make install`.

## Build stunnel
+ Download stunnel 5.57 with `curl -O https://www.usenix.org.uk/mirrors/stunnel/archive/5.x/stunnel-5.57.tar.gz`.
+ Unarchive stunnel-5.57.tar.gz with `tar xvf stunnel-5.57.tar.gz`. cd into stunnel-5.57.
+ Patch the source code with `patch -p1 < stunnel-5.57.patch`, adjusting the path to the patch file accordingly. 
+ Regenerate the configure script with `autoreconf`.
+ Configure stunnel with `./configure --enable-wolfssl`. Add `--enable-wolfssldebug` if you want to enable wolfSSL debug logging during stunnel operation. This requires that you configured wolfSSL with `--enable-debug`.
+ Compile with `make`.
+ Install stunnel into /usr/local with `sudo make install`.

## Try It Out
To verify that stunnel built with wolfSSL is working, we'll use an example TCP server and client from the wolfSSL examples repository.

+ In a directory containing the stunnel-client.conf and stunnel-server.conf files, clone the wolfSSL examples repository with `git clone git@github.com:wolfSSL/wolfssl-examples.git`.
+ cd into wolfssl-examples/tls/. Edit server-tcp.c to change the line `#define DEFAULT_PORT 11111` to `#define DEFAULT_PORT 11112`.
+ Compile the TCP client and server with `make`. The server executable is server-tcp and the client is client-tcp.
+ cd back into the main directory containing the .conf files. Edit stunnel-server.conf. Note that the port on the "connect" line matches the one we put in server-tcp.c. Replace <path to server certificate, in PEM format> with the path to wolfssl/certs/server-cert.pem. Replace <path to server private key, in PEM format> with the path to wolfssl/certs/server-key.pem.
+ Edit stunnel-client.conf. Note that the port on the "connect" line matches the "accept" port from stunnel-server.conf. Replace <path to CA certificate, in PEM format> with the path to wolfssl/certs/ca-cert.pem.
+ In one terminal window, fire up the stunnel server with `stunnel stunnel-server.conf`.
+ In another window, launch the stunnel client with `stunnel stunnel-client.conf`. We now have a secure tunnel provided by stunnel and backed by wolfSSL.
+ Now, in yet another terminal window, launch the TCP server, which will communicate with the TCP client via the tunnel, with `./wolfssl-examples/tls/server-tcp`.
+ In a final terminal window, launch the TCP client with `./wolfssl-examples/tls/client-tcp 127.0.0.1`. Enter a message to send to the server. You should see the server respond with "I hear ya fa shizzle!", and you should see the message you sent appear in the server window. Additionally, you should see a flurry of activity in the stunnel server and client windows when the message is sent. If you were to observe this traffic in Wireshark, you would see that the message is encrypted using TLS, indicating that the tunnel is working as intended.
