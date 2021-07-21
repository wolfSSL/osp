# Building socat with wolfSSL
+ Configure wolfSSL with `./configure --enable-opensslextra --enable-opensslall`. Add `--enable-debug` if you're going to be debugging.
+ `make` and `sudo make install` wolfSSL into /usr/local.
+ Download socat-1.7.3.4 with `curl -O http://www.dest-unreach.org/socat/download/socat-1.7.3.4.tar.gz`.
+ Unarchive this tar ball with `tar xvf socat-1.7.3.4.tar.gz`.
+ Apply the socat-1.7.3.4.patch file with `patch -p1 < socat-1.7.3.4.patch` (assuming the patch file is in the socat-1.7.3.4 directory; adjust the path according to your situation).
+ Regenerate the configure script with `autoconf`.
+ Configure socat with `./configure --with-wolfssl=/usr/local`. Update the path if you've installed wolfSSL using a different prefix than /usr/local.
+ Run `make clean` and `make` to compile. I'm not sure exactly how socat has set up its Makefile stuff, but I've found you typically have to run `make clean` before re-compiling. Otherwise, any changes you make won't be picked up, and make will think it has nothing to do.
+ At this point, you can optionally install into /usr/local with `make install`. The example below assumes you're running socat from the socat-1.7.3.4 directory, though.

## Example
+ Open one terminal window where you'll run the server. Start the server with `./socat openssl-listen:9999,reuseaddr,cert=/path/to/server-cert.pem,key=/path/to/server-key.pem,cafile=/path/to/client-cert.pem echo`, replacing the /path/to/ in each path with the path to wolfssl/certs/.
+ Open another terminal window for the client. Start it with `./socat stdio openssl-connect:127.0.0.1:9999,cert=/path/to/client-cert.pem,key=/path/to/client-key.pem,cafile=/path/to/server-cert.pem,commonname=www.wolfssl.com`, once again replacing the /path/to/ accordingly. The `commonname` option is important. If you don't include this, the client will error out, saying that the hostname (127.0.0.1 AKA localhost) doesn't match the common name in the server's cert (www.wolfssl.com).
+ Type a message and hit enter in the client window. You should see it echoed back from the server.
+ If you observe this traffic on the loopback interface (lo) in Wireshark, you should see that it's encrypted using TLS.
