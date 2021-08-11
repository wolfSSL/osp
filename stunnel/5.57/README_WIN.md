# Windows Build Instructions
These instructions assume that you have already built wolfssl.dll. For instructions on how to do this using Visual Studio, see https://www.wolfssl.com/docs/visual-studio/. You will need to set the appropriate settings for stunnel compatibility in user_settings.h. You can determine what these settings are by configuring on Linux using `./configure --enable-stunnel` and checking out the generated options.h file.

## Build stunnel
We'll be cross-compiling on Linux for 32-bit Windows, using the MinGW compiler.

+ Download stunnel 5.57 with `curl -O https://www.usenix.org.uk/mirrors/stunnel/archive/5.x/stunnel-5.57.tar.gz`.
+ Unarchive stunnel-5.57.tar.gz with `tar xvf stunnel-5.57.tar.gz`. cd into stunnel-5.57.
+ Patch the source code with `patch -p1 < stunnel-5.57.patch`, adjusting the path to the patch file accordingly.
+ Regenerate the configure script with `autoreconf`.
+ Configure stunnel with `./configure`. It's not important that we specify `--enable-wolfssl` here. We're simply using the configure script here to generate the file src/Makefile. src/mingw_wolfssl.mk will handle the rest.
+ cd into the src directory and compile for 32-bit Windows using `make mingw`. By default, the build assumes the wolfSSL headers and DLL are in /opt/wolfssl_windows under the include and lib subdirectories, respectively. Adjust the `win32_ssl_dir = ` line in mingw_wolfssl.mk if these files are located elsewhere. If you want to enable wolfSSL debug logging in stunnel, edit mingw_wolfssl.mk and add `-DWOLFSSL_DEBUG_ON` to the `win32_cflags +=` line after `-DWITH_WOLFSSL`. This assumes you've built wolfssl.dll with debugging enabled, too.
+ `cd ../bin/win32/`. This directory should contain tstunnel.exe and stunnel.exe, which are the CLI and GUI versions of stunnel, respectively. Copy these over to your Windows machine/VM.

## Try It Out (tstunnel.exe)
To verify that stunnel built with wolfSSL is working, we'll use an example TCP server and client from the wolfSSL examples repository. This example assumes you have Cygwin or some other toolchain available that allows you to compile programs on Windows in a Unix-like fashion.

+ Clone the wolfSSL examples repository with `git clone git@github.com:wolfSSL/wolfssl-examples.git`.
+ cd into wolfssl-examples/tls. Edit server-tcp.c to change the line `#define DEFAULT_PORT 11111` to `#define DEFAULT_PORT 11112`.
+ Compile the TCP client and server with `make`. The server executable is server-tcp and the client is client-tcp.
+ Edit stunnel-server.conf. Note that the port on the "connect" line matches the one we put in server-tcp.c. Replace <path to server certificate, in PEM format> with the path to wolfssl/certs/server-cert.pem. Replace <path to server private key, in PEM format> with the path to wolfssl/certs/server-key.pem.
+ Edit stunnel-client.conf. Note that the port on the "connect" line matches the "accept" port from stunnel-server.conf. Replace <path to CA certificate, in PEM format> with the path to wolfssl/certs/ca-cert.pem.
+ All of the following terminal/cmd windows assume the working directory contains the wolfssl-examples repository, wolfssl.dll, and the .conf files.
+ In one terminal window, fire up the stunnel server with `.\tstunnel.exe stunnel-server.conf`.
+ In another window, launch the stunnel client with `.\tstunnel.exe stunnel-client.conf`. We now have a secure tunnel provided by stunnel and backed by wolfSSL.
+ Now, in yet another terminal window, launch the TCP server, which will communicate with the TCP client via the tunnel, with `.\wolfssl-examples\tls\server-tcp`.
+ In a final terminal window, launch the TCP client with `.\wolfssl-examples\tls\client-tcp 127.0.0.1`. Enter a message to send to the server. You should see the server respond with "I hear ya fa shizzle!", and you should see the message you sent appear in the server window. Additionally, you should see a flurry of activity in the stunnel server and client windows when the message is sent. If you were to observe this traffic in Wireshark, you would see that the message is encrypted using TLS, indicating that the tunnel is working as intended.

### Installing and running stunnel.exe as a Windows service
To install stunnel as a Windows service, open a command prompt and run `.\stunnel.exe -install <path to stunnel.conf>`. Then, to start the service, run `.\stunnel.exe -start <path to stunnel.conf>`.  Replace "-start" with "-stop" to stop the service
