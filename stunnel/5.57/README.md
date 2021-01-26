## Overview
stunnel.exe is a GUI version of stunnel 5.57 built to use a wolfSSL FIPS Ready DLL (wolfssl-fips.dll). It should work seamlessly on the client or server side and with clients/servers using either OpenSSL or wolfSSL on their end of the tunnel.

tstunnel.exe is essentially the CLI version of stunnel.exe.

## Installing and running stunnel.exe as a Windows service
To install stunnel as a Windows service, open a command prompt and run `.\stunnel.exe -install <path to stunnel.conf>`. Then, to start the service, run `.\stunnel.exe -start <path to stunnel.conf>`.  Replace "-start" with "-stop" to stop the service.

### Example (tstunnel.exe)
You'll need two machines (they can be VMs, so long as they have a unique IP on their LAN) to carry out this example. Pick one machine as the server. Create a file stunnel-server.conf on that machine, with the following contents:
```
debug = info
output = <path to log file>

[stunnel-server]
cert = <path to server certificate, in PEM format>
key = <path to server private key, in PEM format>
accept = <server's IP address>:<stunnel port of your choosing>
connect = 127.0.0.1:<application port of your choosing>
```

You can use the example server certificate and private key distributed with the wolfSSL library, if you don't have a certificate/private key pair handy (certs/server-cert.pem, certs/server-key.pem). Then, make sure wolfssl-fips.dll is in the same directory as tstunnel.exe. Launch tstunnel.exe from a command prompt: `.\tstunnel.exe stunnel-server.conf`. Note: You may need to run the server side application and stunnel as administrator. Do this by opening the command prompt window as administrator.

The server application code is in server-tcp.c, and the corresponding executable is server-tcp.exe. Launch the program from a command prompt window with `.\server-tcp.exe <application port>`, where application port is the port specified on the `connect` line from stunnel-server.conf.

On the client machine, create a file stunnel-client.conf, with the following contents:
```
debug = info
output = <path to log file>

[stunnel-client]
client = yes
accept = 127.0.0.1:<application port of your choosing>
connect = <server's IP address>:<server's stunnel port>
CAfile = <path to CA certificate, in PEM format>
verifyChain = yes
```

You'll need a CA certificate to verify the server with. If you're using the example wolfSSL certs mentioned earlier, you can use wolfSSL's example CA cert, too (certs/ca-cert.pem). Note that the port on the `connect` line here should match the `accept` port in stunnel-server.conf. Again, make sure wolfssl-fips.dll is in the same directory as tstunnel.exe. Launch tstunnel.exe from a command prompt: `.\tstunnel.exe stunnel-client.conf`.

Launch the client program, client-tcp.exe, with `.\client-tcp.exe <application port>`, where application port is the port specified on the `accept` line from stunnel-client.conf.

Now, type in a message to send to the server, and hit enter. You should see "I hear ya fa shizzle!" returned from the server, and, if you look at the server's window, you should see the message sent by the client.

### Compiling Example Programs
Open Developer Command Prompt for VS 2019 (or whatever version of Visual Studio you have). Navigate to the directory containing server-tcp.c/client-tcp.c and run `cl server-tcp.c`/`cl client-tcp.c` to build an executable.
