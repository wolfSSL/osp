This folder contains patches for mosquitto to work with wolfSSL. Patches make it easier to add support for newer versions of a target library. The format of the patch names is: `<mosquitto version>.patch` Instructions for applying each patch are included in the patch commit message.

wolfSSL

```
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-mosquitto
make
make install
```

Eclipse Mosquitto
If wolfSSL is installed to a custom directory, specify that dir with `WOLFSSLDIR`

```
git clone https://github.com/eclipse/mosquitto.git
cd mosquitto
git checkout v2.0.18
patch -p1 < <path/to/patch/file>
make WITH_TLS=wolfssl
make WITH_TLS=wolfssl ptest
```
