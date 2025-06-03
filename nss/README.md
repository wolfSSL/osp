# NSS (Network Security Services)

This folder contains patches to allow NSS to work with wolfPKCS11.

**Note:** wolfPKCS11 does not support the NSS `cert9.db` and `key4.db`. It will
use its own files or a TPM.

## Patches

The support comes in the form of two patches, both of which need to be applied.

### nss-ecc-curves.patch

NSS uses a fixed list of ECC curves and tries to use this list regardless of
whether or not the underlying PKCS11 backend supports it. This patch makes NSS
test the PKCS11 layer to see which curves are supported.

### nss-slot.patch

NSS assumes that it is using a two-slot PKCS11 backend for non-FIPS by default.
This patch falls back to one slot if a second slot is not found.

## Compiling

### NSS

First of all, there are some dependencies you need. In Ubuntu these are
installed using:

```
sudo apt-get install \
mercurial \
gyp \
ninja-build \
python3 \
python-is-python3
```

The following instructions can be used to get the sources and compile.

Note: if you want a debug build for the “Debug Tracing” section later in this
document, set `BUILD_OPT=0` instead.

```
export BUILD_OPT=1
export USE_64=1
hg clone https://hg.mozilla.org/projects/nspr
hg clone https://hg.mozilla.org/projects/nss
git clone https://github.com/wolfssl/osp
cd nss
patch -p1 < ../osp/nss/nss-ecc-curves.patch
patch -p1 < ../osp/nss/nss-slot.patch
export USE_64=0
./build.sh -v
```

Once compiled the sources need to be installed. We have not found a better way
of doing this at the moment than as follows. It is expected that integrating
this into a Debian package build will make things a lot smoother:

```
cp -r dist/public/nss/* /usr/local/include/nss/
cp -r ../nspr/dist/Debug/include/nspr/* /usr/local/include/nspr/
find /src/dist/Debug -name "*.so" -exec cp {} /usr/local/lib/ \;
find /src/nspr/Debug -name "*.so" -exec cp {} /usr/local/lib/ \;
```

### wolfSSL

Next, wolfSSL should be compiled. These instructions assume that you are using a
wolfSSL FIPSv5 source package in the directory `wolfssl-with-v5.2.1`:

```
cd wolfssl-with-v5.2.1
./configure \
--enable-aescfb \
--enable-cryptocb \
--enable-rsapss \
--enable-keygen \
--enable-pwdbased \
--enable-scrypt \
--enable-fips=v5  \
CFLAGS="-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT"
make
./fips-hash.sh
make install
```

If you are not using a FIPS package, remove the `--enable-fips=v5` option and
do not do the `./fips-hash.sh` command.

### wolfPKCS11

Finally, wolfPKCS11 needs to be compiled. For now, this needs to be done using
the nss branch in wolfPKCS11, which contains NSS compatibility features:

```
./autogen.sh
./configure \
--enable-nss \
--enable-aesecb \
--enable-aesctr \
--enable-aesccm \
--enable-aescmac
make
make install
```

## Setup

Now that everything is installed, NSS needs to be configured to use wolfPKCS11.
To do this, either edit or create `/etc/pki/nssdb/pkcs11.txt` with the following
contents:

```
library=/usr/local/lib/libwolfpkcs11.so
name=wolfPKCS11
NSS=Flags=internal,critical cipherOrder=100 slotParams={0x00000001=[slotFlags=ECC,RSA,DSA,DH,RC2,RC4,DES,RANDOM,SHA1,MD5,MD2,SSL,TLS,AES,Camellia,SEED,SHA256,SHA512] }
```

**Notes:**

* If you are using Firefox or Thunderbird, `pkcs11.txt` is found in the user’s
profile directory instead (also, Firefox is likely statically compiled with a
built-in NSS).
* The `slotFlags` do not really determine the algorithms, this is probed for
later.
* If there are other entries in this file, they should be removed.

From this point forward, anything using NSS will now use wolfPKCS11 for the
crypto backend.

## Debug Tracing

To trace what calls are going into wolfPKCS11 within NSS, a recompile of NSS is needed with some additional flags. As mentioned in the NSS section, you will need to compile with `BUILD_OPT=0`. There are then various options you can set using environment variables.


| Variable | Description |
| -------- | ----------- |
| `NSS_DEBUG_PKCS11_MODULE` | The name of the PKCS11 module you wish to get debugging output for. Set to wolfPKCS11 for wolfPKCS11 or "NSS Internal PKCS #11 Module" for NSS’s internal one. |
| `NSPR_LOG_MODULES` | The NSS modules and log level for them. It is recommended that you use "all:5", but a full description of the options can be found here. |
| `NSPR_LOG_FILE` | The path and file name you wish the logging information to go to. Such as `/tmp/nss.log`. |
| `NSS_OUTPUT_FILE` | The output file for NSS’s performance log, which contains statistics of the PKCS11 calls made. Such as `/tmp/stats.log`. If this is not set, but `NSS_DEBUG_PKCS11_MODULE` is, this will go to stdout. |


