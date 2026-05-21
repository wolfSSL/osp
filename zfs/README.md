## Description

This contains a patch to OpenZFS that replaces its native crypto implementation
with calls to wolfCrypt API.

1. Clone wolfSSL:
```
git clone https://github.com/wolfSSL/wolfssl.git
```

Build `libwolfssl.so` userspace lib first:
```
./scripts/wolfssl/build_wolfssl_so
```

Next build `libwolfssl.ko` kernel module:
```
./scripts/wolfssl/build_wolfssl_ko
```


2. Clone OpenZFS:

```
git clone https://github.com/openzfs/zfs.git
```

3. Patch OpenZFS:

```
cd zfs
git checkout cd06f79e2949b6255f5e8bf621c1b9497ad97b02
git apply ../patches/cd06f79e2_wolfzfs.patch
cd ../
```

Build patched ZFS:

```
./scripts/zfs/build_wolfzfs
```
