# Patch for Qt 5.15.9

## Apply Qt 5.15.2 and 5.15.8 patchs
Please see [README](https://github.com/wolfSSL/osp/blob/master/qt/5.15.8/README_v5158.md)

## Apply Qt 5.15.9 patch and Build

### Building wolfSSL
Please follow [README](https://github.com/wolfSSL/osp/blob/master/qt/README_v515.md).

### Building Qt 5.15.9 with wolfSSL
1. Prepare Qt 5.15.9

2. Apply 5.15.9 patch

Get patch folder from [osp/qt/5.15.9](https::/github.com/wolfSSL/osp/qt/5.15.9/)

cp all contents in the folder to /path/to/qt5159/

Run shell command

```
$cd /path/to/qt5159
$v5159_path.sh
```

4. Add unit test program(Optional)


Please see [README](https://github.com/wolfSSL/osp/blob/master/qt/5.15.8/README_v5158.md) for unit test patch.

5. Configure build and install


Please follow [README](https://github.com/wolfSSL/osp/blob/master/qt/README_v515.md)


Note1: <strong>For wolfSSL configuration, you need to add `-DALLOW_INVALID_CERTSIGN` for CFLAG Option to make `qsslcertificate` tests passed. </strong>
This needs becaue higher versions than wolfSSL v5.6.4 doesn't allow a certificate which has `CA:FALSE` and `Certificate Sign` set. The certificate is qtbase/tests/auto/network/ssl/qsslcertificate/verify-certs/test-ocsp-good-cert.pem which is used for `qsslcertificate` tests.

```
comments from asn.c
/*
 *   https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
 *   If the cA boolean is not asserted, then the keyCertSign bit in the
 *   key usage extension MUST NOT be asserted.
 */
```

## Running tests
Please see [README](https://github.com/wolfSSL/osp/blob/master/qt/README_v515.md)
