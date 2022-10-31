# Overview

This is a patch for [nginx-upload-module](https://github.com/fdintino/nginx-upload-module)
version 2.3.0. It's intended to be used with nginx/OpenResty built with wolfSSL
FIPS. The patch removes support for MD5 from the module, since MD5 isn't
FIPS-compliant.

# Building

- `git clone https://github.com/fdintino/nginx-upload-module.git`.
- `cd nginx-upload-module` and `git checkout 2.3.0`.
- `patch -p1 < <path to wolfssl-nginx-upload-module-2.3.0.patch>`.

Then, build nginx/OpenResty as normal.
