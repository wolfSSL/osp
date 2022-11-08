# Overview

This is a patch for [encrypted-session-nginx-module](https://github.com/openresty/encrypted-session-nginx-module)
version 0.08. It's intended to be used with nginx/OpenResty built with wolfSSL
FIPS. The patch makes it so that SHA-256 will be used for digests instead of
MD5, which isn't a FIPS-compliant algorithm.

# Building

- `git clone https://github.com/openresty/encrypted-session-nginx-module.git`.
- `cd encrypted-session-nginx-module` and `git checkout v0.08`.
- `patch -p1 < <path to wolfssl-encrypted-session-nginx-module-0.08.patch>`.

Then, build OpenResty/nginx as normal.
