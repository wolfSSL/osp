This is a list of steps to follow to generate an OpenResty bundle that can be compiled with wolfSSL.

# Get the version you need
- Download the appropriate release from https://openresty.org/en/download.html
- Extract (tar -xf openresty-<version>.tar.gz)

# Modify the configure script
Patch the `configure` script to link against wolfSSL instead of OpenSSL. In the OpenResty directory:
```
patch -p1 < <version>.patch
```
Patches for the following versions are available in this directory:
* 1.31.1.1
* 1.25.3.1
* 1.19.9.1
* 1.19.3.1
* 1.13.6.2

# Compiling wolfSSL
```
./configure --enable-openresty
make
make install
```

# Compiling OpenResty
```
./configure --with-wolfssl=/usr/local
make
```

# Known limitations with wolfSSL (1.31.1.1)
The following features need OpenSSL APIs that wolfSSL does not provide. They fail at configuration time or return an error; the rest of `ngx.ssl` works.
* `ssl_client_hello_by_lua*` (needs the OpenSSL 1.1.1 ClientHello callback API).
* `proxy_ssl_certificate_by_lua*` and `proxy_ssl_verify_by_lua*` (need OpenSSL 3.0.2 `SSL_set_retry_verify()`).
* Yielding (cosockets, sleeps) inside `ssl_session_fetch_by_lua*`. The handler runs synchronously because wolfSSL has no equivalent of OpenResty's OpenSSL `sess_set_get_cb_yield` patch.
* `lua_ssl_key_log`, `ngx.ssl.get_shared_ssl_ciphers()` and `ngx.ssl.export_keying_material*()` report "OpenSSL too old" because wolfSSL advertises OpenSSL 1.1.0 compatibility.
* Lua libraries that load OpenSSL symbols through FFI (`lua-resty-string`, `lua-resty-rsa`, `lua-resty-openssl`). wolfSSL only exports `wolfSSL_`-prefixed symbols.
* `ngx.ssl.set_der_cert()` with a certificate chain needs a wolfSSL release newer than 5.9.2 (`d2i_X509_bio()` fix). With older releases use `ngx.ssl.parse_pem_cert()` and `ngx.ssl.set_cert()` instead.
* Yielding (cosockets, sleeps, `ngx.thread.wait()`, semaphores) inside `ssl_certificate_by_lua*`. wolfSSL's certificate callback cannot suspend the handshake, so the port fails the handshake and logs `lua: cannot yield in cert cb` at `[crit]` instead of hanging. Load certificates synchronously, for example from a `lua_shared_dict` filled by a timer.
* `ngx.ocsp.validate_ocsp_response()` on a response without `nextUpdate` needs a wolfSSL release newer than 5.9.2.
* With wolfSSL 5.9.2 and older, `ssl_session_fetch_by_lua*` also runs when the client resumes with a session ticket. Newer releases skip it for ticket resumptions unless `ssl_early_data` is on, as OpenSSL does.
* HTTP/3 (`--with-http_v3_module`).
* Cosocket clients do not request TLS 1.2 session tickets (a wolfSSL client only does after `wolfSSL_UseSessionTicket()`), so their resumptions use session IDs and run `ssl_session_fetch_by_lua*` on the server.

# Running the bundled tests
The Test::Nginx suites of the bundled modules (`ngx_lua`, `ngx_stream_lua`, `lua-resty-core`) check the `nginx -V` banner and expect an OpenSSL build. `<version>-tests.patch` (1.31.1.1 only) makes them run against a wolfSSL build:
* `built with wolfSSL` in the banner sets `TEST_NGINX_USE_WOLFSSL=1`.
* Files that need the APIs listed above skip as a whole (`plan(skip_all => ...)`). Blocks that check OpenSSL-specific log text, cipher descriptions or APIs, or that yield inside `ssl_certificate_by_lua*`, skip with `--- skip_eval: N:$ENV{TEST_NGINX_USE_WOLFSSL}` and a comment naming the reason.
* The expected `Server` header is `openresty`, because the bundle and not a plain nginx serves the tests.

Apply it after the port patch and build with `--with-debug`, because the tests read the debug log. Run `prove` from the module directory:
```
patch -p1 < <version>-tests.patch
./configure --with-wolfssl=/usr/local --with-debug && make && make install
cd bundle/ngx_lua-*
TEST_NGINX_BINARY=/usr/local/openresty/nginx/sbin/nginx prove -I. t/139-ssl-cert-by.t
```
`lua-resty-core` needs its sibling directory named `lua-resty-lrucache`, some blocks need memcached on `TEST_NGINX_MEMCACHED_PORT` (11211) with UDP enabled (`memcached -U 11211`), and the unix socket paths under `t/servroot` must stay short. Do not set `TEST_NGINX_NO_CLEAN`, it leaves nginx running. wolfSSL's `.github/workflows/openresty.yml` runs the SSL test files in CI.

# Developer notes
When porting to a new version of OpenResty, you need to copy the appropriate Nginx patch from the wolfssl-nginx repo and rename it to `nginx-wolfssl.patch`. The patch file should be placed in the `bundle` directory.
```
cp <path/to/wolfssl/nginx/patch> bundle/nginx-wolfssl.patch
```
If wolfssl-nginx has no patch for the bundled nginx version, rebase the newest one. The nginx 1.31.1 patch inside `1.31.1.1.patch` was rebased from `nginx-1.28.1-wolfssl.patch`. The patch must apply cleanly against the nginx sources in `bundle/`, which carry OpenResty's own changes.

`1.31.1.1.patch` also initialises the `lua_ssl_*` defaults of `ngx_stream_lua` 0.0.19rc4, which the module only does when its proxy SSL support is compiled in. Without it every `lua_ssl_verify_depth` in a `stream` block fails as a duplicate directive.

Patches are generated with the following command:
```
git format-patch -1
```

The tests patch is a plain diff of the `t/` directories. Extract the tarball, apply `<version>.patch`, commit the tree in a scratch git repo, edit `bundle/*/t/*.t` and run:
```
git diff -- 'bundle/*/t/*' > <version>-tests.patch
```

