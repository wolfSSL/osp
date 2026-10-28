GCM exact-buffer reservation regression
=======================================

Run from any directory:

    /path/to/gcm_buffering/run.sh /path/to/applied-openzfs-source

The source tree must already have the wolfZFS patch applied. Required tools:
Bash, Python 3, a C compiler with ASan/UBSan support, and OpenSSL development
headers/libcrypto (for example, libssl-dev). CC may select the compiler.
The script requires the source-tree argument, creates its own temporary build
directory, and removes that directory on exit. It does not build OpenZFS or
modify the supplied tree or this checkout. Save stdout/stderr externally if a
persistent test receipt is wanted.

What is compiled
----------------
extract.py copies these actual functions unchanged and preserves their source
copyright/license notices:

* gcm_reserve_data, gcm_save_data, GCM initialization and encrypt/decrypt
  contiguous-block/final functions;
* aes_encrypt_atomic and aes_decrypt_atomic;
* crypto_update_iov and crypto_update_uio;
* gcm_clear_ctx.

The runner prints the applied source files' SHA256 values. Extraction fails
rather than substituting a model if a selected function cannot be located.
The extractor targets the named function/declaration layout in this patch;
changes to that layout can require updating the extraction rules.

Harness seams and limits
------------------------
Kernel data structures, key-schedule initialization, allocator operations and
wolfCrypt API calls are test seams. CCM is deliberately unreachable. The crypto
seam uses OpenSSL EVP and checks a NIST GCM known answer plus expected ciphertext
for the generated roundtrips. Both compilation profiles are exercised by
selecting whether WOLFSSL_AESGCM_STREAM is defined. This tests actual adapter
control flow, input traversal, output handling and buffer ownership; it does
not execute a licensed wolfCrypt module, verify FIPS wrappers or establish FIPS
runtime/compliance evidence. OpenSSL is a test dependency only.

Checks
------
Each profile runs 32 actual atomic roundtrip/authentication-failure cases over
RAW and fragmented UIO input, at lengths 0, 1, 15, 16, 17, 4096, 4097 and 1 MiB.
UIO uses the actual update traversal with 4096-byte fragments. Negative cases
cover short tags, INT_MAX/SIZE_MAX length rejection, insufficient output before
allocation, allocation failure, truncated UIO, and direct reserve/append/final
underfill and overfill contracts. Invalid tags must not release plaintext.

The allocator counts calls and rejects a second simultaneous allocation.
The actual cleanup must wipe every byte of the exact reservation before free;
free checks the size and zero contents. Separate memcpy instrumentation excludes
normal output copying and checks that no old work buffer is moved. The 1 MiB
cases require one exact allocation for buffered encryption and for decryption,
zero growth allocations and zero old-buffer moves. Streaming encryption must
allocate no work buffer. These deterministic work-count assertions address the
previous quadratic reallocation overhead; they are not throughput benchmarks.

ASan/UBSan and leak detection are enabled for both profiles. Failed assertions,
compiler errors, or sanitizer findings cause a nonzero runner exit.
