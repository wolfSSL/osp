--- config.h.orig	2015-06-21 04:41:25.818750681 +0200
+++ config.h	2015-06-21 05:08:24.678624381 +0200
@@ -245,7 +245,7 @@
 /* #undef HAVE_BLOWFISH_STREAM2WORD */
 
 /* Define to 1 if you have the `BN_is_prime_ex' function. */
-/* #undef HAVE_BN_IS_PRIME_EX */
+#define HAVE_BN_IS_PRIME_EX 1
 
 /* Define to 1 if you have the <bsd/libutil.h> header file. */
 /* #undef HAVE_BSD_LIBUTIL_H */
@@ -278,13 +278,13 @@
 #define HAVE_CONTROL_IN_MSGHDR 1
 
 /* Define to 1 if you have the `crypt' function. */
-/* #undef HAVE_CRYPT */
+#define HAVE_CRYPT 1
 
 /* Define to 1 if you have the <crypto/sha2.h> header file. */
 /* #undef HAVE_CRYPTO_SHA2_H */
 
 /* Define to 1 if you have the <crypt.h> header file. */
-#define HAVE_CRYPT_H 1
+/* #undef HAVE_CRYPT_H */
 
 /* Define if you are on Cygwin */
 /* #undef HAVE_CYGWIN */
@@ -383,7 +383,7 @@
 #define HAVE_DIRNAME 1
 
 /* Define to 1 if you have the `DSA_generate_parameters_ex' function. */
-/* #undef HAVE_DSA_GENERATE_PARAMETERS_EX */
+#define HAVE_DSA_GENERATE_PARAMETERS_EX 1
 
 /* Define to 1 if you have the <elf.h> header file. */
 #define HAVE_ELF_H 1
@@ -407,22 +407,22 @@
 /* #undef HAVE_EVP_CIPHER_CTX_CTRL */
 
 /* Define to 1 if you have the `EVP_DigestFinal_ex' function. */
-/* #undef HAVE_EVP_DIGESTFINAL_EX */
+#define HAVE_EVP_DIGESTFINAL_EX 1
 
 /* Define to 1 if you have the `EVP_DigestInit_ex' function. */
-/* #undef HAVE_EVP_DIGESTINIT_EX */
+#define HAVE_EVP_DIGESTINIT_EX 1
 
 /* Define to 1 if you have the `EVP_MD_CTX_cleanup' function. */
-/* #undef HAVE_EVP_MD_CTX_CLEANUP */
+#define HAVE_EVP_MD_CTX_CLEANUP 1
 
 /* Define to 1 if you have the `EVP_MD_CTX_copy_ex' function. */
-/* #undef HAVE_EVP_MD_CTX_COPY_EX */
+#define HAVE_EVP_MD_CTX_COPY_EX 1
 
 /* Define to 1 if you have the `EVP_MD_CTX_init' function. */
-/* #undef HAVE_EVP_MD_CTX_INIT */
+#define HAVE_EVP_MD_CTX_INIT 1
 
 /* Define to 1 if you have the `EVP_sha256' function. */
-/* #undef HAVE_EVP_SHA256 */
+#define HAVE_EVP_SHA256 1
 
 /* Define if you have ut_exit in utmp.h */
 #define HAVE_EXIT_IN_UTMP 1
@@ -816,7 +816,7 @@
 #define HAVE_OPENPTY 1
 
 /* Define if your ssl headers are included with #include <openssl/header.h> */
-/* #undef HAVE_OPENSSL */
+#undef HAVE_OPENSSL
 
 /* Define if you have Digital Unix Security Integration Architecture */
 /* #undef HAVE_OSF_SIA */
@@ -885,10 +885,10 @@
 #define HAVE_RRESVPORT_AF 1
 
 /* Define to 1 if you have the `RSA_generate_key_ex' function. */
-/* #undef HAVE_RSA_GENERATE_KEY_EX */
+#define HAVE_RSA_GENERATE_KEY_EX 1
 
 /* Define to 1 if you have the `RSA_get_default_method' function. */
-/* #undef HAVE_RSA_GET_DEFAULT_METHOD */
+#define HAVE_RSA_GET_DEFAULT_METHOD 1
 
 /* Define to 1 if you have the <sandbox.h> header file. */
 /* #undef HAVE_SANDBOX_H */
@@ -984,7 +984,7 @@
 /* #undef HAVE_SET_ID */
 
 /* Define to 1 if you have the `SHA256_Update' function. */
-/* #undef HAVE_SHA256_UPDATE */
+#define HAVE_SHA256_UPDATE 1
 
 /* Define to 1 if you have the <sha2.h> header file. */
 /* #undef HAVE_SHA2_H */
@@ -1448,19 +1448,19 @@
 /* #undef OPENSSL_EVP_DIGESTUPDATE_VOID */
 
 /* OpenSSL has ECC */
-/* #undef OPENSSL_HAS_ECC */
+#define OPENSSL_HAS_ECC 1
 
 /* libcrypto has NID_X9_62_prime256v1 */
-/* #undef OPENSSL_HAS_NISTP256 */
+#define OPENSSL_HAS_NISTP256 1
 
 /* libcrypto has NID_secp384r1 */
-/* #undef OPENSSL_HAS_NISTP384 */
+#define OPENSSL_HAS_NISTP384 1
 
 /* libcrypto has NID_secp521r1 */
-/* #undef OPENSSL_HAS_NISTP521 */
+#define OPENSSL_HAS_NISTP521 1
 
 /* libcrypto has EVP AES CTR */
-/* #undef OPENSSL_HAVE_EVPCTR */
+#define OPENSSL_HAVE_EVPCTR 1
 
 /* libcrypto has EVP AES GCM */
 /* #undef OPENSSL_HAVE_EVPGCM */
@@ -1707,3 +1707,11 @@
 
 /* type to use in place of socklen_t if not defined */
 /* #undef socklen_t */
+
+/* Define if using WolfSSL */
+#define USING_WOLFSSL 1
+#define WOLFSSL_AES_DIRECT 1
+#define WOLFSSL_SHA384 1
+#define WOLFSSL_SHA512 1
+#define WOLFSSL_RIPEMD 1
+#define UNSUPPORTED_POSIX_THREADS_HACK 1
