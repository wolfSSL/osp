#ifndef _USER_SETTINGS_H_
#define _USER_SETTINGS_H_

/* Verify this is Windows */
#ifdef _WIN32
    #ifdef WOLFSSL_VERBOSE_MSBUILD
        #pragma message("include Ws2_32")
    #endif
    /* Microsoft-specific pragma to link Ws2_32.lib */
    #pragma comment(lib, "Ws2_32.lib")
#else
    #error This user_settings.h header is only designed for Windows
#endif

#ifdef WOLFSSL_VERBOSE_MSBUILD
    /* See the wolfssl-GlobalProperties.props for build verbosity setting */
    #pragma message("Confirmed using realm/VS2022/include/user_settings.h")
#endif

#define USE_WOLFSSL_IO
#define HAVE_AESGCM
#define WOLFSSL_TLS13
#define HAVE_HKDF
#define HAVE_FFDHE_4096
#define WC_RSA_PSS
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_SEND_HRR_COOKIE
#define WOLFSSL_DTLS_CID
#define HAVE_TLS_EXTENSIONS

/* Realm */
#define HAVE_HMAC
#define WOLFSSL_SHA224
#define OPENSSL_EXTRA
#define OPENSSL_ALL
#define WOLFSSL_CERT_GEN
#define WOLFSSL_EVP_INCLUDED

/* npm */
#define NPM_WOLFCRYPT
#ifdef NPM_WOLFCRYPT
    /* Optional debug */
    /* #define DEBUG_WOLFSSL */

    /* Optional RNG */
    /* #define WC_RNG_SEED_CB */

    #define HAVE_PKCS7
    #define HAVE_AES_KEYWRAP
    #define WOLFSSL_AES_DIRECT
    #define HAVE_X963_KDF
    #define WOLFSSL_SHA224
    #define WOLFSSL_KEY_GEN
    #define HAVE_ECC
    #define ECC_MAX_BITS 521
    #define WC_ECC256
    #define WC_ECC384
    #define WC_ECC521
    #define HAVE_ECC_ENCRYPT
    #define WOLFSSL_UINT128_T_DEFINED
    #define WOLFSSL_SHA512
    #define WOLFSSL_SHA384
    #define WOLFSSL_SHA3

    #define NO_OLD_RNGNAME
    #define TFM_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT
    #define WC_RSA_BLINDING
    #define TFM_ECC256
    #define ECC_SHAMIR
    #define ECC_MIN_KEY_SZ 224
    #define HAVE_ECC_BRAINPOOL
    #define HAVE_CURVE25519
    #define FP_ECC
    #define HAVE_ECC_ENCRYPT
    // #define WOLFCRYPT_HAVE_ECCSI /* benchmark disabled */
    #define WOLFSSL_CUSTOM_CURVES
#endif

/* Configurations */
#if defined(HAVE_FIPS)
    /* FIPS */
    #define OPENSSL_EXTRA
    #define HAVE_THREAD_LS
    #define WOLFSSL_KEY_GEN
    #define HAVE_HASHDRBG
    #define WOLFSSL_SHA384
    #define WOLFSSL_SHA512
    #define NO_PSK
    #define NO_RC4
    #define NO_DSA
    #define NO_MD4

    #define GCM_NONCE_MID_SZ 12
#else
    /* Enables blinding mode, to prevent timing attacks */
    #define WC_RSA_BLINDING
    #define NO_MULTIBYTE_PRINT

    #define HAVE_CRL
    #define HAVE_CRL_MONITOR

    #if defined(WOLFSSL_LIB)
        /* The lib */
        #define OPENSSL_EXTRA
        #define WOLFSSL_RIPEMD
        #define NO_PSK
        #define HAVE_EXTENDED_MASTER
        #define WOLFSSL_SNIFFER
        #define HAVE_SECURE_RENEGOTIATION

        #define HAVE_AESGCM
        #define WOLFSSL_AESGCM_STREAM
        #define WOLFSSL_SHA384
        #define WOLFSSL_SHA512

        #define HAVE_SUPPORTED_CURVES
        #define HAVE_TLS_EXTENSIONS

        #define HAVE_ECC
        #define ECC_SHAMIR
        #define ECC_TIMING_RESISTANT

        #define WOLFSSL_SP_X86_64
        #define SP_INT_BITS  4096

        /* Optional Performance Speedups */
        #if 0
            /* AESNI on x64 */
            #ifdef _WIN64
                #define HAVE_INTEL_RDSEED
                #define WOLFSSL_AESNI
                #define HAVE_INTEL_AVX1
                #if 0
                    #define HAVE_INTEL_AVX2
                #endif

                #define USE_INTEL_CHACHA_SPEEDUP
                #define USE_INTEL_POLY1305_SPEEDUP
            #endif

            /* Single Precision Support for RSA/DH 1024/2048/3072 and
             * ECC P-256/P-384 */
            #define WOLFSSL_SP
            #define WOLFSSL_HAVE_SP_ECC
            #define WOLFSSL_HAVE_SP_DH
            #define WOLFSSL_HAVE_SP_RSA

            #ifdef _WIN64
                /* Old versions of MASM compiler do not recognize newer
                 * instructions. */
                #if 0
                    #define NO_AVX2_SUPPORT
                    #define NO_MOVBE_SUPPORT
                #endif
                #define WOLFSSL_SP_ASM
                #define WOLFSSL_SP_X86_64_ASM
            #endif
        #endif
    #else
        /* The servers and clients */
        #define OPENSSL_EXTRA
        #define NO_PSK
    #endif
#endif /* HAVE_FIPS */




#endif /* _USER_SETTINGS_H_ */
