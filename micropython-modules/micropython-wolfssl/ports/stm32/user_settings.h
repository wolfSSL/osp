/* user_settings.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Custom wolfSSL user settings for GCC ARM */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(WOLFSSL_CONF_OPTIMIZE_SIZE) && defined(WOLFSSL_CONF_OPTIMIZE_SPEED)) \
    || (defined(WOLFSSL_CONF_OPTIMIZE_SPEED) && defined(WOLFSSL_CONF_OPTIMIZE_MEM)) \
    || (defined(WOLFSSL_CONF_OPTIMIZE_SIZE) && defined(WOLFSSL_CONF_OPTIMIZE_MEM))
    #error "Please choose only one optimization method: size, speed, or memory"
#elif !defined(WOLFSSL_CONF_OPTIMIZE_SIZE) && !defined(WOLFSSL_CONF_OPTIMIZE_SPEED) && !defined(WOLFSSL_CONF_OPTIMIZE_MEM)
    // default optimization is for size
    #define WOLFSSL_CONF_OPTIMIZE_SIZE
#endif


/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT   4
#define SINGLE_THREADED
#define WOLFSSL_USER_IO
#define WOLFSSL_ASN_TEMPLATE

//#define WOLFSSL_SMALL_STACK

//#define NO_WOLFSSL_SERVER
#define WOLFSSL_NO_TLS12

/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
#define SIZEOF_LONG_LONG 8

#if 1
    #define WOLFSSL_SP_MATH_ALL
    #define WOLFSSL_SP_SMALL
    //#define WOLFSSL_SP_ARM_THUMB
#else
    #define WOLFSSL_SP_SMALL      /* use smaller version of code */
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_HAVE_SP_DH
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_SP_MATH     /* only SP math - eliminates fast math code */
    #define WOLFSSL_SP_ARM_THUMB_ASM
#endif

//#define WOLFSSL_SP
//#define WOLFSSL_SP_SMALL      /* use smaller version of code */
//#define WOLFSSL_HAVE_SP_RSA
//#define WOLFSSL_HAVE_SP_DH
//#define WOLFSSL_HAVE_SP_ECC
////#define WOLFSSL_SP_CACHE_RESISTANT
//#define WOLFSSL_SP_MATH     /* only SP math - eliminates fast math code */
//
///* SP Assembly Speedups */
//#define WOLFSSL_SP_ASM      /* required if using the ASM versions */
////#define WOLFSSL_SP_ARM32_ASM
////#define WOLFSSL_SP_ARM64_ASM
////#define WOLFSSL_SP_ARM_THUMB_ASM
//#define WOLFSSL_SP_ARM_CORTEX_M_ASM

/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
/* half as much memory but twice as slow */
#if defined(WOLFSSL_CONF_OPTIMIZE_SIZE) || defined(WOLFSSL_CONF_OPTIMIZE_MEM)
    #define RSA_LOW_MEM
#endif

/* Enables blinding mode, to prevent timing attacks */
#undef  WC_RSA_BLINDING
#define WC_RSA_BLINDING

/* RSA PSS Support */
#define WC_RSA_PSS

/* ECC */
#define HAVE_ECC

/* Manually define enabled curves */
#define ECC_USER_CURVES
#ifdef ECC_USER_CURVES
    /* Manual Curve Selection */
    //#define HAVE_ECC192
    //#define HAVE_ECC224
    //#undef NO_ECC256
    //#define HAVE_ECC384
    //#define HAVE_ECC521
#endif

/* Optional ECC calculation method */
/* Note: doubles heap usage, but slightly faster */
#define ECC_SHAMIR

/* Reduces heap usage, but slower */
#define ECC_TIMING_RESISTANT

/* DH */
/* Use table for DH instead of -lm (math) lib dependency */
#define WOLFSSL_DH_CONST
#define HAVE_FFDHE_2048
//#define HAVE_FFDHE_4096
//#define HAVE_FFDHE_6144
//#define HAVE_FFDHE_8192

/* AES */
#define HAVE_AES_CBC
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER

#if defined(WOLFSSL_CONF_OPTIMIZE_SIZE)
    /* GCM Method: GCM_SMALL, GCM_WORD32 or GCM_TABLE */
    #define GCM_SMALL
    #define WOLFSSL_AES_SMALL_TABLES
    #define WOLFSSL_AES_NO_UNROLL
#endif

/* DES3 */
#define NO_DES3


/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
/* 1k smaller, but 25% slower */
#if defined(WOLFSSL_CONF_OPTIMIZE_SIZE)
    #define USE_SLOW_SHA
#endif

/* Sha256 */
#if defined(WOLFSSL_CONF_OPTIMIZE_SIZE)
    /* not unrolled - ~2k smaller and ~25% slower */
    #define USE_SLOW_SHA256
#endif

///* Sha512 */
//#define WOLFSSL_SHA512
//
///* Sha384 */
//#define WOLFSSL_SHA384
//
///* over twice as small, but 50% slower */
//#define USE_SLOW_SHA512

/* HKDF */
#define HAVE_HKDF

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
//#define DEBUG_WOLFSSL
#if defined(WOLFSSL_CONF_OPTIMIZE_SIZE)
    #define NO_ERROR_STRINGS
#endif


/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */
/* Override Memory API's */
#undef  XMALLOC_OVERRIDE
#define XMALLOC_OVERRIDE

/* prototypes for user heap override functions */
/* Note: Realloc only required for normal math */
#include <stddef.h>  /* for size_t */
extern void *myMalloc(size_t n, void* heap, int type);
extern void myFree(void *p, void* heap, int type);
// extern void *myRealloc(void *p, size_t n, void* heap, int type);

#define XMALLOC(n, h, t)     myMalloc(n, h, t)
#define XFREE(p, h, t)       myFree(p, h, t)
// #define XREALLOC(p, n, h, t) myRealloc(p, n, h, t)

/* use stdlib malloc, free and realloc */
#define NO_WOLFSSL_MEMORY


/* ------------------------------------------------------------------------- */
/* Port */
/* ------------------------------------------------------------------------- */
#define CTYPE_USER
#include <stdint.h>
extern uint32_t unichar_tolower(uint32_t);
#define XTOLOWER unichar_tolower

/* Override Current Time */
/* Allows custom "custom_time()" function to be used for benchmark */
//#define WOLFSSL_USER_CURRTIME
//#define WOLFSSL_GMTIME
//#define USER_TICKS
//extern unsigned long my_time(unsigned long* timer);
//#define NO_ASN_TIME

//#define HAL_RTC_MODULE_ENABLED

#include <time.h>
#define TIME_OVERRIDES
#define HAVE_TIME_T_TYPE
#define HAVE_TM_TYPE
//#define WOLFSSL_GMTIME


/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */
/* Seed Source */
/* Size of returned HW RNG value */
#define CUSTOM_RAND_TYPE      unsigned int
extern unsigned int my_rng_seed_gen(void);
#undef  CUSTOM_RAND_GENERATE
#define CUSTOM_RAND_GENERATE  my_rng_seed_gen

//
//#define WOLFSSL_STM32_CUBEMX
// #define WOLFSSL_STM32_RNG_NOLIB
// #define STM32_RNG

/* Choose RNG method */
#if 1
    /* Use built-in P-RNG (SHA256 based) with HW RNG */
    /* P-RNG + HW RNG (P-RNG is ~8K) */
    #undef  HAVE_HASHDRBG
    #define HAVE_HASHDRBG
#else
    #undef  WC_NO_HASHDRBG
    #define WC_NO_HASHDRBG

    /* Bypass P-RNG and use only HW RNG */
    extern int my_rng_gen_block(unsigned char* output, unsigned int sz);
    #undef  CUSTOM_RAND_GENERATE_BLOCK
    #define CUSTOM_RAND_GENERATE_BLOCK  my_rng_gen_block
#endif


/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_SNI
#define KEEP_PEER_CERT
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define WOLFSSL_BASE64_ENCODE
#define NO_SESSION_CACHE

/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#define NO_CRYPT_TEST
#define NO_CRYPT_BENCHMARK

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
#undef  NO_INLINE
//#define NO_INLINE

#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define NO_DSA
#define NO_RC4
#define NO_OLD_TLS
#define NO_OLD_RNGNAME
#define NO_PSK
#define NO_MD4
#define NO_PWDBASED
#define WOLFSSL_IGNORE_FILE_WARN


#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */



