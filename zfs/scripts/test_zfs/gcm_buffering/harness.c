#include <assert.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define CRYPTO_SUCCESS 0
#define CRYPTO_DATA_LEN_RANGE 1
#define CRYPTO_ENCRYPTED_DATA_LEN_RANGE 7
#define CRYPTO_HOST_MEMORY 2
#define CRYPTO_MECHANISM_PARAM_INVALID 3
#define CRYPTO_BUFFER_TOO_SMALL 4
#define CRYPTO_INVALID_MAC 5
#define CRYPTO_ARGUMENTS_BAD 6
#define AES_GCM_AUTH_E -180
#define CRYPTO_DATA_RAW 1
#define CRYPTO_DATA_UIO 2
#define KM_SLEEP 0
#define GCM_MODE 1
#define CCM_MODE 2
#define PROVIDER_OWNS_KEY_SCHEDULE 4
#define AES_GCM_MECH_INFO_TYPE 1
#define AES_CCM_MECH_INFO_TYPE 2
#define AES_BLOCK_LEN 16
#define WC_AES_BLOCK_SIZE 16
#define GCM_NONCE_MAX_SZ 16
#define CRYPTO_BITS2BYTES(x) ((x) / 8)
#define DEBUG_LOG(...) ((void)0)
#define ERR_LOG(...) ((void)0)
#define GCM_DUMP_DATA(...) ((void)0)
#define B_TRUE 1
#define B_FALSE 0
#define ASSERT assert
#define ASSERT0(x) assert((x) == 0)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define UIO_SYSSPACE 0
typedef int boolean_t;
typedef unsigned int uint_t;
typedef unsigned char uchar_t;
typedef struct {
    uint8_t key[32], iv[16];
    size_t keylen, ivlen;
    EVP_CIPHER_CTX *e;
    int dir;
} Aes;
typedef struct {
    Aes aes;
} aes_key_t;
typedef struct crypto_data {
    struct crypto_data *cd_uio;
    int cd_format;
    off_t cd_offset;
    size_t cd_length;
    struct {
        void *iov_base;
        size_t iov_len;
    } cd_raw;
    uint8_t *vec[1024];
    size_t lens[1024];
    unsigned nv;
} crypto_data_t;
typedef crypto_data_t zfs_uio_t;
typedef struct {
    Aes gcm_wc_aes;
    void *gcm_keysched;
    size_t keysched_len;
    uint8_t *gcm_work;
    size_t gcm_saved, gcm_work_len, gcm_tag_len, gcm_remainder_len,
        gcm_processed_data_len;
    int gcm_flags;
    const uint8_t *gcm_iv, *gcm_aad;
    size_t gcm_iv_len, gcm_aad_len;
    uint8_t gcm_chunk[256];
    size_t dummy;
} gcm_ctx_t;
typedef gcm_ctx_t aes_ctx_t;
typedef gcm_ctx_t ccm_ctx_t;
#define ac_flags gcm_flags
#define ac_keysched gcm_keysched
#define ac_keysched_len keysched_len
#define ac_tag_len gcm_tag_len
#define ac_remainder_len gcm_remainder_len
#define ac_mac_len dummy
#define ac_data_len dummy
#define ac_processed_data_len dummy
#define ac_processed_mac_len dummy
typedef struct {
    void *pIv, *pAAD;
    size_t ulIvLen, ulAADLen, ulTagBits;
} CK_AES_GCM_PARAMS;
typedef struct {
    int cm_type;
    void *cm_param;
} crypto_mechanism_t;
typedef aes_key_t crypto_key_t;
typedef void *crypto_spi_ctx_template_t;
static int fail_alloc, fail_crypto, fail_out, allocs, frees, output_active;
static size_t allocated, wiped, buffer_moves, peak;
static void *tracked;
static void *vmem_alloc(size_t n, int x) {
    (void)x;
    allocs++;
    if (fail_alloc)
        return NULL;
    assert(!tracked);
    void *p = malloc(n);
    assert(p);
    memset(p, 0xcc, n);
    tracked = p;
    allocated = n;
    if (n > peak)
        peak = n;
    return p;
}
static void vmem_free(void *p, size_t n) {
    assert(p == tracked && n == allocated);
    for (size_t i = 0; i < n; i++)
        assert(((unsigned char *)p)[i] == 0);
    wiped += n;
    frees++;
    free(p);
    tracked = NULL;
    allocated = 0;
}
static void explicit_memset(void *p, int v, size_t n) {
    volatile unsigned char *q = p;
    while (n--)
        *q++ = v;
}
static void *checked_memcpy(void *d, const void *s, size_t n) {
    if (tracked && s == tracked && d != tracked && !output_active)
        buffer_moves += n;
    return memcpy(d, s, n);
}
#define memcpy checked_memcpy
static int zfs_uio_segflg(zfs_uio_t *u) {
    (void)u;
    return 0;
}
static unsigned zfs_uio_iovcnt(zfs_uio_t *u) { return u->nv; }
static size_t zfs_uio_iovlen(zfs_uio_t *u, unsigned i) { return u->lens[i]; }
static char *zfs_uio_iovbase(zfs_uio_t *u, unsigned i) {
    return (char *)u->vec[i];
}
static off_t zfs_uio_index_at_offset(zfs_uio_t *u, off_t o, unsigned *i) {
    for (*i = 0; *i < u->nv; (*i)++) {
        if (o < (off_t)u->lens[*i])
            break;
        o -= u->lens[*i];
    }
    return o;
}
static int put_output(uint8_t *b, crypto_data_t *out, int n) {
    if (fail_out)
        return 4;
    if (out->cd_format == 1) {
        if (out->cd_offset < 0 ||
            (size_t)out->cd_offset > out->cd_raw.iov_len ||
            (size_t)n > out->cd_raw.iov_len - (size_t)out->cd_offset)
            return 4;
        if (n)
            memcpy((uint8_t *)out->cd_raw.iov_base + out->cd_offset, b, n);
        return 0;
    }
    size_t off = out->cd_offset, rem = n;
    for (unsigned i = 0; i < out->nv && rem; i++) {
        if (off >= out->lens[i]) {
            off -= out->lens[i];
            continue;
        }
        size_t k = MIN(out->lens[i] - off, rem);
        memcpy(out->vec[i] + off, b, k);
        b += k;
        rem -= k;
        off = 0;
    }
    return rem ? 4 : 0;
}
static int crypto_put_output_data(uint8_t *b, crypto_data_t *out, int n) {
    output_active = 1;
    int r = put_output(b, out, n);
    output_active = 0;
    return r;
}
static int cipher(Aes *a, uint8_t *out, const uint8_t *in, unsigned n,
                  const uint8_t *iv, unsigned ivn, uint8_t *tag, unsigned tn,
                  const uint8_t *aad, unsigned an, int enc) {
    if (fail_crypto)
        return -1;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    assert(c);
    int k = 0, r;
    assert(EVP_CipherInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL, enc));
    assert(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, ivn, NULL));
    assert(EVP_CipherInit_ex(c, NULL, NULL, a->key, iv, enc));
    if (an)
        assert(EVP_CipherUpdate(c, NULL, &k, aad, an));
    if (n)
        assert(EVP_CipherUpdate(c, out, &k, in, n));
    if (!enc)
        assert(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, tn, tag));
    uint8_t dummy[16];
    r = EVP_CipherFinal_ex(c, n ? out + n : dummy, &k);
    if (enc)
        assert(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, tn, tag));
    EVP_CIPHER_CTX_free(c);
    return r ? 0 : AES_GCM_AUTH_E;
}
#ifndef WOLFSSL_AESGCM_STREAM
static int wc_AesGcmSetExtIV(Aes *a, const uint8_t *iv, uint32_t n) {
    if (fail_crypto)
        return -1;
    memcpy(a->iv, iv, n);
    a->ivlen = n;
    return 0;
}
static int wc_AesGcmEncrypt_ex(Aes *a, uint8_t *out, const uint8_t *in,
                               uint32_t n, uint8_t *iv, uint32_t ivn,
                               uint8_t *t, uint32_t tn, const uint8_t *aad,
                               uint32_t an) {
    memcpy(iv, a->iv, ivn);
    return cipher(a, out, in, n, a->iv, ivn, t, tn, aad, an, 1);
}
static int wc_AesGcmDecrypt(Aes *a, uint8_t *out, const uint8_t *in, uint32_t n,
                            const uint8_t *iv, uint32_t ivn, const uint8_t *t,
                            uint32_t tn, const uint8_t *aad, uint32_t an) {
    return cipher(a, out, in, n, iv, ivn, (uint8_t *)t, tn, aad, an, 0);
}
#else
static int wc_AesGcmInit(Aes *a, const void *k, unsigned kn, const uint8_t *iv,
                         unsigned ivn) {
    (void)k;
    (void)kn;
    memcpy(a->iv, iv, ivn);
    a->ivlen = ivn;
    return 0;
}
static int streamupdate(Aes *a, uint8_t *out, const uint8_t *in, unsigned n,
                        const uint8_t *aad, unsigned an, int enc) {
    if (fail_crypto)
        return -1;
    if (!a->e) {
        a->e = EVP_CIPHER_CTX_new();
        assert(a->e);
        assert(
            EVP_CipherInit_ex(a->e, EVP_aes_128_gcm(), NULL, NULL, NULL, enc));
        assert(
            EVP_CIPHER_CTX_ctrl(a->e, EVP_CTRL_GCM_SET_IVLEN, a->ivlen, NULL));
        assert(EVP_CipherInit_ex(a->e, NULL, NULL, a->key, a->iv, enc));
    }
    int l;
    if (an)
        assert(EVP_CipherUpdate(a->e, NULL, &l, aad, an));
    if (n)
        assert(EVP_CipherUpdate(a->e, out, &l, in, n));
    return 0;
}
static int wc_AesGcmEncryptUpdate(Aes *a, uint8_t *out, const uint8_t *in,
                                  unsigned n, const uint8_t *aad, unsigned an) {
    return streamupdate(a, out, in, n, aad, an, 1);
}
static int wc_AesGcmDecryptUpdate(Aes *a, uint8_t *out, const uint8_t *in,
                                  unsigned n, const uint8_t *aad, unsigned an) {
    return streamupdate(a, out, in, n, aad, an, 0);
}
static int wc_AesGcmEncryptFinal(Aes *a, uint8_t *t, unsigned tn) {
    uint8_t b[16];
    int n;
    assert(EVP_CipherFinal_ex(a->e, b, &n));
    assert(EVP_CIPHER_CTX_ctrl(a->e, EVP_CTRL_GCM_GET_TAG, tn, t));
    return 0;
}
static int wc_AesGcmDecryptFinal(Aes *a, const uint8_t *t, unsigned tn) {
    uint8_t b[16];
    int n;
    assert(EVP_CIPHER_CTX_ctrl(a->e, EVP_CTRL_GCM_SET_TAG, tn, (void *)t));
    return EVP_CipherFinal_ex(a->e, b, &n) ? 0 : AES_GCM_AUTH_E;
}
#endif
static void wc_AesFree(Aes *a) {
    EVP_CIPHER_CTX_free(a->e);
    a->e = NULL;
}
#include "actual-clear.c"
#include "actual-gcm.c"
#include "actual-update.c"
static int aes_check_mech_param(crypto_mechanism_t *m, void *p) {
    (void)m;
    (void)p;
    return 0;
}
static int aes_common_init_ctx(aes_ctx_t *c, void *t, crypto_mechanism_t *m,
                               crypto_key_t *k, int x, int enc) {
    (void)t;
    (void)x;
    c->gcm_keysched = k;
    return gcm_init_ctx(c, m->cm_param, enc, 16, NULL, NULL, NULL);
}
static void aes_free_keysched(void *p, size_t n) {
    (void)p;
    (void)n;
    abort();
}
static int aes_encrypt_contiguous_blocks(void *c, caddr_t p, size_t n,
                                         crypto_data_t *o) {
    return gcm_mode_encrypt_contiguous_blocks(c, p, n, o, 16, NULL, NULL, NULL);
}
static int aes_decrypt_contiguous_blocks(void *c, caddr_t p, size_t n,
                                         crypto_data_t *o) {
    return gcm_mode_decrypt_contiguous_blocks(c, p, n, o, 16, NULL, NULL, NULL);
}
static int ccm_encrypt_final(ccm_ctx_t *c, crypto_data_t *o, size_t n, void *a,
                             void *b) {
    (void)c;
    (void)o;
    (void)n;
    (void)a;
    (void)b;
    abort();
}
static int ccm_decrypt_final(ccm_ctx_t *c, crypto_data_t *o, size_t n, void *a,
                             void *b, void *d) {
    (void)c;
    (void)o;
    (void)n;
    (void)a;
    (void)b;
    (void)d;
    abort();
}
static void ccm_clear_ctx(ccm_ctx_t *c) {
    (void)c;
    abort();
}
#include "actual-atomic.c"
#undef memcpy
static uint8_t iv[12], aad[13];
static crypto_key_t key;
static CK_AES_GCM_PARAMS params = {iv, aad, 12, 13, 128};
static crypto_mechanism_t mech = {AES_GCM_MECH_INFO_TYPE, &params};
static void reset(void) {
    assert(!tracked);
    allocs = frees = 0;
    peak = wiped = buffer_moves = 0;
    fail_alloc = fail_crypto = fail_out = 0;
}
static crypto_data_t data(uint8_t *p, size_t n, int uio, size_t chunk) {
    crypto_data_t d = {
        .cd_format = uio ? 2 : 1, .cd_length = n, .cd_raw = {p, n}};
    if (uio) {
        while (n) {
            assert(d.nv < 1024);
            size_t k = MIN(n, chunk);
            d.vec[d.nv] = p;
            d.lens[d.nv++] = k;
            p += k;
            n -= k;
        }
    }
    return d;
}
static void linkdata(crypto_data_t *d) { d->cd_uio = d; }
static int cases;
static void roundtrip(size_t n, int uio, int bad) {
    uint8_t *p = malloc(n + 1), *ct = malloc(n + 16), *ref = malloc(n + 16),
            *out = malloc(n + 1);
    for (size_t i = 0; i < n; i++)
        p[i] = i;
    crypto_data_t in = data(p, n, uio, 4096), enc = data(ct, n + 16, 0, 1);
    linkdata(&in);
    reset();
    int rc = aes_encrypt_atomic(&mech, &key, &in, &enc, NULL);
    assert(rc == 0 && enc.cd_length == n + 16 && enc.cd_offset == 0);
    assert(buffer_moves == 0);
#ifndef WOLFSSL_AESGCM_STREAM
    assert(allocs == (n ? 1 : 0) && frees == allocs && wiped == n && peak == n);
#else
    assert(allocs == 0 && frees == 0);
#endif
    Aes a = {0};
    assert(!cipher(&a, ref, p, n, iv, 12, ref + n, 16, aad, 13, 1));
    assert(!memcmp(ct, ref, n + 16));
    if (bad)
        ct[n] ^= 1;
    crypto_data_t ci = data(ct, n + 16, uio, 4096), po = data(out, n, 0, 1);
    linkdata(&ci);
    memset(out, 0xa5, n + 1);
    reset();
    rc = aes_decrypt_atomic(&mech, &key, &ci, &po, NULL);
    assert(rc == (bad ? CRYPTO_INVALID_MAC : 0));
    assert(allocs == 1 && frees == 1 && wiped == n + 16 && peak == n + 16);
    assert(buffer_moves == 0);
    if (bad) {
        for (size_t i = 0; i < n + 1; i++)
            assert(out[i] == 0xa5);
    } else
        assert(!memcmp(p, out, n));
    if (n == 1048576 && !bad)
        printf("PERF actual atomic %s input=%zu encrypt_alloc=%d "
               "decrypt_alloc=1 decrypt_capacity=%zu full_wipe=%zu "
               "growth_allocations=0 old_buffer_moves=0\n",
               uio ? "UIO/4KiB" : "RAW", n,
#ifndef WOLFSSL_AESGCM_STREAM
               1,
#else
               0,
#endif
               n + 16, wiped);
    free(p);
    free(ct);
    free(ref);
    free(out);
    cases++;
}
static void negatives(void) {
    uint8_t b[80] = {0}, o[100];
    crypto_data_t in = data(b, 64, 1, 16), out = data(o, sizeof o, 0, 1);
    linkdata(&in);
    reset();
    out.cd_length = 1;
    assert(aes_encrypt_atomic(&mech, &key, &in, &out, NULL) == 4);
    assert(!allocs);
    reset();
    in.cd_length = 15;
    out.cd_length = sizeof o;
    assert(aes_decrypt_atomic(&mech, &key, &in, &out, NULL) == 7);
    assert(!allocs);
    reset();
    in.cd_length = (size_t)INT_MAX + 1;
    assert(aes_decrypt_atomic(&mech, &key, &in, &out, NULL) == 7);
    assert(!allocs);
#ifndef WOLFSSL_AESGCM_STREAM
    reset();
    assert(aes_encrypt_atomic(&mech, &key, &in, &out, NULL) == 1);
    assert(!allocs);
#endif
    reset();
    in.cd_length = SIZE_MAX;
    assert(aes_encrypt_atomic(&mech, &key, &in, &out, NULL) == 1);
    assert(!allocs);
    reset();
    in.cd_length = 64;
    fail_alloc = 1;
    int r = aes_decrypt_atomic(&mech, &key, &in, &out, NULL);
    assert(r == 2 && allocs == 1 && !frees && !tracked);
#ifndef WOLFSSL_AESGCM_STREAM
    reset();
    fail_alloc = 1;
    assert(aes_encrypt_atomic(&mech, &key, &in, &out, NULL) == 2);
    assert(allocs == 1 && !tracked);
#endif
    /* Actual UIO traversal observes fewer bytes than declared. */
    reset();
    in.cd_length = 65;
    assert(aes_decrypt_atomic(&mech, &key, &in, &out, NULL) == 1);
    assert(allocs == 1 && frees == 1 && wiped == 65);
    /* Exact reservation contract: direct unsupported under/over-fill cannot
     * pass final. */
    gcm_ctx_t c = {0};
    c.gcm_keysched = &key;
    reset();
    assert(!gcm_init_ctx(&c, (char *)&params, 0, 16, NULL, NULL, NULL));
    assert(!gcm_reserve_data(&c, 32));
    assert(!gcm_save_data(&c, (char *)b, 16));
    assert(gcm_decrypt_final(&c, &out, 16, NULL, NULL) == 5);
    assert(gcm_save_data(&c, (char *)b, 17) == 1);
    assert(c.gcm_saved == 16 && c.gcm_work_len == 32);
    gcm_clear_ctx(&c);
    assert(wiped == 32 && !tracked);
#ifndef WOLFSSL_AESGCM_STREAM
    c = (gcm_ctx_t){0};
    c.gcm_keysched = &key;
    reset();
    assert(!gcm_init_ctx(&c, (char *)&params, 1, 16, NULL, NULL, NULL));
    assert(!gcm_reserve_data(&c, 32));
    assert(!gcm_save_data(&c, (char *)b, 16));
    assert(gcm_encrypt_final(&c, &out, 16, NULL, NULL, NULL) == 1);
    gcm_clear_ctx(&c);
    assert(wiped == 32);
#endif
    reset();
    c = (gcm_ctx_t){0};
    assert(gcm_reserve_data(&c, (size_t)INT_MAX + 1) == 1);
    assert(!allocs);
    assert(gcm_save_data(&c, (char *)b, 1) == 1);
    assert(!allocs);
}
static void nist(void) {
    uint8_t zero[16] = {0}, ct[32],
            expect[] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
                        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    params.pAAD = NULL;
    params.ulAADLen = 0;
    crypto_data_t in = data(zero, 16, 0, 1), out = data(ct, 32, 0, 1);
    reset();
    assert(!aes_encrypt_atomic(&mech, &key, &in, &out, NULL));
    assert(!memcmp(ct, expect, 32));
    params.pAAD = aad;
    params.ulAADLen = 13;
}
int main(void) {
    nist();
    size_t ns[] = {0, 1, 15, 16, 17, 4096, 4097, 1048576};
    for (unsigned i = 0; i < sizeof ns / sizeof *ns; i++)
        for (int u = 0; u < 2; u++)
            for (int b = 0; b < 2; b++)
                roundtrip(ns[i], u, b);
    negatives();
    printf("PASS actual atomic+actual RAW/UIO traversal: %d "
           "roundtrip/auth-failure cases; NIST; "
           "bounds/truncation/overfill/underfill/allocation-failure/full-wipe "
           "checks\n",
           cases);
}
