/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2017-2018 Paul Sokolovsky
 * Copyright (c) 2018 Yonatan Goldschmidt
 * Copyright (c) 2023 wolfSSL Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "py/mpconfig.h"

#if MICROPY_PY_WOLFSSL_UCRYPTOLIB

#include <assert.h>
#include <string.h>

#include "py/runtime.h"

// This module implements crypto ciphers API, roughly following
// https://www.python.org/dev/peps/pep-0272/ . Exact implementation
// of PEP 272 can be made with a simple wrapper which adds all the
// needed boilerplate.

// values follow PEP 272
enum {
    UCRYPTOLIB_MODE_ECB = 1,
    UCRYPTOLIB_MODE_CBC = 2,
    UCRYPTOLIB_MODE_CTR = 6,
};

struct ctr_params {
    // counter is the IV of the AES context.

    size_t offset; // in encrypted_counter
    // encrypted counter
    uint8_t encrypted_counter[16];
};

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/aes.h>

struct wolfssl_aes_ctx_with_key {
    union {
        Aes ctx;
        struct {
            uint8_t key[AES_256_KEY_SIZE];
            uint8_t keysize;
        } init_data;
    } u;
    unsigned char iv[AES_IV_SIZE];
};
#define AES_CTX_IMPL struct wolfssl_aes_ctx_with_key

typedef struct _mp_obj_aes_t {
    mp_obj_base_t base;
    AES_CTX_IMPL ctx;
    uint8_t block_mode : 6;
#define AES_KEYTYPE_NONE 0
#define AES_KEYTYPE_ENC  1
#define AES_KEYTYPE_DEC  2
    uint8_t key_type : 2;
} mp_obj_aes_t;

static inline bool is_ctr_mode(int block_mode) {
    #if MICROPY_PY_UCRYPTOLIB_CTR
    return block_mode == UCRYPTOLIB_MODE_CTR;
    #else
    return false;
    #endif
}

static inline struct ctr_params *ctr_params_from_aes(mp_obj_aes_t *o) {
    // ctr_params follows aes object struct
    return (struct ctr_params *)&o[1];
}

STATIC void aes_initial_set_key_impl(AES_CTX_IMPL *ctx, const uint8_t *key, size_t keysize, const uint8_t iv[16]) {
    assert(AES_128_KEY_SIZE == keysize || AES_192_KEY_SIZE == keysize || AES_256_KEY_SIZE == keysize);

    ctx->u.init_data.keysize = keysize;
    memcpy(ctx->u.init_data.key, key, keysize);

    if (NULL != iv) {
        memcpy(ctx->iv, iv, sizeof(ctx->iv));
    }
}

STATIC void aes_final_set_key_impl(AES_CTX_IMPL *ctx, bool encrypt, mp_int_t block_mode) {
    // first, copy key aside
    uint8_t key[AES_256_KEY_SIZE];
    uint8_t keysize = ctx->u.init_data.keysize;

    assert(AES_128_KEY_SIZE == keysize || AES_192_KEY_SIZE == keysize || AES_256_KEY_SIZE == keysize);
    memcpy(key, ctx->u.init_data.key, keysize);

    int dir = (encrypt) ? AES_ENCRYPTION : AES_DECRYPTION;

    // now, override key with the context object, calling the appropriate key initialization
    // function for the block mode
    if (block_mode == UCRYPTOLIB_MODE_CBC) {
        wc_AesSetKey(&ctx->u.ctx, key, keysize, (const unsigned char*)&ctx->iv, dir);
    } else if (block_mode == UCRYPTOLIB_MODE_ECB) {
        // ECB requires NULL IV
        wc_AesSetKey(&ctx->u.ctx, key, keysize, NULL, dir);
    } else if (block_mode == UCRYPTOLIB_MODE_CTR) {
        // from AES API documentation:
        // NOTE: If using wc_AesSetKeyDirect with Aes Counter mode (Stream cipher)
        // only use AES_ENCRYPTION for both encrypting and decrypting
        wc_AesSetKeyDirect(&ctx->u.ctx, key, keysize, (const unsigned char*)&ctx->iv, AES_ENCRYPTION);
    }
}

STATIC void aes_process_ecb_impl(AES_CTX_IMPL *ctx, const uint8_t in[16], uint8_t out[16], bool encrypt) {
    if (encrypt) {
        wc_AesEncryptDirect(&ctx->u.ctx, out, in);
    } else {
        wc_AesDecryptDirect(&ctx->u.ctx, out, in);
    }
}

STATIC void aes_process_cbc_impl(AES_CTX_IMPL *ctx, const uint8_t *in, uint8_t *out, size_t in_len, bool encrypt) {
    if (encrypt) {
        wc_AesCbcEncrypt(&ctx->u.ctx, out, in, in_len);
    } else {
        wc_AesCbcDecrypt(&ctx->u.ctx, out, in, in_len);
    }
}

#if MICROPY_PY_UCRYPTOLIB_CTR
STATIC void aes_process_ctr_impl(AES_CTX_IMPL *ctx, const uint8_t *in, uint8_t *out, size_t in_len, struct ctr_params *ctr_params) {
    wc_AesCtrEncrypt(&ctx->u.ctx, out, in, in_len);
}
#endif


STATIC mp_obj_t wolfcryptolib_aes_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 2, 3, false);

    const mp_int_t block_mode = mp_obj_get_int(args[1]);

    switch (block_mode) {
        case UCRYPTOLIB_MODE_ECB:
        case UCRYPTOLIB_MODE_CBC:
        #if MICROPY_PY_UCRYPTOLIB_CTR
        case UCRYPTOLIB_MODE_CTR:
        #endif
            break;

        default:
            mp_raise_ValueError(MP_ERROR_TEXT("mode"));
    }

    mp_obj_aes_t *o = mp_obj_malloc_var(mp_obj_aes_t, struct ctr_params, !!is_ctr_mode(block_mode), type);

    o->block_mode = block_mode;
    o->key_type = AES_KEYTYPE_NONE;

    mp_buffer_info_t keyinfo;
    mp_get_buffer_raise(args[0], &keyinfo, MP_BUFFER_READ);
    if (32 != keyinfo.len && 16 != keyinfo.len) {
        mp_raise_ValueError(MP_ERROR_TEXT("key"));
    }

    mp_buffer_info_t ivinfo;
    ivinfo.buf = NULL;
    if (n_args > 2 && args[2] != mp_const_none) {
        mp_get_buffer_raise(args[2], &ivinfo, MP_BUFFER_READ);

        if (16 != ivinfo.len) {
            mp_raise_ValueError(MP_ERROR_TEXT("IV"));
        }
    } else if (o->block_mode == UCRYPTOLIB_MODE_CBC || is_ctr_mode(o->block_mode)) {
        mp_raise_ValueError(MP_ERROR_TEXT("IV"));
    }

    if (is_ctr_mode(block_mode)) {
        ctr_params_from_aes(o)->offset = 0;
    }

    aes_initial_set_key_impl(&o->ctx, keyinfo.buf, keyinfo.len, ivinfo.buf);

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t aes_process(size_t n_args, const mp_obj_t *args, bool encrypt) {
    mp_obj_aes_t *self = MP_OBJ_TO_PTR(args[0]);

    mp_obj_t in_buf = args[1];
    mp_obj_t out_buf = MP_OBJ_NULL;
    if (n_args > 2) {
        out_buf = args[2];
    }

    mp_buffer_info_t in_bufinfo;
    mp_get_buffer_raise(in_buf, &in_bufinfo, MP_BUFFER_READ);

    if (!is_ctr_mode(self->block_mode) && in_bufinfo.len % 16 != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("blksize % 16"));
    }

    vstr_t vstr;
    mp_buffer_info_t out_bufinfo;
    uint8_t *out_buf_ptr;

    if (out_buf != MP_OBJ_NULL) {
        mp_get_buffer_raise(out_buf, &out_bufinfo, MP_BUFFER_WRITE);
        if (out_bufinfo.len < in_bufinfo.len) {
            mp_raise_ValueError(MP_ERROR_TEXT("output too small"));
        }
        out_buf_ptr = out_bufinfo.buf;
    } else {
        vstr_init_len(&vstr, in_bufinfo.len);
        out_buf_ptr = (uint8_t *)vstr.buf;
    }

    if (AES_KEYTYPE_NONE == self->key_type) {
        // always set key for encryption if CTR mode.
        const bool encrypt_mode = encrypt || is_ctr_mode(self->block_mode);
        aes_final_set_key_impl(&self->ctx, encrypt_mode, self->block_mode);
        self->key_type = encrypt ? AES_KEYTYPE_ENC : AES_KEYTYPE_DEC;
    } else {
        if ((encrypt && self->key_type == AES_KEYTYPE_DEC) ||
            (!encrypt && self->key_type == AES_KEYTYPE_ENC)) {

            mp_raise_ValueError(MP_ERROR_TEXT("can't encrypt & decrypt"));
        }
    }

    switch (self->block_mode) {
        case UCRYPTOLIB_MODE_ECB: {
            uint8_t *in = in_bufinfo.buf, *out = out_buf_ptr;
            uint8_t *top = in + in_bufinfo.len;
            for (; in < top; in += 16, out += 16) {
                aes_process_ecb_impl(&self->ctx, in, out, encrypt);
            }
            break;
        }

        case UCRYPTOLIB_MODE_CBC:
            aes_process_cbc_impl(&self->ctx, in_bufinfo.buf, out_buf_ptr, in_bufinfo.len, encrypt);
            break;

        #if MICROPY_PY_UCRYPTOLIB_CTR
        case UCRYPTOLIB_MODE_CTR:
            aes_process_ctr_impl(&self->ctx, in_bufinfo.buf, out_buf_ptr, in_bufinfo.len,
                ctr_params_from_aes(self));
            break;
        #endif
    }

    if (out_buf != MP_OBJ_NULL) {
        return out_buf;
    }
    return mp_obj_new_bytes_from_vstr(&vstr);
}

STATIC mp_obj_t wolfcryptolib_aes_encrypt(size_t n_args, const mp_obj_t *args) {
    return aes_process(n_args, args, true);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(wolfcryptolib_aes_encrypt_obj, 2, 3, wolfcryptolib_aes_encrypt);

STATIC mp_obj_t wolfcryptolib_aes_decrypt(size_t n_args, const mp_obj_t *args) {
    return aes_process(n_args, args, false);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(wolfcryptolib_aes_decrypt_obj, 2, 3, wolfcryptolib_aes_decrypt);

STATIC const mp_rom_map_elem_t wolfcryptolib_aes_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_encrypt), MP_ROM_PTR(&wolfcryptolib_aes_encrypt_obj) },
    { MP_ROM_QSTR(MP_QSTR_decrypt), MP_ROM_PTR(&wolfcryptolib_aes_decrypt_obj) },
};
STATIC MP_DEFINE_CONST_DICT(wolfcryptolib_aes_locals_dict, wolfcryptolib_aes_locals_dict_table);

STATIC MP_DEFINE_CONST_OBJ_TYPE(
    wolfcryptolib_aes_type,
    MP_QSTR_aes,
    MP_TYPE_FLAG_NONE,
    make_new, wolfcryptolib_aes_make_new,
    locals_dict, &wolfcryptolib_aes_locals_dict
    );

STATIC const mp_rom_map_elem_t mp_module_wolfcryptolib_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_wolfcryptolib) },
    { MP_ROM_QSTR(MP_QSTR_aes), MP_ROM_PTR(&wolfcryptolib_aes_type) },
    #if MICROPY_PY_UCRYPTOLIB_CONSTS
    { MP_ROM_QSTR(MP_QSTR_MODE_ECB), MP_ROM_INT(UCRYPTOLIB_MODE_ECB) },
    { MP_ROM_QSTR(MP_QSTR_MODE_CBC), MP_ROM_INT(UCRYPTOLIB_MODE_CBC) },
    #if MICROPY_PY_UCRYPTOLIB_CTR
    { MP_ROM_QSTR(MP_QSTR_MODE_CTR), MP_ROM_INT(UCRYPTOLIB_MODE_CTR) },
    #endif
    #endif
};

STATIC MP_DEFINE_CONST_DICT(mp_module_wolfcryptolib_globals, mp_module_wolfcryptolib_globals_table);

const mp_obj_module_t mp_module_wolfcryptolib = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_wolfcryptolib_globals,
};

MP_REGISTER_MODULE(MP_QSTR_wolfcryptolib, mp_module_wolfcryptolib);

#endif // MICROPY_PY_WOLFSSL_UCRYPTOLIB
