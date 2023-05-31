/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Paul Sokolovsky
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

#include <assert.h>
#include <string.h>

#include "py/runtime.h"

#if MICROPY_PY_WOLFSSL_UHASHLIB

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include "wolfssl/options.h"
#endif
#include "wolfssl/wolfcrypt/settings.h"

#if MICROPY_PY_UHASHLIB_SHA256
#include "wolfssl/wolfcrypt/sha256.h"
#endif

#if MICROPY_PY_UHASHLIB_SHA1 || MICROPY_PY_UHASHLIB_MD5
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/md5.h"
#endif

typedef struct _mp_obj_hash_t {
    mp_obj_base_t base;
    bool final; // if set, update and digest raise an exception
    uintptr_t state[0]; // must be aligned to a machine word
} mp_obj_hash_t;

static void wolfhashlib_ensure_not_final(mp_obj_hash_t *self) {
    if (self->final) {
        mp_raise_ValueError(MP_ERROR_TEXT("hash is final"));
    }
}

#if MICROPY_PY_UHASHLIB_SHA256
STATIC mp_obj_t wolfhashlib_sha256_update(mp_obj_t self_in, mp_obj_t arg);

STATIC mp_obj_t wolfhashlib_sha256_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_hash_t *o = mp_obj_malloc_var(mp_obj_hash_t, char, sizeof(Sha256), type);
    o->final = false;
    wc_InitSha256((Sha256*)&o->state);
    if (n_args == 1) {
        wolfhashlib_sha256_update(MP_OBJ_FROM_PTR(o), args[0]);
    }
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t wolfhashlib_sha256_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    wolfhashlib_ensure_not_final(self);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    wc_Sha256Update((Sha256*)&self->state, bufinfo.buf, bufinfo.len);
    return mp_const_none;
}

STATIC mp_obj_t wolfhashlib_sha256_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    wolfhashlib_ensure_not_final(self);
    self->final = true;
    vstr_t vstr;
    vstr_init_len(&vstr, WC_SHA256_DIGEST_SIZE);
    wc_Sha256Final((Sha256*)&self->state, (unsigned char *)vstr.buf);
    return mp_obj_new_bytes_from_vstr(&vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(wolfhashlib_sha256_update_obj, wolfhashlib_sha256_update);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(wolfhashlib_sha256_digest_obj, wolfhashlib_sha256_digest);

STATIC const mp_rom_map_elem_t wolfhashlib_sha256_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&wolfhashlib_sha256_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&wolfhashlib_sha256_digest_obj) },
};

STATIC MP_DEFINE_CONST_DICT(wolfhashlib_sha256_locals_dict, wolfhashlib_sha256_locals_dict_table);

STATIC MP_DEFINE_CONST_OBJ_TYPE(
    wolfhashlib_sha256_type,
    MP_QSTR_sha256,
    MP_TYPE_FLAG_NONE,
    make_new, wolfhashlib_sha256_make_new,
    locals_dict, &wolfhashlib_sha256_locals_dict
    );
#endif // MICROPY_PY_UHASHLIB_SHA256

#if MICROPY_PY_UHASHLIB_SHA1
STATIC mp_obj_t wolfhashlib_sha1_update(mp_obj_t self_in, mp_obj_t arg);

STATIC mp_obj_t wolfhashlib_sha1_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_hash_t *o = mp_obj_malloc_var(mp_obj_hash_t, char, sizeof(Sha), type);
    o->final = false;
    wc_InitSha((Sha*)o->state);
    if (n_args == 1) {
        wolfhashlib_sha1_update(MP_OBJ_FROM_PTR(o), args[0]);
    }
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t wolfhashlib_sha1_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    wolfhashlib_ensure_not_final(self);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    wc_ShaUpdate((Sha*)self->state, bufinfo.buf, bufinfo.len);
    return mp_const_none;
}

STATIC mp_obj_t wolfhashlib_sha1_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    wolfhashlib_ensure_not_final(self);
    self->final = true;
    vstr_t vstr;
    vstr_init_len(&vstr, WC_SHA_DIGEST_SIZE);
    wc_ShaFinal((Sha*)self->state, (byte *)vstr.buf);
    return mp_obj_new_bytes_from_vstr(&vstr);
}


STATIC MP_DEFINE_CONST_FUN_OBJ_2(wolfhashlib_sha1_update_obj, wolfhashlib_sha1_update);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(wolfhashlib_sha1_digest_obj, wolfhashlib_sha1_digest);

STATIC const mp_rom_map_elem_t wolfhashlib_sha1_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&wolfhashlib_sha1_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&wolfhashlib_sha1_digest_obj) },
};
STATIC MP_DEFINE_CONST_DICT(wolfhashlib_sha1_locals_dict, wolfhashlib_sha1_locals_dict_table);

STATIC MP_DEFINE_CONST_OBJ_TYPE(
    wolfhashlib_sha1_type,
    MP_QSTR_sha1,
    MP_TYPE_FLAG_NONE,
    make_new, wolfhashlib_sha1_make_new,
    locals_dict, &wolfhashlib_sha1_locals_dict
    );
#endif // MICROPY_PY_UHASHLIB_SHA1

#if MICROPY_PY_UHASHLIB_MD5
STATIC mp_obj_t wolfhashlib_md5_update(mp_obj_t self_in, mp_obj_t arg);

STATIC mp_obj_t wolfhashlib_md5_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_hash_t *o = mp_obj_malloc_var(mp_obj_hash_t, char, sizeof(Md5), type);
    o->final = false;
    wc_InitMd5((Md5*)o->state);
    if (n_args == 1) {
        wolfhashlib_md5_update(MP_OBJ_FROM_PTR(o), args[0]);
    }
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t wolfhashlib_md5_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    wolfhashlib_ensure_not_final(self);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    wc_Md5Update((Md5*)self->state, bufinfo.buf, bufinfo.len);
    return mp_const_none;
}

STATIC mp_obj_t wolfhashlib_md5_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    wolfhashlib_ensure_not_final(self);
    self->final = true;
    vstr_t vstr;
    vstr_init_len(&vstr, MD5_DIGEST_SIZE);
    wc_Md5Final((Md5*)self->state, (byte *)vstr.buf);
    return mp_obj_new_bytes_from_vstr(&vstr);
}


STATIC MP_DEFINE_CONST_FUN_OBJ_2(wolfhashlib_md5_update_obj, wolfhashlib_md5_update);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(wolfhashlib_md5_digest_obj, wolfhashlib_md5_digest);

STATIC const mp_rom_map_elem_t wolfhashlib_md5_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&wolfhashlib_md5_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&wolfhashlib_md5_digest_obj) },
};
STATIC MP_DEFINE_CONST_DICT(wolfhashlib_md5_locals_dict, wolfhashlib_md5_locals_dict_table);

STATIC MP_DEFINE_CONST_OBJ_TYPE(
    wolfhashlib_md5_type,
    MP_QSTR_md5,
    MP_TYPE_FLAG_NONE,
    make_new, wolfhashlib_md5_make_new,
    locals_dict, &wolfhashlib_md5_locals_dict
    );
#endif // MICROPY_PY_UHASHLIB_MD5

STATIC const mp_rom_map_elem_t mp_module_wolfhashlib_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_wolfhashlib) },
    #if MICROPY_PY_UHASHLIB_SHA256
    { MP_ROM_QSTR(MP_QSTR_sha256), MP_ROM_PTR(&wolfhashlib_sha256_type) },
    #endif
    #if MICROPY_PY_UHASHLIB_SHA1
    { MP_ROM_QSTR(MP_QSTR_sha1), MP_ROM_PTR(&wolfhashlib_sha1_type) },
    #endif
    #if MICROPY_PY_UHASHLIB_MD5
    { MP_ROM_QSTR(MP_QSTR_md5), MP_ROM_PTR(&wolfhashlib_md5_type) },
    #endif
};

STATIC MP_DEFINE_CONST_DICT(mp_module_wolfhashlib_globals, mp_module_wolfhashlib_globals_table);

const mp_obj_module_t mp_module_wolfhashlib = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_wolfhashlib_globals,
};

MP_REGISTER_MODULE(MP_QSTR_wolfhashlib, mp_module_wolfhashlib);

#endif // MICROPY_PY_WOLFSSL_UHASHLIB
