#include "wolfssl_micropy_error.h"

#include "py/runtime.h"
//#include "py/stream.h"
#include "py/objstr.h"

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include "wolfssl/wolfcrypt/settings.h"

#include "wolfssl/ssl.h"


NORETURN void wolfssl_raise_error(int err) {
    mp_obj_str_t *o_str = m_new_obj_maybe(mp_obj_str_t);
    byte *o_str_buf = m_new_maybe(byte, WOLFSSL_MAX_ERROR_SZ);
    if (o_str == NULL || o_str_buf == NULL) {
        mp_raise_OSError(err);
    }

    wolfSSL_ERR_error_string(err, (char*)o_str_buf);

    // Put the exception object together
    o_str->base.type = &mp_type_str;
    o_str->data = o_str_buf;
    o_str->len = strlen((char*)o_str_buf);
    o_str->hash = qstr_compute_hash(o_str->data, o_str->len);
    // raise
    mp_obj_t args[2] = { MP_OBJ_NEW_SMALL_INT(err), MP_OBJ_FROM_PTR(o_str)};
    nlr_raise(mp_obj_exception_make_new(&mp_type_OSError, 2, 0, args));
}


