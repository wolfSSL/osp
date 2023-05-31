WOLFSSL_MOD_DIR := $(USERMOD_DIR)

# Add required compile options for micropython
CFLAGS_USERMOD += -DWOLFSSL_USER_SETTINGS -Wno-error=unused-function
# define built-in compile guards to 0 to prevent compilation of extmod/moduhashlib.c, extmod/moducryptolib.c, and extmod/modussl_*.c
CFLAGS_USERMOD += -DMICROPY_PY_UHASHLIB=0 -DMICROPY_PY_UCRYPTOLIB=0 -DMICROPY_PY_USSL=0
# replace with wolfSSL versions
CFLAGS_USERMOD += -DMICROPY_PY_WOLFSSL_UHASHLIB=1 -DMICROPY_PY_WOLFSSL_UCRYPTOLIB=1 -DMICROPY_PY_WOLFSSL_USSL=1

ifeq ($(WOLFSSL_DEBUG),1)
CFLAGS_USERMOD += -DWOLFSSL_DEBUG=1
endif

# Add wolfSSL generic include paths
CFLAGS_USERMOD += -I$(WOLFSSL_MOD_DIR)/wolfssl -I$(WOLFSSL_MOD_DIR)/wolfssl/wolfssl

WOLFSSL_PORT ?= unix
WOLFSSL_PORT_DIR = $(WOLFSSL_MOD_DIR)/ports/$(WOLFSSL_PORT)

$(info [micropython-wolfssl] WOLFSSL_SOURCE=$(WOLFSSL_SOURCE))
$(info [micropython-wolfssl] PORT=$(WOLFSSL_PORT))
$(info [micropython-wolfssl] PORT_DIR=$(WOLFSSL_PORT_DIR))

# check user supplied port corresponds to a port directory with a valid user settings file
ifneq ($(wildcard $(WOLFSSL_PORT_DIR)/user_settings.h),)
# If port is valid, use either user supplied settings file, or default one for the port
ifneq ($(wildcard $(WOLFSSL_USER_SETTINGS_FILE)),)
$(info [micropython-wolfssl] Using custom user settings file: $(WOLFSSL_USER_SETTINGS_FILE))
CFLAGS_USERMOD += -I$(dir $(WOLFSSL_USER_SETTINGS_FILE))
else
$(info [micropython-wolfssl] Using default user settings file: $(WOLFSSL_PORT_DIR/user_settings.h))
CFLAGS_USERMOD += -I$(dir $(WOLFSSL_PORT_DIR)/user_settings.h)
endif
else
$(error no valid port directory with user settings for WOLFSSL_PORT: $(WOLFSSL_PORT_DIR))
endif 

# Add the appropriate port file to source list if it exists
ifneq ($(wildcard $(WOLFSSL_PORT_DIR)/wolfssl_port.c),)
SRC_USERMOD += $(WOLFSSL_PORT_DIR)/wolfssl_port.c
$(info [micropython-wolfssl]: using port file: $(WOLFSSL_PORT_DIR)/wolfssl_port.c)
else
$(info [micropython-wolfssl]: no port file found for port="$(WOLFSSL_PORT)")
endif 

# Add all C files to SRC_USERMOD.
SRC_USERMOD += $(WOLFSSL_MOD_DIR)/modussl_wolfssl.c
SRC_USERMOD += $(WOLFSSL_MOD_DIR)/moducryptolib_wolfssl.c
SRC_USERMOD += $(WOLFSSL_MOD_DIR)/moduhashlib_wolfssl.c
SRC_USERMOD += $(addprefix $(WOLFSSL_MOD_DIR)/wolfssl/,\
	src/crl.c \
	src/internal.c \
	src/keys.c \
	src/ocsp.c \
	src/sniffer.c \
	src/ssl.c \
	src/tls.c \
	src/tls13.c \
	src/wolfio.c \
	wolfcrypt/src/aes.c \
	wolfcrypt/src/cmac.c \
	wolfcrypt/src/des3.c \
	wolfcrypt/src/dh.c \
	wolfcrypt/src/ecc.c \
	wolfcrypt/src/hmac.c \
	wolfcrypt/src/random.c \
	wolfcrypt/src/rsa.c \
	wolfcrypt/src/sha.c \
	wolfcrypt/src/sha256.c \
	wolfcrypt/src/sha512.c \
	wolfcrypt/src/sha3.c \
	wolfcrypt/src/asm.c \
	wolfcrypt/src/asn.c \
	wolfcrypt/src/blake2s.c \
	wolfcrypt/src/chacha.c \
	wolfcrypt/src/chacha20_poly1305.c \
	wolfcrypt/src/coding.c \
	wolfcrypt/src/compress.c \
	wolfcrypt/src/cpuid.c \
	wolfcrypt/src/cryptocb.c \
	wolfcrypt/src/curve25519.c \
	wolfcrypt/src/curve448.c \
	wolfcrypt/src/ecc_fp.c \
	wolfcrypt/src/eccsi.c \
	wolfcrypt/src/ed25519.c \
	wolfcrypt/src/ed448.c \
	wolfcrypt/src/error.c \
	wolfcrypt/src/fe_448.c \
	wolfcrypt/src/fe_low_mem.c \
	wolfcrypt/src/fe_operations.c \
	wolfcrypt/src/ge_448.c \
	wolfcrypt/src/ge_low_mem.c \
	wolfcrypt/src/ge_operations.c \
	wolfcrypt/src/hash.c \
	wolfcrypt/src/kdf.c \
	wolfcrypt/src/integer.c \
	wolfcrypt/src/logging.c \
	wolfcrypt/src/md5.c \
	wolfcrypt/src/memory.c \
	wolfcrypt/src/pkcs12.c \
	wolfcrypt/src/pkcs7.c \
	wolfcrypt/src/poly1305.c \
	wolfcrypt/src/pwdbased.c \
	wolfcrypt/src/rc2.c \
	wolfcrypt/src/sakke.c \
	wolfcrypt/src/signature.c \
	wolfcrypt/src/srp.c \
	wolfcrypt/src/sp_arm32.c \
	wolfcrypt/src/sp_arm64.c \
	wolfcrypt/src/sp_armthumb.c \
	wolfcrypt/src/sp_c32.c \
	wolfcrypt/src/sp_c64.c \
	wolfcrypt/src/sp_cortexm.c \
	wolfcrypt/src/sp_dsp32.c \
	wolfcrypt/src/sp_int.c \
	wolfcrypt/src/sp_x86_64.c \
	wolfcrypt/src/tfm.c \
	wolfcrypt/src/wc_dsp.c \
	wolfcrypt/src/wc_encrypt.c \
	wolfcrypt/src/wc_pkcs11.c \
	wolfcrypt/src/wc_port.c \
	wolfcrypt/src/wolfevent.c \
	wolfcrypt/src/wolfmath.c \
	)

