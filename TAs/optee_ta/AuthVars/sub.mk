WARNS ?= 1
NOWERROR ?= 1
CFG_TA_DEBUG ?= n
CFG_TEE_TA_LOG_LEVEL ?= 1
CFG_AUTHVARS_USE_WOLF ?= y

# Flags
AUTHVAR_FLAGS = -DGCC
CPPFLAGS += -DTHIRTY_TWO_BIT -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -D_ARM_ -w -Wno-strict-prototypes -mcpu=$(TA_CPU) -fstack-protector -Wstack-protector

# Wolf/OpenSSL config
ifeq ($(CFG_AUTHVARS_USE_WOLF),y)
CPPFLAGS += -DUSE_WOLFCRYPT
SSL_FLAGS = -DSINGLE_THREADED -DNO_FILESYSTEM -DNO_WOLFSSL_CLIENT -DNO_WOLFSSL_SERVER -DOPENSSL_EXTRA -DWOLFSSL_USER_SETTINGS -DTIME_OVERRIDES -DSTRING_USER -DCTYPE_USER -DHAVE_PKCS7 -DHAVE_AES_KEYWRAP -DHAVE_X963_KDF -DNO_WRITEV -DNO_ASN_TIME -DHAVE_TIME_T_TYPE -DWOLFCRYPT_ONLY
SSL_WARNING_SUPPRESS = -Wno-unused-function -Wno-switch-default
SSL_INCLUDES = -include ./src/wolf/user_settings.h
INCLUDE_OVERWRITES = $(SSL_INCLUDES)
else
# Nothing for OpenSSL?
endif

# ARM64
ifeq ($(CFG_ARM64_ta_arm64),y)
CPPFLAGS += -mstrict-align
else
CPPFLAGS += -mno-unaligned-access
endif

# Memory upgrade/recovery options
ifeq ($(CFG_TA_WIPE_ON_ERROR),y)
CPPFLAGS += -DAUTHVARS_RESET_ON_ERROR
endif
ifeq ($(CFG_TA_ENABLE_UPGRADE),y)
CPPFLAGS += -DAUTHVAR_ALLOW_UPGRADE
endif

# Debug options
ifeq ($(CFG_TA_DEBUG),y)
CPPFLAGS += -DDBG=1
CPPFLAGS += -O0
CPPFLAGS += -DDEBUG
CPPFLAGS += -DAUTHVAR_DEBUG=1
else
CPPFLAGS += -Os
CPPFLAGS += -DNDEBUG
endif

# Link the required external code into the libraries folder. OP-TEE build
# does not work well when accessing anything below the root directory. Use
# symlinks to trick it.
all: create_lib_symlinks
clean: clean_lib_symlinks

cflags-y += $(AUTHVAR_FLAGS) $(SSL_FLAGS) $(INCLUDE_OVERWRITES)

subdirs-y += lib

global-incdirs-y += src/include

srcs-y += src/varops.c
srcs-y += src/varauth.c
srcs-y += src/varmgmt.c
srcs-y += src/nvmem.c

ifeq ($(CFG_AUTHVARS_USE_WOLF),y)
# Using WolfSSL
global-incdirs-y += src/wolf
srcs-y += src/wolf/RuntimeSupport.c
srcs-y += src/wolf/VarAuthWolf.c
else
# Using OpenSSL
global-incdirs-y += src/ossl
srcs-y += src/ossl/RuntimeSupport.c
srcs-y += src/ossl/VarAuthOSSL.c
endif

srcs-y += AuthVars.c
